// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package token implements the Cloudflare Access browser login protocol.
// The protocol implementation is adapted from cloudflare/cloudflared at
// d2a87e9b9345; see README.md for provenance.
package token

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	loginPath      = "/cdn-cgi/access/login"
	authorizedPath = "/cdn-cgi/access/authorized"
	tokenCookie    = "CF_Authorization"
	sessionCookie  = "CF_AppSession"
	userAgent      = "cloudflared/prometheus-cfaccess"
)

// AppInfo identifies an Access application and its organization.
type AppInfo struct {
	AuthDomain string
	AppAUD     string
	AppDomain  string
}

// Client discovers applications and obtains cached or interactive tokens.
// It is safe to share between goroutines.
type Client struct {
	transport   http.RoundTripper
	cacheDir    func() (string, error)
	openBrowser func(string) error
	output      io.Writer
	logger      *slog.Logger
	transferURL string
}

// NewClient returns a client using the cloudflared token cache.
func NewClient() *Client {
	return &Client{
		transport:   http.DefaultTransport,
		cacheDir:    defaultCacheDir,
		openBrowser: openBrowser,
		output:      os.Stderr,
		logger:      slog.Default(),
		transferURL: "https://login.cloudflareaccess.org/transfer/",
	}
}

func (c *Client) httpClient(timeout time.Duration, redirect func(*http.Request, []*http.Request) error) *http.Client {
	return &http.Client{
		Transport: c.transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many Access redirects")
			}
			if req.URL.Scheme != "https" {
				return fmt.Errorf("access redirects require HTTPS")
			}
			return redirect(req, via)
		},
	}
}

// GetAppInfo discovers the application's audience and authentication domain.
func (c *Client) GetAppInfo(ctx context.Context, appURL *url.URL) (*AppInfo, error) {
	client := c.httpClient(7*time.Second, func(_ *http.Request, via []*http.Request) error {
		if via[len(via)-1].URL.Path == loginPath {
			return http.ErrUseLastResponse
		}
		return nil
	})
	req, err := newRequest(ctx, http.MethodHead, appURL.String())
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discover Access application: %w", err)
	}
	defer resp.Body.Close()
	location := resp.Request.URL
	aud := resp.Header.Get("CF-Access-Aud")
	if location.Path == loginPath {
		aud = location.Query().Get("kid")
	}
	domain := resp.Header.Get("CF-Access-Domain")
	if aud == "" || domain == "" {
		return nil, fmt.Errorf("response does not identify an Access application")
	}
	return &AppInfo{AuthDomain: location.Hostname(), AppAUD: aud, AppDomain: domain}, nil
}

// FetchToken reuses cached credentials or performs an interactive browser login.
func (c *Client) FetchToken(ctx context.Context, appURL *url.URL, info *AppInfo) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	dir, err := c.cacheDir()
	if err != nil {
		return "", err
	}
	appPath, orgPath := cachePaths(dir, info)
	if tok, err := readToken(appPath); err == nil {
		return tok, nil
	}
	release, err := acquireLock(ctx, appPath)
	if err != nil {
		return "", err
	}
	defer release()
	if tok, err := readToken(appPath); err == nil {
		return tok, nil
	}

	// Serialize organization login across applications sharing the same cache.
	releaseOrg, err := acquireLock(ctx, orgPath)
	if err != nil {
		return "", err
	}
	defer releaseOrg()
	if org, err := readToken(orgPath); err == nil {
		tok, err := c.exchangeOrgToken(ctx, appURL, info, org)
		if err == nil {
			if err := writeToken(appPath, tok); err != nil {
				return "", err
			}
			return tok, nil
		}
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		c.logger.Debug("Could not exchange Access organization token", "err", err)
	}
	result, err := c.transfer(ctx, appURL, info.AppAUD)
	if err != nil {
		return "", err
	}
	// Only cache usable tokens; neither cache parsing nor expiry checks verify
	// signatures. Access validates the application token on the actual request.
	if err := checkToken(result.AppToken); err != nil {
		return "", fmt.Errorf("invalid application token: %w", err)
	}
	if result.OrgToken != "" {
		if err := checkToken(result.OrgToken); err != nil {
			return "", fmt.Errorf("invalid organization token: %w", err)
		}
		if err := writeToken(orgPath, result.OrgToken); err != nil {
			return "", err
		}
	}
	if err := writeToken(appPath, result.AppToken); err != nil {
		return "", err
	}
	return result.AppToken, nil
}

func (c *Client) exchangeOrgToken(ctx context.Context, appURL *url.URL, info *AppInfo, org string) (string, error) {
	client := c.httpClient(7*time.Second, func(req *http.Request, via []*http.Request) error {
		if via[len(via)-1].URL.Path == authorizedPath {
			return http.ErrUseLastResponse
		}
		// Restrict credentials to the discovered organization and application.
		req.Header.Del("Cookie")
		if req.URL.Path == loginPath && strings.EqualFold(req.URL.Hostname(), info.AuthDomain) {
			req.AddCookie(&http.Cookie{Name: tokenCookie, Value: org})
		}
		if req.URL.Path == authorizedPath && strings.EqualFold(req.URL.Hostname(), appURL.Hostname()) {
			responses := []*http.Response{req.Response}
			for i := len(via) - 1; i >= 0; i-- {
				responses = append(responses, via[i].Response)
			}
			for _, previous := range responses {
				if previous == nil || previous.Request == nil || !strings.EqualFold(previous.Request.URL.Hostname(), req.URL.Hostname()) {
					continue
				}
				for _, cookie := range previous.Cookies() {
					if cookie.Name == sessionCookie {
						req.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie.Value})
						return nil
					}
				}
			}
		}
		return nil
	})
	req, err := newRequest(ctx, http.MethodHead, appURL.String())
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if !strings.EqualFold(resp.Request.URL.Hostname(), appURL.Hostname()) {
		return "", fmt.Errorf("token exchange ended outside the application")
	}
	for _, cookie := range resp.Cookies() {
		if cookie.Name == tokenCookie && time.Now().Before(cookie.Expires) {
			if err := checkToken(cookie.Value); err != nil {
				return "", err
			}
			return cookie.Value, nil
		}
	}
	return "", fmt.Errorf("token exchange response did not contain an application token")
}

func newRequest(ctx context.Context, method, address string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, address, http.NoBody)
	if err != nil {
		return nil, err
	}
	if req.URL.Scheme != "https" {
		return nil, fmt.Errorf("access authentication requires HTTPS")
	}
	req.Header.Set("User-Agent", userAgent)
	return req, nil
}
