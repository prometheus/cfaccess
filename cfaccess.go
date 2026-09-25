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

// Package cfaccess provides HTTP authentication for applications protected by
// Cloudflare Access.
package cfaccess

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/cloudflare/cloudflared/token"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
)

const (
	// TokenHeader is the header Cloudflare Access checks for a JWT obtained
	// through its browser-based login flow.
	TokenHeader = "Cf-Access-Token"

	tokenExpiryMargin = 30 * time.Second
)

var initializeCloudflared sync.Once

type dependencies struct {
	getAppInfo func(*url.URL) (*token.AppInfo, error)
	fetchToken func(*url.URL, *token.AppInfo, *zerolog.Logger) (string, error)
	now        func() time.Time
	logger     *zerolog.Logger
}

type app struct {
	mtx     sync.Mutex
	info    *token.AppInfo
	token   string
	expires time.Time
}

type roundTripper struct {
	next http.RoundTripper
	deps dependencies

	mtx  sync.Mutex
	apps map[string]*app
}

// NewRoundTripper returns a RoundTripper that obtains a Cloudflare Access
// token for each target application and adds it to requests before passing
// them to next. If next is nil, http.DefaultTransport is used.
func NewRoundTripper(next http.RoundTripper) http.RoundTripper {
	initializeCloudflared.Do(func() {
		// cloudflared stores its User-Agent globally, so use one stable identity
		// rather than allowing constructors to race with per-consumer values.
		token.Init("prometheus-cfaccess")
	})
	if next == nil {
		next = http.DefaultTransport
	}

	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "15:04:05"}).With().Timestamp().Logger()
	return newRoundTripper(next, dependencies{
		getAppInfo: token.GetAppInfo,
		fetchToken: func(appURL *url.URL, info *token.AppInfo, logger *zerolog.Logger) (string, error) {
			return token.FetchToken(appURL, info, false, false, logger)
		},
		now:    time.Now,
		logger: &logger,
	})
}

func newRoundTripper(next http.RoundTripper, deps dependencies) http.RoundTripper {
	return &roundTripper{
		next: next,
		deps: deps,
		apps: make(map[string]*app),
	}
}

func (rt *roundTripper) appFor(key string) *app {
	rt.mtx.Lock()
	defer rt.mtx.Unlock()

	a, ok := rt.apps[key]
	if !ok {
		a = &app{}
		rt.apps[key] = a
	}
	return a
}

// RoundTrip implements http.RoundTripper.
func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := req.Context().Err(); err != nil {
		return nil, err
	}

	key := req.URL.Scheme + "://" + req.URL.Host
	tok, err := rt.appFor(key).fetch(req.URL, rt.deps)
	if err != nil {
		return nil, fmt.Errorf("cloudflare access: %w", err)
	}
	if err := req.Context().Err(); err != nil {
		return nil, err
	}

	outgoing := req.Clone(req.Context())
	if outgoing.Header == nil {
		outgoing.Header = make(http.Header)
	}
	outgoing.Header.Set(TokenHeader, tok)
	return rt.next.RoundTrip(outgoing)
}

func (rt *roundTripper) CloseIdleConnections() {
	if ci, ok := rt.next.(interface{ CloseIdleConnections() }); ok {
		ci.CloseIdleConnections()
	}
}

func (a *app) fetch(requestURL *url.URL, deps dependencies) (string, error) {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	if a.token != "" && deps.now().Add(tokenExpiryMargin).Before(a.expires) {
		return a.token, nil
	}

	if a.info == nil {
		// Cloudflared may retain or modify URLs passed to its APIs. Give each
		// operation its own copy so neither it nor the request can affect the
		// other.
		discoveryURL := *requestURL
		info, err := deps.getAppInfo(&discoveryURL)
		if err != nil {
			return "", fmt.Errorf("failed to detect Cloudflare Access application for %s://%s: %w", requestURL.Scheme, requestURL.Host, err)
		}
		a.info = info
	}

	loginURL := *requestURL
	tok, err := deps.fetchToken(&loginURL, a.info, deps.logger)
	if err != nil {
		return "", fmt.Errorf("failed to fetch Cloudflare Access token: %w", err)
	}

	a.token = tok
	a.expires = tokenExpiry(tok)
	return tok, nil
}

// tokenExpiry returns the expiry time encoded in the token's exp claim. The
// token was obtained directly from cloudflared, so its signature is not
// verified here. A token whose expiry cannot be read is refreshed on the next
// request.
func tokenExpiry(tok string) time.Time {
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(tok, claims); err != nil {
		return time.Time{}
	}
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return time.Time{}
	}
	return exp.Time
}
