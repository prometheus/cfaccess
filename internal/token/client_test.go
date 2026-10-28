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

package token

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/nacl/box"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := f(req)
	if resp != nil {
		resp.Request = req
	}
	return resp, err
}

func testClient(t *testing.T) *Client {
	t.Helper()
	dir := t.TempDir()
	c := NewClient()
	c.cacheDir = func() (string, error) { return dir, nil }
	c.output = io.Discard
	c.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	c.openBrowser = func(string) error { return errors.New("no browser") }
	return c
}

func response(code int, headers http.Header, body string) *http.Response {
	return &http.Response{StatusCode: code, Header: headers, Body: io.NopCloser(strings.NewReader(body))}
}

func cachedToken(t *testing.T, exp time.Time) string {
	t.Helper()
	// Cache reads check syntax and expiry, not the server's signature.
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
		Audience:  jwt.ClaimStrings{"aud"},
		ExpiresAt: jwt.NewNumericDate(exp),
	})
	raw, err := tok.SigningString()
	require.NoError(t, err)
	return raw + ".c2lnbmF0dXJl"
}

func TestGetAppInfo(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		redirect  bool
		missing   bool
		downgrade bool
		wantErr   bool
	}{
		{name: "redirect to login", redirect: true},
		{name: "forbidden application with headers"},
		{name: "missing audience", missing: true, wantErr: true},
		{name: "HTTPS downgrade", redirect: true, downgrade: true, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := testClient(t)
			c.transport = transportFunc(func(req *http.Request) (*http.Response, error) {
				require.Equal(t, http.MethodHead, req.Method)
				require.Equal(t, userAgent, req.UserAgent())
				if tc.redirect && req.URL.Host == "app.example" {
					scheme := "https"
					if tc.downgrade {
						scheme = "http"
					}
					return response(http.StatusFound, http.Header{"Location": {scheme + "://auth.example" + loginPath + "?kid=aud"}}, ""), nil
				}
				h := http.Header{"Cf-Access-Domain": {"app.example"}}
				if !tc.missing {
					h.Set("CF-Access-Aud", "aud")
				}
				if tc.redirect {
					h.Set("Location", "https://identity.example/login")
				}
				status := http.StatusForbidden
				if tc.redirect {
					status = http.StatusFound
				}
				return response(status, h, ""), nil
			})
			u, err := url.Parse("https://app.example/query")
			require.NoError(t, err)
			info, err := c.GetAppInfo(t.Context(), u)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, "aud", info.AppAUD)
			require.Equal(t, "app.example", info.AppDomain)
			if tc.redirect {
				require.Equal(t, "auth.example", info.AuthDomain)
			}
			require.Equal(t, "/query", u.Path)
		})
	}
}

func TestFetchTokenBrowserFlowAndCache(t *testing.T) {
	t.Parallel()
	c := testClient(t)
	app := cachedToken(t, time.Now().Add(time.Hour))
	org := cachedToken(t, time.Now().Add(2*time.Hour))
	var launches atomic.Int32
	var polls atomic.Int32
	c.openBrowser = func(address string) error {
		launches.Add(1)
		u, err := url.Parse(address)
		require.NoError(t, err)
		require.Equal(t, "/cdn-cgi/access/cli", u.Path)
		require.Equal(t, "aud", u.Query().Get("aud"))
		require.Equal(t, "true", u.Query().Get("send_org_token"))
		require.Equal(t, "true", u.Query().Get("edge_token_transfer"))
		redirect, err := url.Parse(u.Query().Get("redirect_url"))
		require.NoError(t, err)
		require.Empty(t, redirect.Path)
		require.Equal(t, u.Query().Get("token"), redirect.Query().Get("token"))
		return errors.New("headless browser")
	}
	c.transport = transportFunc(func(req *http.Request) (*http.Response, error) {
		require.Equal(t, "login.cloudflareaccess.org", req.URL.Host)
		if polls.Add(1) == 1 {
			return response(http.StatusAccepted, nil, ""), nil
		}
		clientKey, err := base64.URLEncoding.DecodeString(strings.TrimPrefix(req.URL.Path, "/transfer/"))
		require.NoError(t, err)
		require.Len(t, clientKey, 32)
		public, private, err := box.GenerateKey(rand.Reader)
		require.NoError(t, err)
		plaintext, err := json.Marshal(transferResponse{AppToken: app, OrgToken: org})
		require.NoError(t, err)
		var nonce [24]byte
		_, err = rand.Read(nonce[:])
		require.NoError(t, err)
		peer := [32]byte(clientKey)
		ciphertext := box.Seal(nonce[:], plaintext, &nonce, &peer, private)
		return response(http.StatusOK, http.Header{"Service-Public-Key": {base64.URLEncoding.EncodeToString(public[:])}}, base64.StdEncoding.EncodeToString(ciphertext)), nil
	})
	u, err := url.Parse("https://app.example/query?keep=value")
	require.NoError(t, err)
	info := &AppInfo{AppDomain: "app.example", AppAUD: "aud", AuthDomain: "auth.example"}
	// Independent callers coordinate through the shared on-disk cache.
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			tok, err := c.FetchToken(t.Context(), u, info)
			if err == nil && tok != app {
				err = fmt.Errorf("unexpected application token")
			}
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.EqualValues(t, 1, launches.Load())
	require.EqualValues(t, 2, polls.Load())
	require.Equal(t, "https://app.example/query?keep=value", u.String())
	dir, err := c.cacheDir()
	require.NoError(t, err)
	appPath, orgPath := cachePaths(dir, info)
	for path, want := range map[string]string{appPath: app, orgPath: org} {
		got, err := readToken(path)
		require.NoError(t, err)
		require.Equal(t, want, got)
		stat, err := os.Stat(path)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), stat.Mode().Perm())
		_, err = os.Stat(path + ".lock")
		require.ErrorIs(t, err, os.ErrNotExist)
	}
}

func TestFetchTokenOrganizationExchange(t *testing.T) {
	t.Parallel()
	c := testClient(t)
	u, err := url.Parse("https://app.example/query")
	require.NoError(t, err)
	info := &AppInfo{AppDomain: "app.example", AppAUD: "aud", AuthDomain: "auth.example"}
	dir, err := c.cacheDir()
	require.NoError(t, err)
	appPath, orgPath := cachePaths(dir, info)
	org := cachedToken(t, time.Now().Add(2*time.Hour))
	app := cachedToken(t, time.Now().Add(time.Hour))
	require.NoError(t, writeToken(orgPath, org))
	c.openBrowser = func(string) error { t.Error("cached organization token should avoid browser login"); return nil }
	var calls int
	c.transport = transportFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		switch req.URL.Path {
		case "/query":
			require.Empty(t, req.Header.Get("Cookie"))
			return response(http.StatusFound, http.Header{"Location": {"https://auth.example" + loginPath}}, ""), nil
		case loginPath:
			cookie, err := req.Cookie(tokenCookie)
			require.NoError(t, err)
			require.Equal(t, org, cookie.Value)
			return response(http.StatusFound, http.Header{"Location": {"https://app.example/callback"}}, ""), nil
		case "/callback":
			require.Empty(t, req.Header.Get("Cookie"))
			return response(http.StatusFound, http.Header{
				"Location":   {"https://app.example" + authorizedPath},
				"Set-Cookie": {sessionCookie + "=session; Secure"},
			}, ""), nil
		case authorizedPath:
			cookie, err := req.Cookie(sessionCookie)
			require.NoError(t, err)
			require.Equal(t, "session", cookie.Value)
			_, err = req.Cookie(tokenCookie)
			require.ErrorIs(t, err, http.ErrNoCookie)
			return response(http.StatusFound, http.Header{
				"Location":   {"https://app.example/query"},
				"Set-Cookie": {(&http.Cookie{Name: tokenCookie, Value: app, Expires: time.Now().Add(time.Hour), Secure: true}).String()},
			}, ""), nil
		default:
			return nil, fmt.Errorf("unexpected request %s", req.URL)
		}
	})
	got, err := c.FetchToken(t.Context(), u, info)
	require.NoError(t, err)
	require.Equal(t, app, got)
	require.Equal(t, 4, calls)
	cached, err := readToken(appPath)
	require.NoError(t, err)
	require.Equal(t, app, cached)
}

func TestFetchTokenCancellation(t *testing.T) {
	t.Parallel()
	for _, stage := range []string{"cache lock", "transfer"} {
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			c := testClient(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			info := &AppInfo{AppDomain: "app.example", AppAUD: "aud", AuthDomain: "auth.example"}
			dir, err := c.cacheDir()
			require.NoError(t, err)
			appPath, orgPath := cachePaths(dir, info)
			if stage == "cache lock" {
				release, err := acquireLock(t.Context(), appPath)
				require.NoError(t, err)
				defer release()
				// The same helper is used by FetchToken; cancel while it is waiting.
				time.AfterFunc(20*time.Millisecond, cancel)
			} else {
				c.transport = transportFunc(func(req *http.Request) (*http.Response, error) {
					cancel()
					return nil, req.Context().Err()
				})
			}
			u, err := url.Parse("https://app.example/")
			require.NoError(t, err)
			_, err = c.FetchToken(ctx, u, info)
			require.ErrorIs(t, err, context.Canceled)
			if stage == "transfer" {
				for _, path := range []string{appPath, orgPath, appPath + ".lock", orgPath + ".lock"} {
					_, err := os.Stat(path)
					require.ErrorIs(t, err, os.ErrNotExist)
				}
			}
		})
	}
}

func TestTokenCache(t *testing.T) {
	t.Parallel()
	valid := cachedToken(t, time.Now().Add(time.Hour))
	for _, tc := range []struct {
		name, raw string
		valid     bool
	}{
		{"valid", valid, true},
		{"expired", cachedToken(t, time.Now().Add(-time.Hour)), false},
		{"malformed", "not-a-token", false},
		{"wrong algorithm", base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`)) + "." + strings.Split(valid, ".")[1] + ".c2ln", false},
		{"missing expiry", "eyJhbGciOiJSUzI1NiJ9.e30.c2ln", false},
		{"invalid signature encoding", strings.TrimSuffix(valid, ".c2lnbmF0dXJl") + ".!", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "app-aud-token")
			require.NoError(t, writeToken(path, tc.raw))
			got, err := readToken(path)
			if tc.valid {
				require.NoError(t, err)
				require.Equal(t, tc.raw, got)
			} else {
				require.Error(t, err)
			}
		})
	}
	info := &AppInfo{AppDomain: "*.example/path", AppAUD: "aud", AuthDomain: "auth.example"}
	a, o := cachePaths(t.TempDir(), info)
	require.Equal(t, "-.example-path-aud-token", filepath.Base(a))
	require.Equal(t, "auth.example-org-token", filepath.Base(o))
}

func TestDecrypt(t *testing.T) {
	t.Parallel()
	public, private, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sender, senderPrivate, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)
	var nonce [24]byte
	_, err = rand.Read(nonce[:])
	require.NoError(t, err)
	encrypted := box.Seal(nonce[:], []byte("secret"), &nonce, public, senderPrivate)
	senderKey := base64.URLEncoding.EncodeToString(sender[:])
	damaged := append([]byte(nil), encrypted...)
	damaged[len(damaged)-1] ^= 1
	for _, tc := range []struct {
		name       string
		ciphertext []byte
		key        string
		valid      bool
	}{
		{"valid", encrypted, senderKey, true},
		{"empty", nil, senderKey, false},
		{"short nonce", encrypted[:23], senderKey, false},
		{"short ciphertext", encrypted[:24], senderKey, false},
		{"invalid key encoding", encrypted, "!", false},
		{"short key", encrypted, base64.URLEncoding.EncodeToString([]byte{1}), false},
		{"tampered ciphertext", damaged, senderKey, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := decrypt(tc.ciphertext, tc.key, private)
			if tc.valid {
				require.NoError(t, err)
				require.Equal(t, []byte("secret"), got)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestTransferFailures(t *testing.T) {
	t.Parallel()
	public, private, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)
	for _, tc := range []struct {
		name    string
		status  int
		body    string
		wantErr string
	}{
		{"server error", http.StatusServiceUnavailable, "unavailable", "HTTP 503"},
		{"invalid base64", http.StatusOK, "!", "decode Access transfer"},
		{"short ciphertext", http.StatusOK, base64.StdEncoding.EncodeToString([]byte("short")), "too short"},
		{"oversized response", http.StatusOK, strings.Repeat("A", (1<<20)+1), "too large"},
		{"waiting", http.StatusAccepted, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resp := response(tc.status, http.Header{"Service-Public-Key": {base64.URLEncoding.EncodeToString(public[:])}}, tc.body)
			got, err := decodeTransfer(resp, private)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
			} else {
				require.NoError(t, err)
				require.Nil(t, got)
			}
		})
	}
	t.Run("poll limit", func(t *testing.T) {
		t.Parallel()
		c := testClient(t)
		var calls int
		c.transport = transportFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return response(http.StatusAccepted, nil, ""), nil
		})
		u, err := url.Parse("https://app.example/query")
		require.NoError(t, err)
		_, err = c.transfer(t.Context(), u, "aud")
		require.ErrorContains(t, err, "timed out")
		require.Equal(t, 10, calls)
	})
}

func TestOrganizationTokenRedirectScope(t *testing.T) {
	t.Parallel()
	for _, destination := range []string{"https://unrelated.example" + loginPath, "http://auth.example" + loginPath} {
		t.Run(destination, func(t *testing.T) {
			t.Parallel()
			c := testClient(t)
			c.transport = transportFunc(func(req *http.Request) (*http.Response, error) {
				require.Empty(t, req.Header.Get("Cookie"))
				if req.URL.Host == "app.example" {
					return response(http.StatusFound, http.Header{"Location": {destination}}, ""), nil
				}
				require.Equal(t, "https", req.URL.Scheme)
				return response(http.StatusForbidden, nil, ""), nil
			})
			u, err := url.Parse("https://app.example/query")
			require.NoError(t, err)
			_, err = c.exchangeOrgToken(t.Context(), u, &AppInfo{AuthDomain: "auth.example"}, "organization-secret")
			require.Error(t, err)
		})
	}
}

func TestCacheLockOwnership(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "app-aud-token")
	release, err := acquireLock(t.Context(), path)
	require.NoError(t, err)
	// Another process can remove and replace the lock. Never unlink its lock.
	require.NoError(t, os.Rename(path+".lock", path+".old-lock"))
	require.NoError(t, os.WriteFile(path+".lock", []byte("other owner"), 0o600))
	release()
	got, err := os.ReadFile(path + ".lock")
	require.NoError(t, err)
	require.Equal(t, "other owner", string(got))
}
