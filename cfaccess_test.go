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

package cfaccess

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudflare/cloudflared/token"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func signedTestToken(t *testing.T, expiry time.Time) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"exp": jwt.NewNumericDate(expiry),
	})
	signed, err := tok.SignedString([]byte("test-signing-key"))
	require.NoError(t, err)
	return signed
}

func testDependencies(
	t *testing.T,
	now func() time.Time,
	getAppInfo func(*url.URL) (*token.AppInfo, error),
	fetchToken func(*url.URL, *token.AppInfo) (string, error),
) dependencies {
	t.Helper()
	logger := zerolog.Nop()
	return dependencies{
		now:        now,
		getAppInfo: getAppInfo,
		fetchToken: func(appURL *url.URL, info *token.AppInfo, _ *zerolog.Logger) (string, error) {
			return fetchToken(appURL, info)
		},
		logger: &logger,
	}
}

func TestTokenExpiry(t *testing.T) {
	t.Parallel()

	t.Run("valid token", func(t *testing.T) {
		t.Parallel()
		expiry := time.Now().Add(time.Hour).Truncate(time.Second)
		require.WithinDuration(t, expiry, tokenExpiry(signedTestToken(t, expiry)), time.Second)
	})

	t.Run("malformed token", func(t *testing.T) {
		t.Parallel()
		require.True(t, tokenExpiry("not-a-jwt").IsZero())
	})

	t.Run("token without exp claim", func(t *testing.T) {
		t.Parallel()
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{})
		signed, err := tok.SignedString([]byte("test-signing-key"))
		require.NoError(t, err)
		require.True(t, tokenExpiry(signed).IsZero())
	})
}

func TestRoundTripper(t *testing.T) {
	t.Parallel()

	fakeNow := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var getAppInfoCalls atomic.Int32
	var fetchTokenCalls atomic.Int32
	shortLivedToken := signedTestToken(t, fakeNow.Add(time.Minute))
	longLivedToken := signedTestToken(t, fakeNow.Add(time.Hour))

	deps := testDependencies(t,
		func() time.Time { return fakeNow },
		func(requestURL *url.URL) (*token.AppInfo, error) {
			getAppInfoCalls.Add(1)
			info := &token.AppInfo{AuthDomain: "auth." + requestURL.Host, AppAUD: "aud", AppDomain: requestURL.Host}
			requestURL.Path = "/mutated-by-discovery"
			return info, nil
		},
		func(appURL *url.URL, _ *token.AppInfo) (string, error) {
			require.Equal(t, "/query", appURL.Path)
			// cloudflared constructs the login endpoint by mutating this URL.
			appURL.Path = "/cdn-cgi/access/cli"
			appURL.RawQuery = "token=secret"
			if fetchTokenCalls.Add(1) == 1 {
				return shortLivedToken, nil
			}
			return longLivedToken, nil
		},
	)

	var gotRequest *http.Request
	next := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		gotRequest = req
		return &http.Response{StatusCode: http.StatusOK}, nil
	})
	rt := newRoundTripper(next, deps)

	req1, err := http.NewRequest(http.MethodGet, "https://app.example.com/query", http.NoBody)
	require.NoError(t, err)
	req1.Header.Set("X-Test", "preserved")
	_, err = rt.RoundTrip(req1)
	require.NoError(t, err)
	require.Equal(t, "https://app.example.com/query", gotRequest.URL.String())
	require.Equal(t, shortLivedToken, gotRequest.Header.Get(TokenHeader))
	require.Equal(t, "preserved", gotRequest.Header.Get("X-Test"))
	require.Empty(t, req1.Header.Get(TokenHeader))
	require.Equal(t, "https://app.example.com/query", req1.URL.String())
	require.EqualValues(t, 1, getAppInfoCalls.Load())
	require.EqualValues(t, 1, fetchTokenCalls.Load())

	req2, err := http.NewRequest(http.MethodGet, "https://app.example.com/query", http.NoBody)
	require.NoError(t, err)
	_, err = rt.RoundTrip(req2)
	require.NoError(t, err)
	require.EqualValues(t, 1, getAppInfoCalls.Load())
	require.EqualValues(t, 1, fetchTokenCalls.Load())

	req3, err := http.NewRequest(http.MethodGet, "https://other.example.com/query", http.NoBody)
	require.NoError(t, err)
	_, err = rt.RoundTrip(req3)
	require.NoError(t, err)
	require.Equal(t, longLivedToken, gotRequest.Header.Get(TokenHeader))
	require.EqualValues(t, 2, getAppInfoCalls.Load())
	require.EqualValues(t, 2, fetchTokenCalls.Load())

	fakeNow = fakeNow.Add(time.Minute)
	req4, err := http.NewRequest(http.MethodGet, "https://app.example.com/query", http.NoBody)
	require.NoError(t, err)
	_, err = rt.RoundTrip(req4)
	require.NoError(t, err)
	require.Equal(t, longLivedToken, gotRequest.Header.Get(TokenHeader))
	require.EqualValues(t, 2, getAppInfoCalls.Load())
	require.EqualValues(t, 3, fetchTokenCalls.Load())
}

func TestRoundTripperConcurrentRequestsShareToken(t *testing.T) {
	t.Parallel()

	now := time.Now()
	tok := signedTestToken(t, now.Add(time.Hour))
	var fetchTokenCalls atomic.Int32
	deps := testDependencies(t,
		func() time.Time { return now },
		func(requestURL *url.URL) (*token.AppInfo, error) {
			return &token.AppInfo{AuthDomain: "auth.example.com", AppAUD: "aud", AppDomain: requestURL.Host}, nil
		},
		func(*url.URL, *token.AppInfo) (string, error) {
			fetchTokenCalls.Add(1)
			return tok, nil
		},
	)

	next := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if got := req.Header.Get(TokenHeader); got != tok {
			return nil, fmt.Errorf("unexpected access token %q", got)
		}
		return &http.Response{StatusCode: http.StatusOK}, nil
	})
	rt := newRoundTripper(next, deps)

	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for range 20 {
		wg.Go(func() {
			req, err := http.NewRequest(http.MethodGet, "https://app.example.com/query", http.NoBody)
			if err != nil {
				errs <- err
				return
			}
			_, err = rt.RoundTrip(req)
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.EqualValues(t, 1, fetchTokenCalls.Load())
}

var errGetAppInfo = errors.New("get app info failed")

func TestRoundTripperGetAppInfoError(t *testing.T) {
	t.Parallel()

	deps := testDependencies(t,
		time.Now,
		func(*url.URL) (*token.AppInfo, error) { return nil, errGetAppInfo },
		func(*url.URL, *token.AppInfo) (string, error) {
			t.Fatal("FetchToken must not be called when GetAppInfo fails")
			return "", nil
		},
	)
	next := roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("next RoundTripper must not be called when authentication fails")
		return nil, nil
	})
	rt := newRoundTripper(next, deps)
	req, err := http.NewRequest(http.MethodGet, "https://app.example.com/query", http.NoBody)
	require.NoError(t, err)

	_, err = rt.RoundTrip(req)
	require.ErrorIs(t, err, errGetAppInfo)
}

func TestRoundTripperDoesNotSendCancelledRequest(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	deps := testDependencies(t,
		time.Now,
		func(requestURL *url.URL) (*token.AppInfo, error) {
			return &token.AppInfo{AuthDomain: "auth.example.com", AppAUD: "aud", AppDomain: requestURL.Host}, nil
		},
		func(*url.URL, *token.AppInfo) (string, error) {
			cancel()
			return signedTestToken(t, time.Now().Add(time.Hour)), nil
		},
	)
	next := roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("next RoundTripper must not receive a cancelled request")
		return nil, nil
	})
	rt := newRoundTripper(next, deps)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.example.com/query", http.NoBody)
	require.NoError(t, err)

	_, err = rt.RoundTrip(req)
	require.ErrorIs(t, err, context.Canceled)
}

func TestRoundTripperDoesNotAuthenticateCancelledRequest(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	deps := testDependencies(t,
		time.Now,
		func(*url.URL) (*token.AppInfo, error) {
			t.Fatal("GetAppInfo must not receive a cancelled request")
			return nil, nil
		},
		func(*url.URL, *token.AppInfo) (string, error) {
			t.Fatal("FetchToken must not receive a cancelled request")
			return "", nil
		},
	)
	rt := newRoundTripper(roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("next RoundTripper must not receive a cancelled request")
		return nil, nil
	}), deps)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.example.com/query", http.NoBody)
	require.NoError(t, err)

	_, err = rt.RoundTrip(req)
	require.ErrorIs(t, err, context.Canceled)
}

type closeIdleRoundTripper struct {
	closed atomic.Bool
}

func (*closeIdleRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK}, nil
}

func (rt *closeIdleRoundTripper) CloseIdleConnections() {
	rt.closed.Store(true)
}

func TestRoundTripperClosesIdleConnections(t *testing.T) {
	t.Parallel()

	next := &closeIdleRoundTripper{}
	rt := newRoundTripper(next, dependencies{}).(*roundTripper)
	rt.CloseIdleConnections()
	require.True(t, next.closed.Load())
}

func TestNewRoundTripperDefaultsTransport(t *testing.T) {
	t.Parallel()

	rt := NewRoundTripper(nil).(*roundTripper)
	require.Same(t, http.DefaultTransport, rt.next)
}
