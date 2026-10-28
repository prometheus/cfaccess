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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/crypto/nacl/box"
)

type transferResponse struct {
	AppToken string `json:"app_token"`
	OrgToken string `json:"org_token"`
}

func loginURL(appURL *url.URL, aud, publicKey string) string {
	u := *appURL
	q := u.Query()
	q.Set("token", publicKey)
	q.Set("aud", aud)
	u.RawQuery = q.Encode()
	u.Path = ""
	u.RawPath = ""
	u.Fragment = ""
	q.Set("redirect_url", u.String())
	q.Set("send_org_token", "true")
	q.Set("edge_token_transfer", "true")
	u.RawQuery = q.Encode()
	u.Path = "/cdn-cgi/access/cli"
	return u.String()
}

func (c *Client) transfer(ctx context.Context, appURL *url.URL, aud string) (*transferResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	public, private, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	key := base64.URLEncoding.EncodeToString(public[:])
	address := loginURL(appURL, aud, key)
	// A failed browser launch is recoverable: users can open the printed URL.
	if err := c.openBrowser(address); err != nil {
		c.logger.Debug("Could not open browser", "err", err)
	}
	fmt.Fprintf(c.output, "Open the following URL to log in with Cloudflare Access:\n\n%s\n\nLeave this command running to receive the token.\n", address)
	client := c.httpClient(time.Minute, func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	})
	for range 10 {
		req, err := newRequest(ctx, http.MethodGet, c.transferURL+key)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		result, err := decodeTransfer(resp, private)
		if err != nil {
			return nil, err
		}
		if result != nil {
			return result, nil
		}
		c.logger.Info("Waiting for Cloudflare Access login")
	}
	return nil, fmt.Errorf("timed out waiting for Cloudflare Access login")
}

func decodeTransfer(resp *http.Response, private *[32]byte) (*transferResponse, error) {
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("access transfer service returned HTTP %d", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}
	// Token responses are small. Bound memory even if an endpoint misbehaves.
	const limit = 1 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if len(body) > limit {
		return nil, fmt.Errorf("access transfer response too large")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		return nil, fmt.Errorf("decode Access transfer: %w", err)
	}
	plaintext, err := decrypt(ciphertext, resp.Header.Get("service-public-key"), private)
	if err != nil {
		return nil, err
	}
	var result transferResponse
	if err := json.Unmarshal(plaintext, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func decrypt(ciphertext []byte, encodedKey string, private *[32]byte) ([]byte, error) {
	if len(ciphertext) < 24+box.Overhead {
		return nil, fmt.Errorf("access transfer ciphertext is too short")
	}
	key, err := base64.URLEncoding.DecodeString(encodedKey)
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("invalid Access transfer public key")
	}
	var nonce [24]byte
	copy(nonce[:], ciphertext[:24])
	public := [32]byte(key)
	plaintext, ok := box.Open(nil, ciphertext[24:], &nonce, &public, private)
	if !ok {
		return nil, fmt.Errorf("could not decrypt Access transfer")
	}
	return plaintext, nil
}
