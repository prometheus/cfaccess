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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func defaultCacheDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".cloudflared")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

func cachePaths(dir string, info *AppInfo) (appPath, orgPath string) {
	// Keep cloudflared's cache names while also rejecting Windows separators.
	sanitize := strings.NewReplacer("/", "-", "\\", "-", "*", "-")
	return filepath.Join(dir, sanitize.Replace(info.AppDomain+"-"+info.AppAUD+"-token")),
		filepath.Join(dir, sanitize.Replace(info.AuthDomain+"-org-token"))
}

func checkToken(raw string) error {
	claims := jwt.RegisteredClaims{}
	parser := jwt.NewParser()
	tok, parts, err := parser.ParseUnverified(raw, &claims)
	if err != nil {
		return err
	}
	if tok.Method.Alg() != "RS256" {
		return fmt.Errorf("unsupported Access token algorithm")
	}
	// ParseUnverified intentionally skips signature decoding.
	signature, err := parser.DecodeSegment(parts[2])
	if err != nil || len(signature) == 0 {
		return fmt.Errorf("invalid Access token signature encoding")
	}
	if claims.ExpiresAt == nil || !time.Now().Before(claims.ExpiresAt.Time) {
		return fmt.Errorf("access token is expired or has no expiry")
	}
	return nil
}

func readToken(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	raw := string(data)
	if err := checkToken(raw); err != nil {
		return "", err
	}
	return raw, nil
}

func writeToken(path, raw string) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".access-token-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(raw); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func acquireLock(ctx context.Context, tokenPath string) (func(), error) {
	path := tokenPath + ".lock"
	// Do not steal locks from a slow browser login. Abandoned lock files require
	// explicit removal; no signal handlers or process exits belong in a library.
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	for {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("waiting for Access cache lock %s (remove it if abandoned): %w", path, err)
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			info, statErr := f.Stat()
			closeErr := f.Close()
			if err := errors.Join(statErr, closeErr); err != nil {
				_ = os.Remove(path)
				return nil, err
			}
			return func() {
				// An external cloudflared process may have replaced a stale lock.
				current, err := os.Stat(path)
				if err == nil && os.SameFile(info, current) {
					_ = os.Remove(path)
				}
			}, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
}
