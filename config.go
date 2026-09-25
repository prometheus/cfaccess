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
	"fmt"
	"strings"

	commonconfig "github.com/prometheus/common/config"
)

// AuthorizationType is the value of commonconfig.Authorization.Type that
// selects Cloudflare Access authentication.
const AuthorizationType = "cf-access"

// PrepareHTTPClientConfig detects Cloudflare Access authentication in cfg and
// returns a copy suitable for commonconfig.NewClientFromConfig or
// commonconfig.NewRoundTripperFromConfig. When enabled is true, callers must
// wrap the resulting transport with NewRoundTripper.
//
// The returned configuration has Authorization removed so prometheus/common
// does not interpret cf-access as a literal HTTP Authorization scheme. cfg is
// never modified.
//
//nolint:gocritic // Passing by value is intentional: the returned copy can be sanitized without mutating cfg.
func PrepareHTTPClientConfig(cfg commonconfig.HTTPClientConfig) (clean commonconfig.HTTPClientConfig, enabled bool, err error) {
	if cfg.Authorization == nil || !strings.EqualFold(strings.TrimSpace(cfg.Authorization.Type), AuthorizationType) {
		return cfg, false, nil
	}

	auth := cfg.Authorization
	if string(auth.Credentials) != "" || auth.CredentialsFile != "" || auth.CredentialsRef != "" {
		return cfg, false, fmt.Errorf("authorization credentials, credentials_file & credentials_ref must not be configured when authorization type is %q", AuthorizationType)
	}
	if cfg.BasicAuth != nil || cfg.OAuth2 != nil || string(cfg.BearerToken) != "" || cfg.BearerTokenFile != "" {
		return cfg, false, fmt.Errorf("basic_auth, oauth2, bearer_token & bearer_token_file must not be configured when authorization type is %q", AuthorizationType)
	}

	clean = cfg
	clean.Authorization = nil
	return clean, true, nil
}
