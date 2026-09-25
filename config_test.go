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
	"testing"

	commonconfig "github.com/prometheus/common/config"
	"github.com/stretchr/testify/require"
)

func TestPrepareHTTPClientConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  commonconfig.HTTPClientConfig
		enabled bool
		wantErr string
	}{
		{
			name: "no authorization",
		},
		{
			name: "other authorization",
			config: commonconfig.HTTPClientConfig{
				Authorization: &commonconfig.Authorization{Type: "Bearer", Credentials: "token"},
			},
		},
		{
			name: "Cloudflare Access",
			config: commonconfig.HTTPClientConfig{
				Authorization: &commonconfig.Authorization{Type: "  CF-Access  "},
			},
			enabled: true,
		},
		{
			name: "inline credentials",
			config: commonconfig.HTTPClientConfig{
				Authorization: &commonconfig.Authorization{Type: AuthorizationType, Credentials: "token"},
			},
			wantErr: `authorization credentials, credentials_file & credentials_ref must not be configured when authorization type is "cf-access"`,
		},
		{
			name: "credentials file",
			config: commonconfig.HTTPClientConfig{
				Authorization: &commonconfig.Authorization{Type: AuthorizationType, CredentialsFile: "token-file"},
			},
			wantErr: `authorization credentials, credentials_file & credentials_ref must not be configured when authorization type is "cf-access"`,
		},
		{
			name: "credentials reference",
			config: commonconfig.HTTPClientConfig{
				Authorization: &commonconfig.Authorization{Type: AuthorizationType, CredentialsRef: "token-ref"},
			},
			wantErr: `authorization credentials, credentials_file & credentials_ref must not be configured when authorization type is "cf-access"`,
		},
		{
			name: "basic authentication",
			config: commonconfig.HTTPClientConfig{
				Authorization: &commonconfig.Authorization{Type: AuthorizationType},
				BasicAuth:     &commonconfig.BasicAuth{},
			},
			wantErr: `basic_auth, oauth2, bearer_token & bearer_token_file must not be configured when authorization type is "cf-access"`,
		},
		{
			name: "OAuth2",
			config: commonconfig.HTTPClientConfig{
				Authorization: &commonconfig.Authorization{Type: AuthorizationType},
				OAuth2:        &commonconfig.OAuth2{},
			},
			wantErr: `basic_auth, oauth2, bearer_token & bearer_token_file must not be configured when authorization type is "cf-access"`,
		},
		{
			name: "bearer token",
			config: commonconfig.HTTPClientConfig{
				Authorization: &commonconfig.Authorization{Type: AuthorizationType},
				BearerToken:   "token",
			},
			wantErr: `basic_auth, oauth2, bearer_token & bearer_token_file must not be configured when authorization type is "cf-access"`,
		},
		{
			name: "bearer token file",
			config: commonconfig.HTTPClientConfig{
				Authorization:   &commonconfig.Authorization{Type: AuthorizationType},
				BearerTokenFile: "token-file",
			},
			wantErr: `basic_auth, oauth2, bearer_token & bearer_token_file must not be configured when authorization type is "cf-access"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			originalAuthorization := tc.config.Authorization
			clean, enabled, err := PrepareHTTPClientConfig(tc.config)
			if tc.wantErr != "" {
				require.EqualError(t, err, tc.wantErr)
				require.False(t, enabled)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.enabled, enabled)
			require.Same(t, originalAuthorization, tc.config.Authorization)
			if tc.enabled {
				require.Nil(t, clean.Authorization)
			} else {
				require.Same(t, originalAuthorization, clean.Authorization)
			}
		})
	}
}
