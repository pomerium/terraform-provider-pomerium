package provider_test

import (
	"strings"
	"testing"

	"github.com/pomerium/enterprise-terraform-provider/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateBootstrapServiceAccountToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		sharedSecret  string
		expectError   bool
		validateToken func(t *testing.T, token string)
	}{
		{
			name:         "invalid base64",
			sharedSecret: "not-base64",
			expectError:  true,
		},
		{
			name:         "valid base64",
			sharedSecret: "dGVzdC1zZWNyZXQ=", // "test-secret" in base64
			expectError:  false,
			validateToken: func(t *testing.T, token string) {
				// JWT format: header.payload.signature
				parts := strings.Split(token, ".")
				require.Len(t, parts, 3)
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			token, err := provider.GenerateBootstrapServiceAccountToken(tt.sharedSecret)
			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.NotEmpty(t, token)

			if tt.validateToken != nil {
				tt.validateToken(t, token)
			}
		})
	}
}
