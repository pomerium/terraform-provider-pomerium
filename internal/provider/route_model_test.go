package provider_test

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/pomerium/enterprise-client-go/pb"
	"github.com/pomerium/enterprise-terraform-provider/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertRouteFromPB(t *testing.T) {
	t.Run("jwt_issuer_format", func(t *testing.T) {
		testCases := []struct {
			name     string
			input    pb.IssuerFormat
			expected string
			isNull   bool
		}{
			{
				name:     "host_only",
				input:    pb.IssuerFormat_IssuerHostOnly,
				expected: "IssuerHostOnly",
			},
			{
				name:     "uri",
				input:    pb.IssuerFormat_IssuerURI,
				expected: "IssuerURI",
			},
			{
				name:   "invalid value",
				input:  pb.IssuerFormat(999),
				isNull: true,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				m := &provider.RouteModel{}
				r := &pb.Route{
					JwtIssuerFormat: tc.input,
				}
				diags := provider.ConvertRouteFromPB(m, r)
				require.False(t, diags.HasError())
				if tc.isNull {
					assert.True(t, m.JWTIssuerFormat.IsNull())
				} else {
					assert.Equal(t, tc.expected, m.JWTIssuerFormat.ValueString())
				}
			})
		}
	})
}

func TestConvertRouteToPB(t *testing.T) {
	t.Run("jwt_issuer_format", func(t *testing.T) {
		testCases := []struct {
			name        string
			input       string
			expected    pb.IssuerFormat
			expectError bool
		}{
			{"host_only", "IssuerHostOnly", pb.IssuerFormat_IssuerHostOnly, false},
			{"uri", "IssuerURI", pb.IssuerFormat_IssuerURI, false},
			{"invalid_value", "invalid_value", -1, true},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				m := &provider.RouteModel{
					JWTIssuerFormat: types.StringValue(tc.input),
				}
				r, diag := provider.ConvertRouteToPB(context.Background(), m)
				if tc.expectError {
					require.True(t, diag.HasError())
				} else {
					require.False(t, diag.HasError())
					assert.Equal(t, tc.expected, r.JwtIssuerFormat)
				}
			})
		}
	})
}
