package provider_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/pomerium/enterprise-client-go/pb"
	"github.com/pomerium/enterprise-terraform-provider/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetValidEnumValuesCanonical(t *testing.T) {
	t.Parallel()

	values := provider.GetValidEnumValuesCanonical[pb.LoadBalancingPolicy]("LOAD_BALANCING_POLICY")
	assert.Empty(t, cmp.Diff(
		[]string{"maglev", "random", "ring_hash", "round_robin", "least_request"},
		values,
		cmpopts.SortSlices(func(a, b string) bool { return a < b }),
	))
}

func TestOptionalEnumValueToPB(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		input       types.String
		prefix      string
		expectNil   bool
		expectValue pb.LoadBalancingPolicy
		expectError bool
	}{
		{
			name:        "valid value",
			input:       types.StringValue("round_robin"),
			prefix:      "LOAD_BALANCING_POLICY",
			expectNil:   false,
			expectValue: pb.LoadBalancingPolicy_LOAD_BALANCING_POLICY_ROUND_ROBIN,
			expectError: false,
		},
		{
			name:        "another valid value",
			input:       types.StringValue("least_request"),
			prefix:      "LOAD_BALANCING_POLICY",
			expectNil:   false,
			expectValue: pb.LoadBalancingPolicy_LOAD_BALANCING_POLICY_LEAST_REQUEST,
			expectError: false,
		},
		{
			name:        "null value",
			input:       types.StringNull(),
			prefix:      "LOAD_BALANCING_POLICY",
			expectNil:   true,
			expectError: false,
		},
		{
			name:        "invalid value",
			input:       types.StringValue("INVALID_VALUE"),
			prefix:      "LOAD_BALANCING_POLICY",
			expectNil:   false,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got *pb.LoadBalancingPolicy
			var diagnostics diag.Diagnostics

			provider.OptionalEnumValueToPB(&got, tt.input, tt.prefix, &diagnostics)

			if tt.expectError {
				assert.True(t, diagnostics.HasError())
			} else {
				require.False(t, diagnostics.HasError(), diagnostics.Errors())
				if tt.expectNil {
					assert.Nil(t, got)
				} else {
					require.NotNil(t, got)
					assert.Equal(t, tt.expectValue, *got)
				}
			}
		})
	}
}

func TestOptionalEnumValueFromPB(t *testing.T) {
	t.Parallel()

	prefix := "LOAD_BALANCING_POLICY"
	tests := []struct {
		name        string
		input       *pb.LoadBalancingPolicy
		expectValue types.String
	}{
		{
			name:        "valid value",
			input:       pb.LoadBalancingPolicy_LOAD_BALANCING_POLICY_ROUND_ROBIN.Enum(),
			expectValue: types.StringValue("round_robin"),
		},
		{
			name:        "another valid value",
			input:       pb.LoadBalancingPolicy_LOAD_BALANCING_POLICY_LEAST_REQUEST.Enum(),
			expectValue: types.StringValue("least_request"),
		},
		{
			name:        "nil value",
			input:       nil,
			expectValue: types.StringNull(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := provider.OptionalEnumValueFromPB(tt.input, prefix)
			assert.Equal(t, tt.expectValue, got)
		})
	}
}
