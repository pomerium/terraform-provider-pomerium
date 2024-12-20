package provider_test

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/pomerium/enterprise-client-go/pb"
	"github.com/pomerium/enterprise-terraform-provider/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestFromStringSlice(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected types.List
	}{
		{
			name:     "nil slice",
			input:    nil,
			expected: types.ListNull(types.StringType),
		},
		{
			name:     "empty slice",
			input:    []string{},
			expected: types.ListValueMust(types.StringType, []attr.Value{}),
		},
		{
			name:  "normal slice",
			input: []string{"a", "b", "c"},
			expected: types.ListValueMust(types.StringType, []attr.Value{
				types.StringValue("a"),
				types.StringValue("b"),
				types.StringValue("c"),
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := provider.FromStringSlice(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFromDurationP(t *testing.T) {
	tests := []struct {
		name     string
		input    *durationpb.Duration
		expected types.String
	}{
		{
			name:     "nil duration",
			input:    nil,
			expected: types.StringNull(),
		},
		{
			name:     "zero duration",
			input:    durationpb.New(0),
			expected: types.StringValue("0s"),
		},
		{
			name:     "normal duration",
			input:    durationpb.New(time.Hour + time.Minute),
			expected: types.StringValue("1h1m0s"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := provider.FromDuration(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestToStringList(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name        string
		input       types.List
		expectError bool
		validate    func(*testing.T, *pb.Settings_StringList)
	}{
		{
			name:  "null list",
			input: types.ListNull(types.StringType),
			validate: func(t *testing.T, s *pb.Settings_StringList) {
				assert.Nil(t, s)
			},
		},
		{
			name:  "empty list",
			input: types.ListValueMust(types.StringType, []attr.Value{}),
			validate: func(t *testing.T, s *pb.Settings_StringList) {
				require.NotNil(t, s)
				assert.Empty(t, s.Values)
			},
		},
		{
			name: "valid list",
			input: types.ListValueMust(types.StringType, []attr.Value{
				types.StringValue("value1"),
				types.StringValue("value2"),
			}),
			validate: func(t *testing.T, s *pb.Settings_StringList) {
				require.NotNil(t, s)
				assert.Equal(t, []string{"value1", "value2"}, s.Values)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result *pb.Settings_StringList
			diagnostics := diag.Diagnostics{}
			provider.ToStringList(ctx, &result, tt.input, &diagnostics)

			if tt.expectError {
				assert.True(t, diagnostics.HasError())
				return
			}

			assert.False(t, diagnostics.HasError())
			if tt.validate != nil {
				tt.validate(t, result)
			}
		})
	}
}
