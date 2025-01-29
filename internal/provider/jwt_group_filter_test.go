package provider

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/pomerium/enterprise-client-go/pb"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestJWTGroupsFilterFromPB(t *testing.T) {
	tests := []struct {
		name     string
		input    *pb.JwtGroupsFilter
		expected types.Object
	}{
		{
			name:     "nil input",
			input:    nil,
			expected: types.ObjectNull(jwtGroupsFilterSchemaAttr),
		},
		{
			name: "empty groups",
			input: &pb.JwtGroupsFilter{
				Groups:       []string{},
				InferFromPpl: false,
			},
			expected: types.ObjectValueMust(jwtGroupsFilterSchemaAttr, map[string]attr.Value{
				"groups":         types.SetValueMust(types.StringType, []attr.Value{}),
				"infer_from_ppl": types.BoolValue(false),
			}),
		},
		{
			name: "with groups",
			input: &pb.JwtGroupsFilter{
				Groups:       []string{"group1", "group2"},
				InferFromPpl: true,
			},
			expected: types.ObjectValueMust(jwtGroupsFilterSchemaAttr, map[string]attr.Value{
				"groups": types.SetValueMust(types.StringType, []attr.Value{
					types.StringValue("group1"),
					types.StringValue("group2"),
				}),
				"infer_from_ppl": types.BoolValue(true),
			}),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var result types.Object
			JWTGroupsFilterFromPB(&result, tc.input)
			diff := cmp.Diff(tc.expected, result)
			assert.Empty(t, diff)
		})
	}
}

func TestJWTGroupsFilterToPB(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name     string
		input    types.Object
		expected *pb.JwtGroupsFilter
	}{
		{
			name:     "null input",
			input:    types.ObjectNull(jwtGroupsFilterSchemaAttr),
			expected: nil,
		},
		{
			name: "empty groups",
			input: types.ObjectValueMust(jwtGroupsFilterSchemaAttr, map[string]attr.Value{
				"groups":         types.SetValueMust(types.StringType, []attr.Value{}),
				"infer_from_ppl": types.BoolValue(false),
			}),
			expected: &pb.JwtGroupsFilter{
				Groups:       []string{},
				InferFromPpl: false,
			},
		},
		{
			name: "with groups",
			input: types.ObjectValueMust(jwtGroupsFilterSchemaAttr, map[string]attr.Value{
				"groups": types.SetValueMust(types.StringType, []attr.Value{
					types.StringValue("group1"),
					types.StringValue("group2"),
				}),
				"infer_from_ppl": types.BoolValue(true),
			}),
			expected: &pb.JwtGroupsFilter{
				Groups:       []string{"group1", "group2"},
				InferFromPpl: true,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var diags diag.Diagnostics
			var result *pb.JwtGroupsFilter
			JWTGroupsFilterToPB(ctx, &result, tc.input, &diags)
			assert.False(t, diags.HasError())
			diff := cmp.Diff(tc.expected, result, protocmp.Transform())
			assert.Empty(t, diff)
		})
	}
}
