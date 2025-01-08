package provider_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/pomerium/enterprise-client-go/pb"
	"github.com/pomerium/enterprise-terraform-provider/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
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
		expected timetypes.GoDuration
	}{
		{
			name:     "nil duration",
			input:    nil,
			expected: timetypes.NewGoDurationNull(),
		},
		{
			name:     "zero duration",
			input:    durationpb.New(0),
			expected: timetypes.NewGoDurationValueFromStringMust("0s"),
		},
		{
			name:     "normal duration",
			input:    durationpb.New(time.Hour + time.Minute),
			expected: timetypes.NewGoDurationValueFromStringMust("1h1m0s"),
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

func TestGoStructToPB(t *testing.T) {
	type TestStruct struct {
		FirstName types.String
		LastName  types.String
	}

	tests := []struct {
		name     string
		input    interface{}
		want     *structpb.Struct
		wantErr  bool
		errorMsg string
	}{
		{
			name: "basic test",
			input: TestStruct{
				FirstName: basetypes.NewStringValue("John"),
				LastName:  basetypes.NewStringValue("Doe"),
			},
			want: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"first_name": structpb.NewStringValue("John"),
					"last_name":  structpb.NewStringValue("Doe"),
				},
			},
			wantErr: false,
		},
		{
			name:    "nil input",
			input:   nil,
			want:    nil,
			wantErr: false,
		},
		{
			name:  "empty struct",
			input: TestStruct{},
			want: &structpb.Struct{
				Fields: map[string]*structpb.Value{},
			},
			wantErr: false,
		},
		{
			name: "with nil StringValue",
			input: TestStruct{
				FirstName: basetypes.NewStringValue("John"),
				LastName:  basetypes.NewStringNull(),
			},
			want: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"first_name": structpb.NewStringValue("John"),
				},
			},
			wantErr: false,
		},
		{
			name:     "non-struct input",
			input:    123,
			want:     nil,
			wantErr:  true,
			errorMsg: "input must be a struct, got int",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := provider.GoStructToPB(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.EqualError(t, err, tt.errorMsg)
				}
				assert.Nil(t, got)
				return
			}
			assert.NoError(t, err)
			assert.Empty(t, cmp.Diff(tt.want, got, protocmp.Transform()))
		})
	}
}

func TestPBStructToTF(t *testing.T) {
	type TestStruct struct {
		Field1 types.String `tfsdk:"field_one"`
		Field2 types.String `tfsdk:"field_two"`
	}

	testCases := []struct {
		name        string
		src         *structpb.Struct
		want        types.Object
		wantErr     bool
		wantWarning bool
	}{
		{
			name: "successful conversion",
			src: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"field_one": structpb.NewStringValue("value1"),
					"field_two": structpb.NewStringValue("value2"),
				},
			},
			want: types.ObjectValueMust(map[string]attr.Type{
				"field_one": types.StringType,
				"field_two": types.StringType,
			}, map[string]attr.Value{
				"field_one": types.StringValue("value1"),
				"field_two": types.StringValue("value2"),
			}),
		},
		{
			name: "missing field in source",
			src: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"field_one": structpb.NewStringValue("value1"),
				},
			},
			want: types.ObjectValueMust(map[string]attr.Type{
				"field_one": types.StringType,
				"field_two": types.StringType,
			}, map[string]attr.Value{
				"field_one": types.StringValue("value1"),
				"field_two": types.StringNull(),
			}),
		},
		{
			name: "nil source struct",
			want: types.ObjectNull(map[string]attr.Type{
				"field_one": types.StringType,
				"field_two": types.StringType,
			}),
		},
		{
			name: "unexpected field in source",
			src: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"field_one":  structpb.NewStringValue("value1"),
					"field_two":  structpb.NewStringValue("value2"),
					"unexpected": structpb.NewStringValue("value3"),
				},
			},
			want: types.ObjectValueMust(map[string]attr.Type{
				"field_one": types.StringType,
				"field_two": types.StringType,
			}, map[string]attr.Value{
				"field_one": types.StringValue("value1"),
				"field_two": types.StringValue("value2"),
			}),
			wantWarning: true,
		},
		{
			name: "unsupported field type in source",
			src: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"field_one": structpb.NewStringValue("value1"),
					"field_two": structpb.NewNumberValue(123),
				},
			},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dst := types.ObjectNull(map[string]attr.Type{
				"field_one": types.StringType,
				"field_two": types.StringType,
			})
			var diags diag.Diagnostics
			provider.PBStructToTF[TestStruct](&dst, tc.src, &diags)

			require.Equal(t, tc.wantErr, diags.HasError(), diags)
			if tc.wantWarning {
				assert.NotEmpty(t, diags.Warnings())
			}

			if !tc.wantErr {
				assert.Empty(t, cmp.Diff(tc.want, dst))
			}
		})
	}
}
