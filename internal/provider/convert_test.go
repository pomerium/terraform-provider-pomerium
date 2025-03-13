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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/enterprise-client-go/pb"
	"github.com/pomerium/enterprise-terraform-provider/internal/provider"
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
			result := provider.FromStringSliceToList(tt.input)
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

func TestToDuration(t *testing.T) {
	tests := []struct {
		name        string
		input       timetypes.GoDuration
		expected    *durationpb.Duration
		expectError bool
	}{
		{
			name:     "null duration",
			input:    timetypes.NewGoDurationNull(),
			expected: nil,
		},
		{
			name:     "unknown duration",
			input:    timetypes.NewGoDurationUnknown(),
			expected: nil,
		},
		{
			name:     "zero duration",
			input:    timetypes.NewGoDurationValueFromStringMust("0s"),
			expected: durationpb.New(0),
		},
		{
			name:     "normal duration",
			input:    timetypes.NewGoDurationValueFromStringMust("1h1m0s"),
			expected: durationpb.New(time.Hour + time.Minute),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result *durationpb.Duration
			diagnostics := diag.Diagnostics{}
			provider.ToDuration(&result, tt.input, &diagnostics)

			if tt.expectError {
				assert.True(t, diagnostics.HasError())
				return
			}

			assert.False(t, diagnostics.HasError())
			if tt.expected == nil {
				assert.Nil(t, result)
			} else {
				assert.Equal(t, tt.expected.AsDuration(), result.AsDuration())
			}
		})
	}
}

func TestToStringListFromSet(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name        string
		input       types.Set
		expectError bool
		validate    func(*testing.T, *pb.Settings_StringList)
	}{
		{
			name:  "null list",
			input: types.SetNull(types.StringType),
			validate: func(t *testing.T, s *pb.Settings_StringList) {
				assert.Nil(t, s)
			},
		},
		{
			name:  "unknown set",
			input: types.SetUnknown(types.StringType),
			validate: func(t *testing.T, s *pb.Settings_StringList) {
				assert.Nil(t, s)
			},
		},
		{
			name:  "empty list",
			input: types.SetValueMust(types.StringType, []attr.Value{}),
			validate: func(t *testing.T, s *pb.Settings_StringList) {
				require.NotNil(t, s)
				assert.Empty(t, s.Values)
			},
		},
		{
			name: "valid list",
			input: types.SetValueMust(types.StringType, []attr.Value{
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
			provider.ToStringListFromSet(ctx, &result, tt.input, &diagnostics)

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

func TestFromStringSliceToSet(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected types.Set
	}{
		{
			name:     "nil slice",
			input:    nil,
			expected: types.SetNull(types.StringType),
		},
		{
			name:     "empty slice",
			input:    []string{},
			expected: types.SetValueMust(types.StringType, []attr.Value{}),
		},
		{
			name:  "normal slice",
			input: []string{"a", "b", "c"},
			expected: types.SetValueMust(types.StringType, []attr.Value{
				types.StringValue("a"),
				types.StringValue("b"),
				types.StringValue("c"),
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := provider.FromStringSliceToSet(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFromStringListToSet(t *testing.T) {
	tests := []struct {
		name     string
		input    *pb.Settings_StringList
		expected types.Set
	}{
		{
			name:     "nil input",
			input:    nil,
			expected: types.SetNull(types.StringType),
		},
		{
			name:     "empty values",
			input:    &pb.Settings_StringList{Values: []string{}},
			expected: types.SetValueMust(types.StringType, []attr.Value{}),
		},
		{
			name:  "with values",
			input: &pb.Settings_StringList{Values: []string{"x", "y", "z"}},
			expected: types.SetValueMust(types.StringType, []attr.Value{
				types.StringValue("x"),
				types.StringValue("y"),
				types.StringValue("z"),
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := provider.FromStringListToSet(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFromStringMap(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]string
		expected types.Map
	}{
		{
			name:     "nil map",
			input:    nil,
			expected: types.MapNull(types.StringType),
		},
		{
			name:     "empty map",
			input:    map[string]string{},
			expected: types.MapValueMust(types.StringType, map[string]attr.Value{}),
		},
		{
			name: "populated map",
			input: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			expected: types.MapValueMust(types.StringType, map[string]attr.Value{
				"key1": types.StringValue("value1"),
				"key2": types.StringValue("value2"),
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := provider.FromStringMap(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestToStringSliceFromSet(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name     string
		input    types.Set
		expected []string
	}{
		{
			name:     "null set",
			input:    types.SetNull(types.StringType),
			expected: nil,
		},
		{
			name:     "unknown set",
			input:    types.SetUnknown(types.StringType),
			expected: nil,
		},
		{
			name:     "empty set",
			input:    types.SetValueMust(types.StringType, nil),
			expected: []string{},
		},
		{
			name: "populated set",
			input: types.SetValueMust(types.StringType, []attr.Value{
				types.StringValue("a"),
				types.StringValue("b"),
			}),
			expected: []string{"a", "b"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result []string
			diagnostics := diag.Diagnostics{}
			provider.ToStringSliceFromSet(ctx, &result, tt.input, &diagnostics)
			assert.False(t, diagnostics.HasError())
			assert.ElementsMatch(t, tt.expected, result)
		})
	}
}

func TestToByteSlice(t *testing.T) {
	tests := []struct {
		name     string
		input    types.String
		expected []byte
	}{
		{
			name:     "null string",
			input:    types.StringNull(),
			expected: nil,
		},
		{
			name:     "empty string",
			input:    types.StringValue(""),
			expected: nil,
		},
		{
			name:     "non-empty string",
			input:    types.StringValue("hello"),
			expected: []byte("hello"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := provider.ToByteSlice(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestStringSliceExclude(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		exclude  []string
		expected []string
	}{
		{
			name:     "exclude none",
			input:    []string{"a", "b", "c"},
			exclude:  []string{},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "exclude some",
			input:    []string{"a", "b", "c"},
			exclude:  []string{"b"},
			expected: []string{"a", "c"},
		},
		{
			name:     "exclude all",
			input:    []string{"a", "b", "c"},
			exclude:  []string{"a", "b", "c"},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := provider.StringSliceExclude(tt.input, tt.exclude)
			assert.ElementsMatch(t, tt.expected, result)
		})
	}
}

func TestToStringSliceFromList(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name     string
		input    types.List
		expected []string
	}{
		{
			name:     "null list",
			input:    types.ListNull(types.StringType),
			expected: nil,
		},
		{
			name:     "unknown list",
			input:    types.ListUnknown(types.StringType),
			expected: nil,
		},
		{
			name:     "empty list",
			input:    types.ListValueMust(types.StringType, []attr.Value{}),
			expected: []string{},
		},
		{
			name: "populated list",
			input: types.ListValueMust(types.StringType, []attr.Value{
				types.StringValue("a"),
				types.StringValue("b"),
			}),
			expected: []string{"a", "b"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result []string
			diagnostics := diag.Diagnostics{}
			provider.ToStringSliceFromList(ctx, &result, tt.input, &diagnostics)
			assert.False(t, diagnostics.HasError())
			assert.ElementsMatch(t, tt.expected, result)
		})
	}
}

func TestToStringMap(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name     string
		input    types.Map
		expected map[string]string
	}{
		{
			name:     "null map",
			input:    types.MapNull(types.StringType),
			expected: nil,
		},
		{
			name:     "unknown map",
			input:    types.MapUnknown(types.StringType),
			expected: nil,
		},
		{
			name:     "empty map",
			input:    types.MapValueMust(types.StringType, map[string]attr.Value{}),
			expected: map[string]string{},
		},
		{
			name: "populated map",
			input: types.MapValueMust(types.StringType, map[string]attr.Value{
				"key1": types.StringValue("value1"),
				"key2": types.StringValue("value2"),
			}),
			expected: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result map[string]string
			diagnostics := diag.Diagnostics{}
			provider.ToStringMap(ctx, &result, tt.input, &diagnostics)
			assert.False(t, diagnostics.HasError())
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetTFObjectTypes(t *testing.T) {
	type TestStruct struct {
		Field1 types.String `tfsdk:"field_one"`
		Field2 types.String `tfsdk:"field_two"`
	}

	expected := map[string]attr.Type{
		"field_one": types.StringType,
		"field_two": types.StringType,
	}

	result, err := provider.GetTFObjectTypes[TestStruct]()
	require.NoError(t, err)
	assert.Equal(t, expected, result)

	// Test error cases
	type InvalidStruct struct {
		Field1 int `tfsdk:"field_one"` // Invalid type
	}
	_, err = provider.GetTFObjectTypes[InvalidStruct]()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported field type")

	type NoTagStruct struct {
		Field1 types.String // Missing tfsdk tag
	}
	_, err = provider.GetTFObjectTypes[NoTagStruct]()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing tfsdk tag")
}

func TestFromStringList(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		in     *pb.Route_StringList
		expect types.Set
	}{
		{
			"null",
			nil,
			types.SetNull(types.StringType),
		},
		{
			"empty",
			&pb.Route_StringList{},
			types.SetValueMust(types.StringType, []attr.Value{}),
		},
		{
			"entries",
			&pb.Route_StringList{Values: []string{"a", "b", "c"}},
			types.SetValueMust(types.StringType, []attr.Value{
				types.StringValue("a"), types.StringValue("b"), types.StringValue("c"),
			}),
		},
	} {
		assert.Equal(t, tc.expect, provider.FromStringList(tc.in),
			"%s: should convert %v to %v", tc.name, tc.in, tc.expect)
	}
}

func TestFromBearerTokenFormat(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		in     *pb.BearerTokenFormat
		expect types.String
	}{
		{"null", nil, types.StringNull()},
		{"unknown", pb.BearerTokenFormat_BEARER_TOKEN_FORMAT_UNKNOWN.Enum(), types.StringValue("")},
		{"default", pb.BearerTokenFormat_BEARER_TOKEN_FORMAT_DEFAULT.Enum(), types.StringValue("default")},
		{"idp_access_token", pb.BearerTokenFormat_BEARER_TOKEN_FORMAT_IDP_ACCESS_TOKEN.Enum(), types.StringValue("idp_access_token")},
		{"idp_identity_token", pb.BearerTokenFormat_BEARER_TOKEN_FORMAT_IDP_IDENTITY_TOKEN.Enum(), types.StringValue("idp_identity_token")},
	} {
		assert.Equal(t, tc.expect, provider.FromBearerTokenFormat(tc.in),
			"%s: should convert %v to %v", tc.name, tc.in, tc.expect)
	}
}

func TestToBearerTokenFormat(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		in     types.String
		expect *pb.BearerTokenFormat
	}{
		{"null", types.StringNull(), nil},
		{"unknown", types.StringValue(""), pb.BearerTokenFormat_BEARER_TOKEN_FORMAT_UNKNOWN.Enum()},
		{"default", types.StringValue("default"), pb.BearerTokenFormat_BEARER_TOKEN_FORMAT_DEFAULT.Enum()},
		{"idp_access_token", types.StringValue("idp_access_token"), pb.BearerTokenFormat_BEARER_TOKEN_FORMAT_IDP_ACCESS_TOKEN.Enum()},
		{"idp_identity_token", types.StringValue("idp_identity_token"), pb.BearerTokenFormat_BEARER_TOKEN_FORMAT_IDP_IDENTITY_TOKEN.Enum()},
	} {
		assert.Equal(t, tc.expect, provider.ToBearerTokenFormat(tc.in),
			"%s: should convert %v to %v", tc.name, tc.in, tc.expect)
	}
}

func TestFromIssuerFormat(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		in     *pb.IssuerFormat
		expect types.String
	}{
		{"null", nil, types.StringNull()},
		{"host_only", pb.IssuerFormat_IssuerHostOnly.Enum(), types.StringValue("host_only")},
		{"uri", pb.IssuerFormat_IssuerURI.Enum(), types.StringValue("uri")},
		{"unknown", (*pb.IssuerFormat)(proto.Int32(123)), types.StringNull()},
	} {
		assert.Equal(t, tc.expect, provider.FromIssuerFormat(tc.in),
			"%s: should convert %v to %v", tc.name, tc.in, tc.expect)
	}
}

func TestToIssuerFormat(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		in     types.String
		expect *pb.IssuerFormat
	}{
		{"null", types.StringNull(), nil},
		{"unknown", types.StringValue("foobar"), nil},
		{"host_only", types.StringValue("host_only"), pb.IssuerFormat_IssuerHostOnly.Enum()},
		{"hostOnly", types.StringValue("hostOnly"), pb.IssuerFormat_IssuerHostOnly.Enum()},
		{"uri", types.StringValue("uri"), pb.IssuerFormat_IssuerURI.Enum()},
	} {
		assert.Equal(t, tc.expect, provider.ToIssuerFormat(tc.in),
			"%s: should convert %v to %v", tc.name, tc.in, tc.expect)
	}
}

func TestToRouteStringList(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		in         types.Set
		expect     *pb.Route_StringList
		errorCount int
	}{
		{
			"null",
			types.SetNull(types.StringType),
			nil,
			0,
		},
		{
			"unknown",
			types.SetUnknown(types.StringType),
			nil,
			0,
		},
		{
			"empty",
			types.SetValueMust(types.StringType, []attr.Value{}),
			&pb.Route_StringList{Values: []string{}},
			0,
		},
		{
			"entries",
			types.SetValueMust(types.StringType, []attr.Value{
				types.StringValue("a"), types.StringValue("b"), types.StringValue("c"),
			}),
			&pb.Route_StringList{Values: []string{
				"a", "b", "c",
			}},
			0,
		},
	} {
		ctx := context.Background()
		var diagnostics diag.Diagnostics
		dst := new(*pb.Route_StringList)
		provider.ToRouteStringList(ctx, dst, tc.in, &diagnostics)
		assert.Equal(t, tc.expect, *dst)
		assert.Equal(t, tc.errorCount, diagnostics.ErrorsCount())
	}
}

func TestToSettingsStringList(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		in         types.Set
		expect     *pb.Settings_StringList
		errorCount int
	}{
		{
			"null",
			types.SetNull(types.StringType),
			nil,
			0,
		},
		{
			"unknown",
			types.SetUnknown(types.StringType),
			nil,
			0,
		},
		{
			"empty",
			types.SetValueMust(types.StringType, []attr.Value{}),
			&pb.Settings_StringList{Values: []string{}},
			0,
		},
		{
			"entries",
			types.SetValueMust(types.StringType, []attr.Value{
				types.StringValue("a"), types.StringValue("b"), types.StringValue("c"),
			}),
			&pb.Settings_StringList{Values: []string{
				"a", "b", "c",
			}},
			0,
		},
	} {
		ctx := context.Background()
		var diagnostics diag.Diagnostics
		dst := new(*pb.Settings_StringList)
		provider.ToSettingsStringList(ctx, dst, tc.in, &diagnostics)
		assert.Equal(t, tc.expect, *dst)
		assert.Equal(t, tc.errorCount, diagnostics.ErrorsCount())
	}
}
