package provider_test

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/enterprise-client-go/pb"
	"github.com/pomerium/enterprise-terraform-provider/internal/provider"
)

func TestBaseModelConverter(t *testing.T) {
	t.Parallel()

	t.Run("Duration", func(t *testing.T) {
		t.Parallel()

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
				t.Parallel()

				var diagnostics diag.Diagnostics
				result := provider.NewModelToEnterpriseConverter(&diagnostics).Duration(path.Empty(), tt.input)

				if tt.expectError {
					assert.True(t, diagnostics.HasError())
					return
				}

				assert.Empty(t, diagnostics)
				if tt.expected == nil {
					assert.Nil(t, result)
				} else {
					assert.Equal(t, tt.expected.AsDuration(), result.AsDuration())
				}
			})
		}
	})

	t.Run("StringMap", func(t *testing.T) {
		t.Parallel()

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
				t.Parallel()

				var diagnostics diag.Diagnostics
				result := provider.NewModelToEnterpriseConverter(&diagnostics).StringMap(path.Empty(), tt.input)
				assert.Empty(t, diagnostics)
				assert.Equal(t, tt.expected, result)
			})
		}
	})

	t.Run("StringSliceFromList", func(t *testing.T) {
		t.Parallel()

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
				t.Parallel()

				var diagnostics diag.Diagnostics
				result := provider.NewModelToEnterpriseConverter(&diagnostics).StringSliceFromList(path.Empty(), tt.input)
				assert.Empty(t, diagnostics)
				assert.Equal(t, tt.expected, result)
			})
		}
	})

	t.Run("StringSliceFromSet", func(t *testing.T) {
		t.Parallel()

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
				t.Parallel()

				var diagnostics diag.Diagnostics
				result := provider.NewModelToEnterpriseConverter(&diagnostics).StringSliceFromSet(path.Empty(), tt.input)
				assert.Empty(t, diagnostics)
				assert.Equal(t, tt.expected, result)
			})
		}
	})

	t.Run("Timestamp", func(t *testing.T) {
		t.Parallel()

		t.Run("null", func(t *testing.T) {
			t.Parallel()

			var diagnostics diag.Diagnostics
			assert.Nil(t, provider.NewModelToEnterpriseConverter(&diagnostics).Timestamp(path.Empty(), types.StringNull()))
			assert.Empty(t, diagnostics)
		})

		t.Run("unknown", func(t *testing.T) {
			t.Parallel()

			var diagnostics diag.Diagnostics
			assert.Nil(t, provider.NewModelToEnterpriseConverter(&diagnostics).Timestamp(path.Empty(), types.StringUnknown()))
			assert.Empty(t, diagnostics)
		})

		t.Run("invalid", func(t *testing.T) {
			t.Parallel()

			var diagnostics diag.Diagnostics
			assert.Nil(t, provider.NewModelToEnterpriseConverter(&diagnostics).Timestamp(path.Empty(), types.StringValue("<NOT A TIMESTAMP>")))
			assert.NotEmpty(t, diagnostics)
		})

		t.Run("valid", func(t *testing.T) {
			t.Parallel()

			tm := time.Date(2026, time.February, 12, 15, 22, 0, 0, time.UTC)

			var diagnostics diag.Diagnostics
			assert.Empty(t, cmp.Diff(
				timestamppb.New(tm),
				provider.NewModelToEnterpriseConverter(&diagnostics).Timestamp(path.Empty(), types.StringValue(tm.Format(time.RFC1123))),
				protocmp.Transform(),
			))
			assert.Empty(t, diagnostics)
		})
	})
}

func TestBaseProtoConverter(t *testing.T) {
	t.Parallel()

	t.Run("Duration", func(t *testing.T) {
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
				t.Parallel()

				var diagnostics diag.Diagnostics
				result := provider.NewEnterpriseToModelConverter(&diagnostics).Duration(tt.input)
				assert.Empty(t, diagnostics)
				assert.Empty(t, cmp.Diff(tt.expected, result, protocmp.Transform()))
			})
		}
	})
}

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
		{"host_only", pb.IssuerFormat_IssuerHostOnly.Enum(), types.StringValue("IssuerHostOnly")},
		{"uri", pb.IssuerFormat_IssuerURI.Enum(), types.StringValue("IssuerURI")},
		{"unknown", (*pb.IssuerFormat)(proto.Int32(123)), types.StringNull()},
	} {
		assert.Equal(t, tc.expect, provider.FromIssuerFormat(tc.in),
			"%s: should convert %v to %v", tc.name, tc.in, tc.expect)
	}
}

func TestToIssuerFormat(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name                 string
		in                   types.String
		expect               *pb.IssuerFormat
		expectedErrorDetails string
	}{
		{"null", types.StringNull(), nil, ""},
		{"host_only", types.StringValue("IssuerHostOnly"), pb.IssuerFormat_IssuerHostOnly.Enum(), ""},
		{"uri", types.StringValue("IssuerURI"), pb.IssuerFormat_IssuerURI.Enum(), ""},
		{"unknown", types.StringValue("foobar"), nil, `unknown issuer format "foobar"`},
	} {
		diagnostics := diag.Diagnostics{}
		assert.Equal(t, tc.expect, provider.ToIssuerFormat(tc.in, &diagnostics),
			"%s: should convert %v to %v", tc.name, tc.in, tc.expect)
		if tc.expectedErrorDetails == "" {
			assert.False(t, diagnostics.HasError())
		} else {
			assert.Len(t, diagnostics, 1)
			assert.Equal(t, tc.expectedErrorDetails, diagnostics[0].Detail())
		}
	}
}

func TestConvertRoute(t *testing.T) {
	t.Parallel()

	pbRoute := &pb.Route{
		Id:                               "route-123",
		Name:                             "test-route",
		From:                             "https://from.example.com",
		To:                               []string{"https://to1.example.com", "https://to2.example.com"},
		NamespaceId:                      "namespace-123",
		PolicyIds:                        []string{"policy-1", "policy-2"},
		StatName:                         "test-stat",
		Prefix:                           ptr("/prefix"),
		Path:                             ptr("/path"),
		Regex:                            ptr("^/regex.*$"),
		PrefixRewrite:                    ptr("/prefix-rewrite"),
		RegexRewritePattern:              ptr("^/old(.*)$"),
		RegexRewriteSubstitution:         ptr("/new$1"),
		HostRewrite:                      ptr("rewritten-host"),
		HostRewriteHeader:                ptr("X-Host-Header"),
		HostPathRegexRewritePattern:      ptr("^/path-pattern(.*)$"),
		HostPathRegexRewriteSubstitution: ptr("host-sub$1"),
		RegexPriorityOrder:               ptr(int64(10)),
		Timeout:                          durationpb.New(30 * time.Second),
		IdleTimeout:                      durationpb.New(5 * time.Minute),
		AllowWebsockets:                  ptr(true),
		AllowSpdy:                        ptr(true),
		TlsSkipVerify:                    ptr(false),
		TlsUpstreamServerName:            ptr("upstream.example.com"),
		TlsDownstreamServerName:          ptr("downstream.example.com"),
		TlsUpstreamAllowRenegotiation:    ptr(true),
		SetRequestHeaders:                map[string]string{"X-Request-1": "value1", "X-Request-2": "value2"},
		RemoveRequestHeaders:             []string{"X-Remove-1", "X-Remove-2"},
		SetResponseHeaders:               map[string]string{"X-Response-1": "value1", "X-Response-2": "value2"},
		PreserveHostHeader:               ptr(true),
		PassIdentityHeaders:              ptr(true),
		KubernetesServiceAccountToken:    ptr("k8s-token"),
		IdpClientId:                      ptr("idp-client-id"),
		IdpClientSecret:                  ptr("idp-client-secret"),
		ShowErrorDetails:                 true,
		TlsClientKeyPairId:               ptr("client-key-pair-123"),
		TlsCustomCaKeyPairId:             ptr("ca-key-pair-123"),
		Description:                      ptr("Route description"),
		LogoUrl:                          ptr("https://logo.example.com/logo.png"),
		EnableGoogleCloudServerlessAuthentication: true,
		KubernetesServiceAccountTokenFile:         ptr("/path/to/token"),
		JwtIssuerFormat:                           pb.IssuerFormat_IssuerURI.Enum(),
		BearerTokenFormat:                         pb.BearerTokenFormat_BEARER_TOKEN_FORMAT_IDP_ACCESS_TOKEN.Enum(),
		IdpAccessTokenAllowedAudiences:            &pb.Route_StringList{Values: []string{"aud1", "aud2"}},
		LoadBalancingPolicy:                       pb.LoadBalancingPolicy_LOAD_BALANCING_POLICY_ROUND_ROBIN.Enum(),
		RewriteResponseHeaders: []*pb.RouteRewriteHeader{
			{
				Header:  "X-Rewrite-Header",
				Value:   "new-value",
				Matcher: &pb.RouteRewriteHeader_Prefix{Prefix: "old-prefix"},
			},
		},
		JwtGroupsFilter: &pb.JwtGroupsFilter{
			Groups:       []string{"group1", "group2"},
			InferFromPpl: ptr(true),
		},
		OriginatorId: provider.OriginatorID,
		HealthChecks: []*pb.HealthCheck{
			{
				Timeout:               durationpb.New(5 * time.Second),
				Interval:              durationpb.New(10 * time.Second),
				InitialJitter:         durationpb.New(100 * time.Millisecond),
				IntervalJitter:        durationpb.New(200 * time.Millisecond),
				IntervalJitterPercent: 5,
				UnhealthyThreshold:    2,
				HealthyThreshold:      2,
				HealthChecker: &pb.HealthCheck_HttpHealthCheck_{
					HttpHealthCheck: &pb.HealthCheck_HttpHealthCheck{
						Host:            "health.example.com",
						Path:            "/health",
						CodecClientType: pb.CodecClientType_HTTP2,
						ExpectedStatuses: []*pb.Int64Range{
							{Start: 200, End: 300},
						},
						RetriableStatuses: []*pb.Int64Range{
							{Start: 500, End: 501},
						},
					},
				},
			},
			{
				Timeout:            durationpb.New(3 * time.Second),
				Interval:           durationpb.New(15 * time.Second),
				UnhealthyThreshold: 3,
				HealthyThreshold:   1,
				HealthChecker: &pb.HealthCheck_TcpHealthCheck_{
					TcpHealthCheck: &pb.HealthCheck_TcpHealthCheck{
						Send: &pb.HealthCheck_Payload{
							Payload: &pb.HealthCheck_Payload_Text{
								Text: "000000FF",
							},
						},
						Receive: []*pb.HealthCheck_Payload{
							{
								Payload: &pb.HealthCheck_Payload_Text{
									Text: "0000FFFF",
								},
							},
						},
					},
				},
			},
			{
				Timeout:            durationpb.New(2 * time.Second),
				Interval:           durationpb.New(5 * time.Second),
				UnhealthyThreshold: 2,
				HealthyThreshold:   1,
				HealthChecker: &pb.HealthCheck_GrpcHealthCheck_{
					GrpcHealthCheck: &pb.HealthCheck_GrpcHealthCheck{
						ServiceName: "my-service",
						Authority:   "grpc.example.com",
					},
				},
			},
		},
		DependsOn:             []string{"foo.example.com", "bar.example.com:8443"},
		HealthyPanicThreshold: ptr(int32(33)),
	}

	tfRoute := provider.RouteModel{
		ID:                               types.StringValue("route-123"),
		Name:                             types.StringValue("test-route"),
		From:                             types.StringValue("https://from.example.com"),
		To:                               types.SetValueMust(types.StringType, []attr.Value{types.StringValue("https://to1.example.com"), types.StringValue("https://to2.example.com")}),
		NamespaceID:                      types.StringValue("namespace-123"),
		Policies:                         types.SetValueMust(types.StringType, []attr.Value{types.StringValue("policy-1"), types.StringValue("policy-2")}),
		StatName:                         types.StringValue("test-stat"),
		Prefix:                           types.StringValue("/prefix"),
		Path:                             types.StringValue("/path"),
		Regex:                            types.StringValue("^/regex.*$"),
		PrefixRewrite:                    types.StringValue("/prefix-rewrite"),
		RegexRewritePattern:              types.StringValue("^/old(.*)$"),
		RegexRewriteSubstitution:         types.StringValue("/new$1"),
		HostRewrite:                      types.StringValue("rewritten-host"),
		HostRewriteHeader:                types.StringValue("X-Host-Header"),
		HostPathRegexRewritePattern:      types.StringValue("^/path-pattern(.*)$"),
		HostPathRegexRewriteSubstitution: types.StringValue("host-sub$1"),
		RegexPriorityOrder:               types.Int64Value(10),
		Timeout:                          timetypes.NewGoDurationValue(30 * time.Second),
		IdleTimeout:                      timetypes.NewGoDurationValue(5 * time.Minute),
		AllowWebsockets:                  types.BoolValue(true),
		AllowSPDY:                        types.BoolValue(true),
		TLSSkipVerify:                    types.BoolValue(false),
		TLSUpstreamServerName:            types.StringValue("upstream.example.com"),
		TLSDownstreamServerName:          types.StringValue("downstream.example.com"),
		TLSUpstreamAllowRenegotiation:    types.BoolValue(true),
		SetRequestHeaders: types.MapValueMust(types.StringType, map[string]attr.Value{
			"X-Request-1": types.StringValue("value1"),
			"X-Request-2": types.StringValue("value2"),
		}),
		RemoveRequestHeaders: types.SetValueMust(types.StringType, []attr.Value{types.StringValue("X-Remove-1"), types.StringValue("X-Remove-2")}),
		SetResponseHeaders: types.MapValueMust(types.StringType, map[string]attr.Value{
			"X-Response-1": types.StringValue("value1"),
			"X-Response-2": types.StringValue("value2"),
		}),
		PreserveHostHeader:            types.BoolValue(true),
		PassIdentityHeaders:           types.BoolValue(true),
		KubernetesServiceAccountToken: types.StringValue("k8s-token"),
		IDPClientID:                   types.StringValue("idp-client-id"),
		IDPClientSecret:               types.StringValue("idp-client-secret"),
		ShowErrorDetails:              types.BoolValue(true),
		TLSClientKeyPairID:            types.StringValue("client-key-pair-123"),
		TLSCustomCAKeyPairID:          types.StringValue("ca-key-pair-123"),
		Description:                   types.StringValue("Route description"),
		LogoURL:                       types.StringValue("https://logo.example.com/logo.png"),
		EnableGoogleCloudServerlessAuthentication: types.BoolValue(true),
		KubernetesServiceAccountTokenFile:         types.StringValue("/path/to/token"),
		JWTIssuerFormat:                           types.StringValue("IssuerURI"),
		BearerTokenFormat:                         types.StringValue("idp_access_token"),
		IDPAccessTokenAllowedAudiences:            types.SetValueMust(types.StringType, []attr.Value{types.StringValue("aud1"), types.StringValue("aud2")}),
		LoadBalancingPolicy:                       types.StringValue("round_robin"),
		JWTGroupsFilter: types.ObjectValueMust(
			map[string]attr.Type{
				"infer_from_ppl": types.BoolType,
				"groups":         types.SetType{ElemType: types.StringType},
			},
			map[string]attr.Value{
				"infer_from_ppl": types.BoolValue(true),
				"groups":         types.SetValueMust(types.StringType, []attr.Value{types.StringValue("group1"), types.StringValue("group2")}),
			},
		),
		RewriteResponseHeaders: types.SetValueMust(
			provider.RewriteHeaderObjectType(),
			[]attr.Value{types.ObjectValueMust(
				provider.RewriteHeaderObjectType().AttrTypes,
				map[string]attr.Value{
					"header": types.StringValue("X-Rewrite-Header"),
					"value":  types.StringValue("new-value"),
					"prefix": types.StringValue("old-prefix"),
				},
			)},
		),
		HealthChecks: types.SetValueMust(
			provider.HealthCheckObjectType(),
			[]attr.Value{
				types.ObjectValueMust(
					provider.HealthCheckObjectType().AttrTypes,
					map[string]attr.Value{
						"timeout":                 timetypes.NewGoDurationValue(5 * time.Second),
						"interval":                timetypes.NewGoDurationValue(10 * time.Second),
						"initial_jitter":          timetypes.NewGoDurationValue(100 * time.Millisecond),
						"interval_jitter":         timetypes.NewGoDurationValue(200 * time.Millisecond),
						"interval_jitter_percent": types.Int64Value(5),
						"unhealthy_threshold":     types.Int64Value(2),
						"healthy_threshold":       types.Int64Value(2),
						"tcp_health_check":        types.ObjectNull(provider.TCPHealthCheckObjectType().AttrTypes),
						"grpc_health_check":       types.ObjectNull(provider.GrpcHealthCheckObjectType().AttrTypes),
						"http_health_check": types.ObjectValueMust(
							provider.HTTPHealthCheckObjectType().AttrTypes,
							map[string]attr.Value{
								"host":              types.StringValue("health.example.com"),
								"path":              types.StringValue("/health"),
								"codec_client_type": types.StringValue("HTTP2"),
								"expected_statuses": types.SetValueMust(
									provider.Int64RangeObjectType(),
									[]attr.Value{
										types.ObjectValueMust(
											provider.Int64RangeObjectType().AttrTypes,
											map[string]attr.Value{
												"start": types.Int64Value(200),
												"end":   types.Int64Value(300),
											},
										),
									},
								),
								"retriable_statuses": types.SetValueMust(
									provider.Int64RangeObjectType(),
									[]attr.Value{
										types.ObjectValueMust(
											provider.Int64RangeObjectType().AttrTypes,
											map[string]attr.Value{
												"start": types.Int64Value(500),
												"end":   types.Int64Value(501),
											},
										),
									},
								),
							},
						),
					},
				),
				types.ObjectValueMust(
					provider.HealthCheckObjectType().AttrTypes,
					map[string]attr.Value{
						"timeout":                 timetypes.NewGoDurationValue(3 * time.Second),
						"interval":                timetypes.NewGoDurationValue(15 * time.Second),
						"initial_jitter":          timetypes.NewGoDurationNull(),
						"interval_jitter":         timetypes.NewGoDurationNull(),
						"interval_jitter_percent": types.Int64Null(),
						"unhealthy_threshold":     types.Int64Value(3),
						"healthy_threshold":       types.Int64Value(1),
						"http_health_check":       types.ObjectNull(provider.HTTPHealthCheckObjectType().AttrTypes),
						"grpc_health_check":       types.ObjectNull(provider.GrpcHealthCheckObjectType().AttrTypes),
						"tcp_health_check": types.ObjectValueMust(
							provider.TCPHealthCheckObjectType().AttrTypes,
							map[string]attr.Value{
								"send": types.ObjectValueMust(
									provider.HealthCheckPayloadObjectType().AttrTypes,
									map[string]attr.Value{
										"text":       types.StringValue("000000FF"),
										"binary_b64": types.StringNull(),
									},
								),
								"receive": types.SetValueMust(
									provider.HealthCheckPayloadObjectType(),
									[]attr.Value{
										types.ObjectValueMust(
											provider.HealthCheckPayloadObjectType().AttrTypes,
											map[string]attr.Value{
												"text":       types.StringValue("0000FFFF"),
												"binary_b64": types.StringNull(),
											},
										),
									},
								),
							},
						),
					},
				),
				types.ObjectValueMust(
					provider.HealthCheckObjectType().AttrTypes,
					map[string]attr.Value{
						"timeout":                 timetypes.NewGoDurationValue(2 * time.Second),
						"interval":                timetypes.NewGoDurationValue(5 * time.Second),
						"initial_jitter":          timetypes.NewGoDurationNull(),
						"interval_jitter":         timetypes.NewGoDurationNull(),
						"interval_jitter_percent": types.Int64Null(),
						"unhealthy_threshold":     types.Int64Value(2),
						"healthy_threshold":       types.Int64Value(1),
						"http_health_check":       types.ObjectNull(provider.HTTPHealthCheckObjectType().AttrTypes),
						"tcp_health_check":        types.ObjectNull(provider.TCPHealthCheckObjectType().AttrTypes),
						"grpc_health_check": types.ObjectValueMust(
							provider.GrpcHealthCheckObjectType().AttrTypes,
							map[string]attr.Value{
								"service_name": types.StringValue("my-service"),
								"authority":    types.StringValue("grpc.example.com"),
							},
						),
					},
				),
			},
		),
		DependsOnHosts: types.SetValueMust(types.StringType, []attr.Value{
			types.StringValue("foo.example.com"),
			types.StringValue("bar.example.com:8443"),
		}),
		HealthyPanicThreshold: types.Int32Value(33),
	}

	t.Run("pb to tf", func(t *testing.T) {
		var diagnostics diag.Diagnostics
		got := provider.NewEnterpriseToModelConverter(&diagnostics).Route(pbRoute)
		require.False(t, diagnostics.HasError(), "ConvertRouteFromPB returned diagnostics errors")
		if diff := cmp.Diff(tfRoute, got); diff != "" {
			t.Errorf("ConvertRouteFromPB() mismatch (-want +got):\n%s", diff)
		}
	})
	t.Run("tf to pb", func(t *testing.T) {
		var diagnostics diag.Diagnostics
		got := provider.NewModelToEnterpriseConverter(&diagnostics).Route(tfRoute)
		require.False(t, diagnostics.HasError(), "ConvertRouteToPB returned diagnostics errors")

		if diff := cmp.Diff(pbRoute, got, protocmp.Transform()); diff != "" {
			t.Errorf("ConvertRouteToPB() mismatch (-want +got):\n%s", diff)
		}
	})
}

func TestJWTGroupsFilterFromPB(t *testing.T) {
	tests := []struct {
		name     string
		input    *pb.JwtGroupsFilter
		expected types.Object
	}{
		{
			name:     "nil input",
			input:    nil,
			expected: types.ObjectNull(provider.JWTGroupsFilterObjectType().AttrTypes),
		},
		{
			name: "empty groups",
			input: &pb.JwtGroupsFilter{
				Groups:       []string{},
				InferFromPpl: proto.Bool(false),
			},
			expected: types.ObjectValueMust(provider.JWTGroupsFilterObjectType().AttrTypes, map[string]attr.Value{
				"groups":         types.SetValueMust(types.StringType, []attr.Value{}),
				"infer_from_ppl": types.BoolValue(false),
			}),
		},
		{
			name: "with groups",
			input: &pb.JwtGroupsFilter{
				Groups:       []string{"group1", "group2"},
				InferFromPpl: proto.Bool(true),
			},
			expected: types.ObjectValueMust(provider.JWTGroupsFilterObjectType().AttrTypes, map[string]attr.Value{
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
			var diagnostics diag.Diagnostics
			result := provider.NewEnterpriseToModelConverter(&diagnostics).JWTGroupsFilter(tc.input)
			assert.Empty(t, cmp.Diff(tc.expected, result))
			assert.Empty(t, diagnostics)
		})
	}
}

func TestJWTGroupsFilterToPB(t *testing.T) {
	tests := []struct {
		name     string
		input    types.Object
		expected *pb.JwtGroupsFilter
	}{
		{
			name:     "null input",
			input:    types.ObjectNull(provider.JWTGroupsFilterObjectType().AttrTypes),
			expected: nil,
		},
		{
			name: "empty groups",
			input: types.ObjectValueMust(provider.JWTGroupsFilterObjectType().AttrTypes, map[string]attr.Value{
				"groups":         types.SetValueMust(types.StringType, []attr.Value{}),
				"infer_from_ppl": types.BoolValue(false),
			}),
			expected: &pb.JwtGroupsFilter{
				Groups:       []string{},
				InferFromPpl: proto.Bool(false),
			},
		},
		{
			name: "with groups",
			input: types.ObjectValueMust(provider.JWTGroupsFilterObjectType().AttrTypes, map[string]attr.Value{
				"groups": types.SetValueMust(types.StringType, []attr.Value{
					types.StringValue("group1"),
					types.StringValue("group2"),
				}),
				"infer_from_ppl": types.BoolValue(true),
			}),
			expected: &pb.JwtGroupsFilter{
				Groups:       []string{"group1", "group2"},
				InferFromPpl: proto.Bool(true),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var diagnostics diag.Diagnostics
			result := provider.NewModelToEnterpriseConverter(&diagnostics).JWTGroupsFilter(tc.input)
			assert.Empty(t, cmp.Diff(tc.expected, result, protocmp.Transform()))
			assert.Empty(t, diagnostics)
		})
	}
}
