package provider_test

import (
	_ "embed"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/pomerium/enterprise-terraform-provider/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/ppl-object-ok.yaml
var pplObjectOK string

func TestPolicyTypes(t *testing.T) {
	t.Parallel()

	jsonPPL := func(json string) provider.PolicyLanguage {
		ppl, err := provider.PolicyLanguageType{}.Parse(basetypes.NewStringValue(json))
		require.NoError(t, err)
		return ppl
	}

	testCases := map[string]struct {
		in          tftypes.Value
		expected    provider.PolicyLanguage
		expectedErr error
	}{
		"object-ok": {
			in:       tftypes.NewValue(tftypes.String, pplObjectOK),
			expected: jsonPPL(`[{"allow":{"and":[{"accept":true}]}}]`),
		},
		"null": {
			in:       tftypes.NewValue(tftypes.String, nil),
			expected: provider.PolicyLanguage{StringValue: basetypes.NewStringNull()},
		},
		"unknown": {
			in:       tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
			expected: provider.PolicyLanguage{StringValue: basetypes.NewStringUnknown()},
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			gotValue, err := provider.PolicyLanguageType{}.ValueFromTerraform(t.Context(), testCase.in)
			if testCase.expectedErr != nil {
				require.EqualError(t, err, testCase.expectedErr.Error())
				return
			}
			got, ok := gotValue.(provider.PolicyLanguage)
			require.True(t, ok)
			require.NoError(t, err)
			equals, diag := testCase.expected.StringSemanticEquals(t.Context(), got)
			assert.False(t, diag.HasError())
			assert.True(t, equals)
		})
	}
}
