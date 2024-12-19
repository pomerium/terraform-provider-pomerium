package provider_test

import (
	"context"
	_ "embed"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/pomerium/enterprise-terraform-provider/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/ppl-object-ok.yaml
var pplObjectOK string

func TestPolicyTypes(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		in          tftypes.Value
		expected    attr.Value
		expectedErr error
	}{
		"object-ok": {
			in:       tftypes.NewValue(tftypes.String, pplObjectOK),
			expected: provider.NewPolicyLanguageJSON(`[{"allow":{"and":[{"accept":true}]}}]`),
		},
		"null": {
			in:       tftypes.NewValue(tftypes.String, nil),
			expected: provider.NewPolicyLanguageJSON(`[]`),
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			p := provider.PolicyLanguageType{}
			got, err := p.ValueFromTerraform(context.Background(), testCase.in)
			if testCase.expectedErr != nil {
				require.EqualError(t, err, testCase.expectedErr.Error())
				return
			}
			require.NoError(t, err)
			if !assert.True(t, testCase.expected.Equal(got), got) {
				t.Logf("-: %s", testCase.expected)
				t.Logf("+: %s", got)
			}
		})
	}
}
