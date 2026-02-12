package provider_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/pomerium/enterprise-client-go/pb"
	"github.com/pomerium/enterprise-terraform-provider/internal/provider"
)

func TestModelToEnterpriseConverter(t *testing.T) {
	t.Parallel()

	t.Run("policy", func(t *testing.T) {
		t.Parallel()

		expected := &pb.Policy{
			Description:  "DESCRIPTION",
			Enforced:     true,
			Explanation:  "EXPLANATION",
			Id:           "ID",
			Name:         "NAME",
			NamespaceId:  "NAMESPACE_ID",
			OriginatorId: "terraform",
			Rego:         []string{"REGO"},
			Remediation:  "REMEDIATION",
		}
		var diagnostics diag.Diagnostics
		actual := provider.NewModelToEnterpriseConverter(&diagnostics).Policy(provider.PolicyModel{
			Description: types.StringValue("DESCRIPTION"),
			Enforced:    types.BoolValue(true),
			Explanation: types.StringValue("EXPLANATION"),
			ID:          types.StringValue("ID"),
			Name:        types.StringValue("NAME"),
			NamespaceID: types.StringValue("NAMESPACE_ID"),
			PPL:         provider.PolicyLanguage{},
			Rego:        types.ListValueMust(types.StringType, []attr.Value{types.StringValue("REGO")}),
			Remediation: types.StringValue("REMEDIATION"),
		})
		if !assert.Equal(t, 0, diagnostics.ErrorsCount()) {
			t.Log(diagnostics.Errors())
		}
		if diff := cmp.Diff(expected, actual, protocmp.Transform()); diff != "" {
			t.Errorf("unexpected difference: %s", diff)
		}
	})
}
