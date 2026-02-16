package provider_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/pomerium/enterprise-terraform-provider/internal/provider"
	"github.com/pomerium/sdk-go/proto/pomerium"
)

func TestAPIToModel(t *testing.T) {
	t.Parallel()
	t.Run("KeyPair", func(t *testing.T) {
		t.Parallel()

		t.Run("empty", func(t *testing.T) {
			t.Parallel()

			var diagnostics diag.Diagnostics
			result := provider.NewAPIToModelConverter(&diagnostics).KeyPair(&pomerium.KeyPair{})
			assert.Equal(t, provider.KeyPairModel{
				Certificate: types.StringNull(),
				ID:          types.StringNull(),
				Key:         types.StringNull(),
				Name:        types.StringNull(),
				NamespaceID: types.StringNull(),
			}, result)
			assert.Empty(t, diagnostics)
		})
		t.Run("properties", func(t *testing.T) {
			t.Parallel()

			var diagnostics diag.Diagnostics
			result := provider.NewAPIToModelConverter(&diagnostics).KeyPair(&pomerium.KeyPair{
				Certificate: []byte("CERTIFICATE"),
				Id:          proto.String("ID"),
				Key:         []byte("KEY"),
				Name:        proto.String("NAME"),
				NamespaceId: proto.String("NAMESPACE_ID"),
			})
			assert.Equal(t, provider.KeyPairModel{
				Certificate: types.StringValue("CERTIFICATE"),
				ID:          types.StringValue("ID"),
				Key:         types.StringValue("KEY"),
				Name:        types.StringValue("NAME"),
				NamespaceID: types.StringValue("NAMESPACE_ID"),
			}, result)
			assert.Empty(t, diagnostics)
		})
	})
	t.Run("Policy", func(t *testing.T) {
		t.Parallel()

		t.Run("empty", func(t *testing.T) {
			var diagnostics diag.Diagnostics
			result := provider.NewAPIToModelConverter(&diagnostics).Policy(&pomerium.Policy{})
			assert.Equal(t, provider.PolicyModel{
				Description: types.StringValue(""),
				Enforced:    types.BoolValue(false),
				Explanation: types.StringValue(""),
				ID:          types.StringNull(),
				Name:        types.StringNull(),
				NamespaceID: types.StringNull(),
				PPL:         provider.PolicyLanguage{},
				Rego:        types.ListNull(types.StringType),
				Remediation: types.StringValue(""),
			}, result)
			assert.Empty(t, diagnostics)
		})
		t.Run("properties", func(t *testing.T) {
			t.Parallel()

			ppl, _ := provider.PolicyLanguageType{}.Parse(types.StringValue(`[{
			  "allow": {
				  "and": [
					  {"accept":true}
					]
				}
			}]`))
			var diagnostics diag.Diagnostics
			result := provider.NewModelToAPIConverter(&diagnostics).Policy(provider.PolicyModel{
				Description: types.StringValue("DESCRIPTION"),
				Enforced:    types.BoolValue(true),
				Explanation: types.StringValue("EXPLANATION"),
				ID:          types.StringValue("ID"),
				Name:        types.StringValue("NAME"),
				NamespaceID: types.StringValue("NAMESPACE_ID"),
				PPL:         ppl,
				Rego: types.ListValueMust(types.StringType, []attr.Value{
					types.StringValue("REGO1"), types.StringValue("REGO2"), types.StringValue("REGO3"),
				}),
				Remediation: types.StringValue("REMEDIATION"),
			})
			assert.Empty(t, cmp.Diff(&pomerium.Policy{
				Description:  proto.String("DESCRIPTION"),
				Enforced:     proto.Bool(true),
				Explanation:  proto.String("EXPLANATION"),
				Id:           proto.String("ID"),
				Name:         proto.String("NAME"),
				NamespaceId:  proto.String("NAMESPACE_ID"),
				OriginatorId: proto.String(provider.OriginatorID),
				Rego:         []string{"REGO1", "REGO2", "REGO3"},
				Remediation:  proto.String("REMEDIATION"),
				SourcePpl:    proto.String(`[{"allow":{"and":[{"accept":true}]}}]`),
			}, result, protocmp.Transform()))
			assert.Empty(t, diagnostics)
		})
	})
}
