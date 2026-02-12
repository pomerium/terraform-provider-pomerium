package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	enterprise "github.com/pomerium/enterprise-client-go/pb"
)

type EnterpriseToModelConverter struct {
	diagnostics *diag.Diagnostics
}

func NewEnterpriseToModelConverter(diagnostics *diag.Diagnostics) *EnterpriseToModelConverter {
	return &EnterpriseToModelConverter{
		diagnostics: diagnostics,
	}
}

func (c *EnterpriseToModelConverter) Policy(src *enterprise.Policy) PolicyModel {
	ppl, err := PolicyLanguageType{}.Parse(types.StringValue(src.Ppl))
	if err != nil {
		c.diagnostics.AddError("error parsing ppl", err.Error())
	}

	return PolicyModel{
		Description: types.StringValue(src.Description),
		Enforced:    types.BoolValue(src.Enforced),
		Explanation: types.StringValue(src.Explanation),
		ID:          types.StringValue(src.Id),
		Name:        types.StringValue(src.Name),
		NamespaceID: types.StringValue(src.NamespaceId),
		PPL:         ppl,
		Rego:        FromStringSliceToList(src.Rego),
		Remediation: types.StringValue(src.Remediation),
	}
}
