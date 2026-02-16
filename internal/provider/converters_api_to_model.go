package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pomerium/sdk-go/proto/pomerium"
)

type APIToModelConverter struct {
	baseProtoConverter
	diagnostics *diag.Diagnostics
}

func NewAPIToModelConverter(diagnostics *diag.Diagnostics) *APIToModelConverter {
	return &APIToModelConverter{
		baseProtoConverter: baseProtoConverter{
			diagnostics: diagnostics,
		},
		diagnostics: diagnostics,
	}
}

func (c *APIToModelConverter) KeyPair(src *pomerium.KeyPair) KeyPairModel {
	return KeyPairModel{
		Certificate: c.StringFromBytes(src.Certificate),
		ID:          types.StringPointerValue(src.Id),
		Key:         c.StringFromBytes(src.Key),
		Name:        types.StringPointerValue(src.Name),
		NamespaceID: types.StringPointerValue(src.NamespaceId),
	}
}

func (c *APIToModelConverter) Policy(src *pomerium.Policy) PolicyModel {
	ppl, err := PolicyLanguageType{}.Parse(types.StringPointerValue(src.SourcePpl))
	if err != nil {
		c.diagnostics.AddError("error parsing ppl", err.Error())
	}
	return PolicyModel{
		Description: types.StringValue(src.GetDescription()),
		Enforced:    types.BoolValue(src.GetEnforced()),
		Explanation: types.StringValue(src.GetExplanation()),
		ID:          types.StringPointerValue(src.Id),
		Name:        types.StringPointerValue(src.Name),
		NamespaceID: types.StringPointerValue(src.NamespaceId),
		PPL:         ppl,
		Rego:        FromStringSliceToList(src.Rego),
		Remediation: types.StringValue(src.GetRemediation()),
	}
}
