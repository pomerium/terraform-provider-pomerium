package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/sdk-go/proto/pomerium"
)

type ModelToAPIConverter struct {
	baseModelConverter
	diagnostics *diag.Diagnostics
}

func NewModelToAPIConverter(diagnostics *diag.Diagnostics) *ModelToAPIConverter {
	return &ModelToAPIConverter{
		baseModelConverter: baseModelConverter{
			diagnostics: diagnostics,
		},
		diagnostics: diagnostics,
	}
}

func (c *ModelToAPIConverter) Policy(src PolicyModel) *pomerium.Policy {
	return &pomerium.Policy{
		AllowedDomains:   nil,
		AllowedIdpClaims: nil,
		AllowedUsers:     nil,
		AssignedRoutes:   nil,
		CreatedAt:        nil,
		Description:      proto.String(src.Description.ValueString()),
		Enforced:         proto.Bool(src.Enforced.ValueBool()),
		EnforcedRoutes:   nil,
		Explanation:      proto.String(src.Explanation.ValueString()),
		Id:               c.NullableString(src.ID),
		ModifiedAt:       nil,
		Name:             c.NullableString(src.Name),
		NamespaceId:      c.NullableString(src.NamespaceID),
		NamespaceName:    nil,
		OriginatorId:     proto.String(OriginatorID),
		Rego:             c.StringSliceFromList(path.Root("rego"), src.Rego),
		Remediation:      proto.String(src.Remediation.ValueString()),
		SourcePpl:        zeroToNil(string(src.PPL.PolicyJSON)),
	}
}
