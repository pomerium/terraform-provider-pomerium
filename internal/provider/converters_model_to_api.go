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
		AllowedDomains:   nil, // not supported
		AllowedIdpClaims: nil, // not supported
		AllowedUsers:     nil, // not supported
		AssignedRoutes:   nil, // not supported
		CreatedAt:        nil, // not supported
		Description:      proto.String(src.Description.ValueString()),
		Enforced:         proto.Bool(src.Enforced.ValueBool()),
		EnforcedRoutes:   nil, // not supported
		Explanation:      proto.String(src.Explanation.ValueString()),
		Id:               c.NullableString(src.ID),
		ModifiedAt:       nil, // not supported
		Name:             proto.String(src.Name.ValueString()),
		NamespaceId:      c.NullableString(src.NamespaceID),
		NamespaceName:    nil, // not supported
		OriginatorId:     proto.String(OriginatorID),
		Rego:             c.StringSliceFromList(path.Root("rego"), src.Rego),
		Remediation:      proto.String(src.Remediation.ValueString()),
		SourcePpl:        proto.String(string(src.PPL.PolicyJSON)),
	}
}
