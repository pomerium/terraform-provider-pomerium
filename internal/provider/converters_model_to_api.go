package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

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

func (c *ModelToAPIConverter) ListPoliciesRequest(src PoliciesDataSourceModel) *pomerium.ListPoliciesRequest {
	filter := c.Filter(map[string]types.String{
		"cluster_id":   src.ClusterID,
		"namespace_id": src.NamespaceID,
		"query":        src.Query,
	})
	return &pomerium.ListPoliciesRequest{
		Filter:  filter,
		Limit:   c.NullableUint64(src.Limit),
		Offset:  c.NullableUint64(src.Offset),
		OrderBy: c.NullableString(src.OrderBy),
	}
}

func (c *ModelToAPIConverter) Filter(src map[string]types.String) *structpb.Struct {
	var dst *structpb.Struct
	for field, value := range src {
		if value.IsNull() || value.IsUnknown() {
			continue
		}
		if dst == nil {
			dst = &structpb.Struct{Fields: map[string]*structpb.Value{}}
		}
		dst.Fields[field] = structpb.NewStringValue(value.ValueString())
	}
	return dst
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
