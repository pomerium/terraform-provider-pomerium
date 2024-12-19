package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/pomerium/enterprise-client-go/pb"
)

// PolicyModel represents the shared model for policy resources and data sources
type PolicyModel struct {
	ID          types.String   `tfsdk:"id"`
	Name        types.String   `tfsdk:"name"`
	NamespaceID types.String   `tfsdk:"namespace_id"`
	PPL         PolicyLanguage `tfsdk:"ppl"`
}

func ConvertPolicyToPB(_ context.Context, src *PolicyResourceModel) (*pb.Policy, diag.Diagnostics) {
	var diagnostics diag.Diagnostics

	pbPolicy := &pb.Policy{
		Id:          src.ID.ValueString(),
		Name:        src.Name.ValueString(),
		NamespaceId: src.NamespaceID.ValueString(),
		Ppl:         string(src.PPL.PolicyJSON),
	}

	return pbPolicy, diagnostics
}

func ConvertPolicyFromPB(dst *PolicyResourceModel, src *pb.Policy) diag.Diagnostics {
	var diagnostics diag.Diagnostics

	dst.ID = types.StringValue(src.Id)
	dst.Name = types.StringValue(src.Name)
	dst.NamespaceID = types.StringValue(src.NamespaceId)
	ppl, err := PolicyLanguageType{}.Parse(types.StringValue(src.Ppl))
	if err != nil {
		diagnostics.AddError("converting PPL", err.Error())
		return diagnostics
	}
	dst.PPL = ppl

	return diagnostics
}
