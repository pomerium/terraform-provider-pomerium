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
	Description types.String   `tfsdk:"description"`
	NamespaceID types.String   `tfsdk:"namespace_id"`
	PPL         PolicyLanguage `tfsdk:"ppl"`
	Rego        types.List     `tfsdk:"rego"`
	Enforced    types.Bool     `tfsdk:"enforced"`
	Explanation types.String   `tfsdk:"explanation"`
	Remediation types.String   `tfsdk:"remediation"`
}

func ConvertPolicyToPB(ctx context.Context, src *PolicyResourceModel) (*pb.Policy, diag.Diagnostics) {
	var diagnostics diag.Diagnostics

	pbPolicy := &pb.Policy{
		Id:          src.ID.ValueString(),
		Name:        src.Name.ValueString(),
		Description: src.Description.ValueString(),
		NamespaceId: src.NamespaceID.ValueString(),
		Ppl:         string(src.PPL.PolicyJSON),
		Enforced:    src.Enforced.ValueBool(),
		Explanation: src.Explanation.ValueString(),
		Remediation: src.Remediation.ValueString(),
	}
	diagnostics.Append(src.Rego.ElementsAs(ctx, &pbPolicy.Rego, false)...)

	return pbPolicy, diagnostics
}

func ConvertPolicyFromPB(dst *PolicyResourceModel, src *pb.Policy) diag.Diagnostics {
	var diagnostics diag.Diagnostics

	dst.ID = types.StringValue(src.Id)
	dst.Name = types.StringValue(src.Name)
	dst.Description = types.StringValue(src.Description)
	dst.NamespaceID = types.StringValue(src.NamespaceId)
	dst.Enforced = types.BoolValue(src.Enforced)
	dst.Explanation = types.StringValue(src.Explanation)
	dst.Remediation = types.StringValue(src.Remediation)
	dst.Rego = FromStringSliceToList(src.Rego)
	ppl, err := PolicyLanguageType{}.Parse(types.StringValue(src.Ppl))
	if err != nil {
		diagnostics.AddError("converting PPL", err.Error())
		return diagnostics
	}
	dst.PPL = ppl

	return diagnostics
}
