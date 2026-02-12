package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const OriginatorID = "terraform"

type KeyPairModel struct {
	Certificate types.String `tfsdk:"certificate"`
	ID          types.String `tfsdk:"id"`
	Key         types.String `tfsdk:"key"`
	Name        types.String `tfsdk:"name"`
	NamespaceID types.String `tfsdk:"namespace_id"`
}

type NamespaceModel struct {
	ID        types.String `tfsdk:"id"`
	Name      types.String `tfsdk:"name"`
	ParentID  types.String `tfsdk:"parent_id"`
	ClusterID types.String `tfsdk:"cluster_id"`
}

type PolicyModel struct {
	Description types.String   `tfsdk:"description"`
	Enforced    types.Bool     `tfsdk:"enforced"`
	Explanation types.String   `tfsdk:"explanation"`
	ID          types.String   `tfsdk:"id"`
	Name        types.String   `tfsdk:"name"`
	NamespaceID types.String   `tfsdk:"namespace_id"`
	PPL         PolicyLanguage `tfsdk:"ppl"`
	Rego        types.List     `tfsdk:"rego"`
	Remediation types.String   `tfsdk:"remediation"`
}

type ServiceAccountModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	NamespaceID types.String `tfsdk:"namespace_id"`
	Description types.String `tfsdk:"description"`
	UserID      types.String `tfsdk:"user_id"`
	ExpiresAt   types.String `tfsdk:"expires_at"`
}
