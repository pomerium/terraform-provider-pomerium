package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ServiceAccountModel represents the shared model for service account resources and data sources
type ServiceAccountModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	NamespaceID types.String `tfsdk:"namespace_id"`
	Description types.String `tfsdk:"description"`
	UserID      types.String `tfsdk:"user_id"`
	ExpiresAt   types.String `tfsdk:"expires_at"`
}

// NamespaceModel represents the shared model for namespace resources and data sources
type NamespaceModel struct {
	ID       types.String `tfsdk:"id"`
	Name     types.String `tfsdk:"name"`
	ParentID types.String `tfsdk:"parent_id"`
}

// RouteModel represents the shared model for route resources and data sources
type RouteModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	From        types.String `tfsdk:"from"`
	To          types.List   `tfsdk:"to"`
	NamespaceID types.String `tfsdk:"namespace_id"`
	Policies    types.List   `tfsdk:"policies"`
}

// PolicyModel represents the shared model for policy resources and data sources
type PolicyModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	NamespaceID types.String `tfsdk:"namespace_id"`
	PPL         types.String `tfsdk:"ppl"`
}
