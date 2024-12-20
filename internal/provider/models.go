package provider

import (
	"context"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/pomerium/enterprise-client-go/pb"
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

func ConvertServiceAccountToPB(_ context.Context, src *ServiceAccountResourceModel) (*pb.PomeriumServiceAccount, diag.Diagnostics) {
	var diagnostics diag.Diagnostics

	namespaceID := src.NamespaceID.ValueString()
	pbServiceAccount := &pb.PomeriumServiceAccount{
		Id:          src.ID.ValueString(),
		UserId:      src.Name.ValueString(),
		NamespaceId: &namespaceID,
	}

	if !src.Description.IsNull() {
		desc := src.Description.ValueString()
		pbServiceAccount.Description = &desc
	}

	return pbServiceAccount, diagnostics
}

func ConvertServiceAccountFromPB(dst *ServiceAccountResourceModel, src *pb.PomeriumServiceAccount) diag.Diagnostics {
	var diagnostics diag.Diagnostics

	dst.ID = types.StringValue(src.Id)
	dst.Name = types.StringValue(src.UserId)
	if src.NamespaceId != nil {
		dst.NamespaceID = types.StringValue(*src.NamespaceId)
	} else {
		dst.NamespaceID = types.StringNull()
	}
	if src.Description != nil {
		dst.Description = types.StringValue(*src.Description)
	} else {
		dst.Description = types.StringNull()
	}
	dst.UserID = types.StringValue(src.UserId)
	if src.ExpiresAt != nil {
		dst.ExpiresAt = types.StringValue(src.ExpiresAt.AsTime().Format(time.RFC3339))
	} else {
		dst.ExpiresAt = types.StringNull()
	}

	return diagnostics
}

// NamespaceModel represents the shared model for namespace resources and data sources
type NamespaceModel struct {
	ID       types.String `tfsdk:"id"`
	Name     types.String `tfsdk:"name"`
	ParentID types.String `tfsdk:"parent_id"`
}

func ConvertNamespaceToPB(_ context.Context, src *NamespaceResourceModel) (*pb.Namespace, diag.Diagnostics) {
	var diagnostics diag.Diagnostics

	pbNamespace := &pb.Namespace{
		Id:   src.ID.ValueString(),
		Name: src.Name.ValueString(),
	}

	if !src.ParentID.IsNull() {
		pbNamespace.ParentId = src.ParentID.ValueString()
	}

	return pbNamespace, diagnostics
}

func ConvertNamespaceFromPB(dst *NamespaceResourceModel, src *pb.Namespace) diag.Diagnostics {
	var diagnostics diag.Diagnostics

	dst.ID = types.StringValue(src.Id)
	dst.Name = types.StringValue(src.Name)

	if src.ParentId != "" {
		dst.ParentID = types.StringValue(src.ParentId)
	} else {
		dst.ParentID = types.StringNull()
	}

	return diagnostics
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

func ConvertRouteToPB(
	ctx context.Context,
	src *RouteResourceModel,
) (*pb.Route, diag.Diagnostics) {
	pbRoute := new(pb.Route)
	var diagnostics diag.Diagnostics

	pbRoute.Id = src.ID.ValueString()
	pbRoute.Name = src.Name.ValueString()
	pbRoute.From = src.From.ValueString()
	pbRoute.NamespaceId = src.NamespaceID.ValueString()

	diags := src.To.ElementsAs(ctx, &pbRoute.To, false)
	diagnostics.Append(diags...)

	if !src.Policies.IsNull() {
		diags = src.Policies.ElementsAs(ctx, &pbRoute.PolicyIds, false)
		diagnostics.Append(diags...)
	}
	return pbRoute, diagnostics
}

func ConvertRouteFromPB(
	dst *RouteResourceModel,
	src *pb.Route,
) diag.Diagnostics {
	var diagnostics diag.Diagnostics

	dst.ID = types.StringValue(src.Id)
	dst.Name = types.StringValue(src.Name)
	dst.From = types.StringValue(src.From)
	dst.NamespaceID = types.StringValue(src.NamespaceId)

	toList := make([]attr.Value, len(src.To))
	for i, v := range src.To {
		toList[i] = types.StringValue(v)
	}
	dst.To = types.ListValueMust(types.StringType, toList)

	policiesList := make([]attr.Value, len(src.PolicyIds))
	for i, v := range src.PolicyIds {
		policiesList[i] = types.StringValue(v)
	}
	dst.Policies = types.ListValueMust(types.StringType, policiesList)

	return diagnostics
}
