package provider

import (
	"context"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/enterprise-client-go/pb"
)

const OriginatorID = "terraform"

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
	var diags diag.Diagnostics

	pbServiceAccount := &pb.PomeriumServiceAccount{
		Id:           src.ID.ValueString(),
		UserId:       src.Name.ValueString(),
		OriginatorId: proto.String(OriginatorID),
	}

	if src.NamespaceID.ValueString() != "" {
		pbServiceAccount.NamespaceId = src.NamespaceID.ValueStringPointer()
	}

	if !src.Description.IsNull() {
		desc := src.Description.ValueString()
		pbServiceAccount.Description = &desc
	}

	return pbServiceAccount, diags
}

func ConvertServiceAccountFromPB(dst *ServiceAccountModel, src *pb.PomeriumServiceAccount) diag.Diagnostics {
	var diagnostics diag.Diagnostics

	dst.ID = types.StringValue(src.Id)
	dst.Name = types.StringValue(strings.TrimSuffix(src.UserId, "@"+src.GetNamespaceId()+".pomerium"))
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
	ID        types.String `tfsdk:"id"`
	Name      types.String `tfsdk:"name"`
	ParentID  types.String `tfsdk:"parent_id"`
	ClusterID types.String `tfsdk:"cluster_id"`
}

func ConvertNamespaceToPB(_ context.Context, src *NamespaceResourceModel) (*pb.Namespace, diag.Diagnostics) {
	var diagnostics diag.Diagnostics

	pbNamespace := &pb.Namespace{
		OriginatorId: OriginatorID,
		Id:           src.ID.ValueString(),
		Name:         src.Name.ValueString(),
	}

	if !src.ClusterID.IsNull() && !src.ClusterID.IsUnknown() {
		pbNamespace.ClusterId = src.ClusterID.ValueStringPointer()
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

	dst.ClusterID = types.StringPointerValue(src.ClusterId)

	return diagnostics
}
