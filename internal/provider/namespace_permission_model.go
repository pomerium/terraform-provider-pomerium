package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pomerium/enterprise-client-go/pb"
)

type NamespacePermissionModel struct {
	ID          types.String `tfsdk:"id"`
	NamespaceID types.String `tfsdk:"namespace_id"`
	Role        types.String `tfsdk:"role"`
	SubjectID   types.String `tfsdk:"subject_id"`
	SubjectType types.String `tfsdk:"subject_type"`
}

func ConvertNamespacePermissionFromPB(
	dst *NamespacePermissionModel,
	src *pb.NamespacePermission,
) diag.Diagnostics {
	var diagnostics diag.Diagnostics

	dst.ID = types.StringValue(src.Id)
	dst.NamespaceID = types.StringValue(src.NamespaceId)
	dst.Role = types.StringValue(src.Role)
	dst.SubjectID = types.StringValue(src.SubjectId)
	dst.SubjectType = types.StringValue(src.SubjectType)

	return diagnostics
}

func ConvertNamespacePermissionToPB(
	src *NamespacePermissionModel,
) (*pb.NamespacePermission, diag.Diagnostics) {
	var diagnostics diag.Diagnostics

	pbNamespacePermission := &pb.NamespacePermission{
		OriginatorId: OriginatorID,
		Id:           src.ID.ValueString(),
		NamespaceId:  src.NamespaceID.ValueString(),
		Role:         src.Role.ValueString(),
		SubjectId:    src.SubjectID.ValueString(),
		SubjectType:  src.SubjectType.ValueString(),
	}

	return pbNamespacePermission, diagnostics
}
