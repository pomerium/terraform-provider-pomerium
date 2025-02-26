package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pomerium/enterprise-client-go/pb"
)

type KeyPairModel struct {
	Certificate types.String `tfsdk:"certificate"`
	ID          types.String `tfsdk:"id"`
	Key         types.String `tfsdk:"key"`
	Name        types.String `tfsdk:"name"`
	NamespaceID types.String `tfsdk:"namespace_id"`
}

func ConvertKeyPairToCreatePB(src *KeyPairModel) *pb.CreateKeyPairRequest {
	dst := &pb.CreateKeyPairRequest{
		OriginatorId: originatorID,
		NamespaceId:  src.NamespaceID.ValueString(),
		Name:         src.Name.ValueString(),
		Format:       pb.Format_PEM,
		Certificate:  []byte(src.Certificate.ValueString()),
	}
	if !src.Key.IsNull() {
		keyData := []byte(src.Key.ValueString())
		dst.Key = keyData
	}
	return dst
}

func ConvertKeyPairToUpdatePB(src *KeyPairModel) *pb.UpdateKeyPairRequest {
	fmt := pb.Format_PEM
	dst := &pb.UpdateKeyPairRequest{
		OriginatorId: originatorID,
		Id:           src.ID.ValueString(),
		Name:         src.Name.ValueStringPointer(),
		Format:       &fmt,
		Certificate:  []byte(src.Certificate.ValueString()),
	}
	if !src.Key.IsNull() {
		keyData := []byte(src.Key.ValueString())
		dst.Key = keyData
	}
	return dst
}
