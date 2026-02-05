package provider

import (
	"encoding/base64"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pomerium/enterprise-client-go/pb"
)

type modelToConsoleConverter struct {
	diagnostics diag.Diagnostics
}

func newModelToConsoleConverter() *modelToConsoleConverter {
	return &modelToConsoleConverter{
		diagnostics: nil,
	}
}

func (c *modelToConsoleConverter) BytesFromBase64String(src types.String) []byte {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}
	dst, err := base64.StdEncoding.DecodeString(src.String())
	if err != nil {
		c.diagnostics.AddError("invalid base64 string", err.Error())
	}
	return dst
}

func (c *modelToConsoleConverter) Cluster(src *ClusterModel) *pb.Cluster {
	if src == nil {
		return nil
	}
	return &pb.Cluster{
		CertificateAuthority:     c.BytesFromBase64String(src.CertificateAuthorityB64),
		CertificateAuthorityFile: src.CertificateAuthorityFile.ValueStringPointer(),
		CreatedAt:                nil,
		DatabrokerServiceUrl:     src.DatabrokerServiceURL.String(),
		DeletedAt:                nil,
		Id:                       src.ID.String(),
		InsecureSkipVerify:       src.InsecureSkipVerify.ValueBoolPointer(),
		ModifiedAt:               nil,
		Name:                     src.Name.String(),
		OriginatorId:             OriginatorID,
		OverrideCertificateName:  src.OverrideCertificateName.ValueStringPointer(),
		SharedSecret:             c.BytesFromBase64String(src.SharedSecretB64),
	}
}
