package provider

import (
	"context"
	"encoding/base64"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pomerium/enterprise-client-go/pb"
)

type ClusterModel struct {
	ParentNamespaceID        types.String `tfsdk:"parent_namespace_id"`
	ID                       types.String `tfsdk:"id"`
	Name                     types.String `tfsdk:"name"`
	DatabrokerServiceURL     types.String `tfsdk:"databroker_service_url"`
	SharedSecretB64          types.String `tfsdk:"shared_secret_b64"`
	InsecureSkipVerify       types.Bool   `tfsdk:"insecure_skip_verify"`
	OverrideCertificateName  types.String `tfsdk:"override_certificate_name"`
	CertificateAuthority     types.String `tfsdk:"certificate_authority"`
	CertificateAuthorityFile types.String `tfsdk:"certificate_authority_file"`

	NamespaceID types.String `tfsdk:"namespace_id"`
}

func ConvertClusterFromPB(dst *ClusterModel, src *pb.Cluster) diag.Diagnostics {
	var diagnostics diag.Diagnostics

	dst.ID = types.StringValue(src.Id)
	dst.Name = types.StringValue(src.Name)
	dst.DatabrokerServiceURL = types.StringValue(src.DatabrokerServiceUrl)
	dst.SharedSecretB64 = types.StringValue(base64.StdEncoding.EncodeToString(src.SharedSecret))
	dst.InsecureSkipVerify = types.BoolPointerValue(src.InsecureSkipVerify)
	dst.OverrideCertificateName = types.StringPointerValue(src.OverrideCertificateName)
	if len(src.CertificateAuthority) > 0 {
		dst.CertificateAuthority = types.StringValue(string(src.CertificateAuthority))
	} else {
		dst.CertificateAuthority = types.StringNull()
	}
	dst.CertificateAuthorityFile = types.StringPointerValue(src.CertificateAuthorityFile)

	return diagnostics
}

func ConvertClusterToPB(_ context.Context, src *ClusterModel) (*pb.Cluster, diag.Diagnostics) {
	var diagnostics diag.Diagnostics

	sharedSecret, err := base64.StdEncoding.DecodeString(src.SharedSecretB64.ValueString())
	if err != nil {
		diagnostics.AddError("invalid shared secret", err.Error())
		return nil, diagnostics
	}

	var certificateAuthority []byte
	if !src.CertificateAuthority.IsNull() {
		certificateAuthority = []byte(src.CertificateAuthority.ValueString())
	}

	dst := &pb.Cluster{
		Id:                       src.ID.ValueString(),
		Name:                     src.Name.ValueString(),
		DatabrokerServiceUrl:     src.DatabrokerServiceURL.ValueString(),
		SharedSecret:             sharedSecret,
		InsecureSkipVerify:       src.InsecureSkipVerify.ValueBoolPointer(),
		OverrideCertificateName:  src.OverrideCertificateName.ValueStringPointer(),
		CertificateAuthority:     certificateAuthority,
		CertificateAuthorityFile: src.CertificateAuthority.ValueStringPointer(),
	}

	return dst, diagnostics
}
