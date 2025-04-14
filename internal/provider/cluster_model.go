package provider

import (
	"encoding/base64"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pomerium/enterprise-client-go/pb"
)

type ClusterModel struct {
	ParentNamespaceID        types.String `tfsdk:"parent_namespace_id"`
	NamespaceID              types.String `tfsdk:"namespace_id"`
	ID                       types.String `tfsdk:"id"`
	Name                     types.String `tfsdk:"name"`
	DatabrokerServiceURL     types.String `tfsdk:"databroker_service_url"`
	SharedSecretB64          types.String `tfsdk:"shared_secret_b64"`
	InsecureSkipVerify       types.Bool   `tfsdk:"insecure_skip_verify"`
	OverrideCertificateName  types.String `tfsdk:"override_certificate_name"`
	CertificateAuthorityB64  types.String `tfsdk:"certificate_authority_b64"`
	CertificateAuthorityFile types.String `tfsdk:"certificate_authority_file"`
}

func ConvertClusterFromPB(dst *ClusterModel, src *pb.Cluster, namespace *pb.Namespace) diag.Diagnostics {
	var diagnostics diag.Diagnostics
	if namespace != nil {
		dst.NamespaceID = types.StringValue(namespace.Id)
		dst.ParentNamespaceID = types.StringValue(namespace.ParentId)
	}
	dst.ID = types.StringValue(src.Id)
	dst.Name = types.StringValue(src.Name)
	dst.DatabrokerServiceURL = types.StringValue(src.DatabrokerServiceUrl)
	dst.SharedSecretB64 = types.StringValue(base64.StdEncoding.EncodeToString(src.SharedSecret))
	dst.InsecureSkipVerify = types.BoolPointerValue(src.InsecureSkipVerify)
	dst.OverrideCertificateName = types.StringPointerValue(src.OverrideCertificateName)
	if len(src.CertificateAuthority) > 0 {
		dst.CertificateAuthorityB64 = types.StringValue(base64.StdEncoding.EncodeToString(src.CertificateAuthority))
	}
	dst.CertificateAuthorityFile = types.StringPointerValue(src.CertificateAuthorityFile)
	return diagnostics
}

func ConvertClusterToPB(src *ClusterModel) (*pb.Cluster, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	pbCluster := &pb.Cluster{
		Id:                       src.ID.ValueString(),
		Name:                     src.Name.ValueString(),
		DatabrokerServiceUrl:     src.DatabrokerServiceURL.ValueString(),
		InsecureSkipVerify:       src.InsecureSkipVerify.ValueBoolPointer(),
		OverrideCertificateName:  src.OverrideCertificateName.ValueStringPointer(),
		CertificateAuthorityFile: src.CertificateAuthorityFile.ValueStringPointer(),
	}
	if bs, err := base64.StdEncoding.DecodeString(src.SharedSecretB64.ValueString()); err != nil {
		diagnostics.AddError("invalid shared secret", err.Error())
	} else {
		pbCluster.SharedSecret = bs
	}
	if !src.CertificateAuthorityB64.IsNull() {
		if bs, err := base64.StdEncoding.DecodeString(src.CertificateAuthorityB64.ValueString()); err != nil {
			diagnostics.AddError("invalid certificate authority", err.Error())
		} else {
			pbCluster.CertificateAuthority = bs
		}
	}
	return pbCluster, diagnostics
}
