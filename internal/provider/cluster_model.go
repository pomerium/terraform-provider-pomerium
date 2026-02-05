package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/types"
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
