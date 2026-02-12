package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const OriginatorID = "terraform"

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

type NamespacePermissionModel struct {
	ID          types.String `tfsdk:"id"`
	NamespaceID types.String `tfsdk:"namespace_id"`
	Role        types.String `tfsdk:"role"`
	SubjectID   types.String `tfsdk:"subject_id"`
	SubjectType types.String `tfsdk:"subject_type"`
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
