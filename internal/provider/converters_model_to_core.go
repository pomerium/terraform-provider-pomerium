package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"google.golang.org/protobuf/types/known/structpb"
)

type ModelToCoreConverter struct {
	diagnostics *diag.Diagnostics
}

func NewModelToCoreConverter(diagnostics *diag.Diagnostics) *ModelToCoreConverter {
	return &ModelToCoreConverter{
		diagnostics: diagnostics,
	}
}

func (c *ModelToCoreConverter) Cluster(src ClusterModel) *structpb.Struct {
	return &structpb.Struct{
		Fields: map[string]*structpb.Value{
			"certificate_authority_b64":  c.StructString(src.CertificateAuthorityB64),
			"certificate_authority_file": c.StructString(src.CertificateAuthorityFile),
			"databroker_service_url":     c.StructString(src.DatabrokerServiceURL),
			"id":                         c.StructString(src.ID),
			"insecure_skip_verify":       c.StructBool(src.InsecureSkipVerify),
			"name":                       c.StructString(src.Name),
			"namespace_id":               c.StructString(src.NamespaceID),
			"override_certificate_name":  c.StructString(src.OverrideCertificateName),
			"parent_namespace_id":        c.StructString(src.ParentNamespaceID),
			"shared_secret_b64":          c.StructString(src.SharedSecretB64),
		},
	}
}

func (c *ModelToCoreConverter) Namespace(src NamespaceModel) *structpb.Struct {
	return &structpb.Struct{
		Fields: map[string]*structpb.Value{
			"cluster_id": c.StructString(src.ClusterID),
			"id":         c.StructString(src.ID),
			"name":       c.StructString(src.Name),
			"parent_id":  c.StructString(src.ParentID),
		},
	}
}

func (c *ModelToCoreConverter) StructBool(src types.Bool) *structpb.Value {
	if src.IsNull() || src.IsUnknown() {
		return structpb.NewNullValue()
	}
	return structpb.NewBoolValue(src.ValueBool())
}

func (c *ModelToCoreConverter) StructString(src types.String) *structpb.Value {
	if src.IsNull() || src.IsUnknown() {
		return structpb.NewNullValue()
	}
	return structpb.NewStringValue(src.ValueString())
}
