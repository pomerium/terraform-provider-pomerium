package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"google.golang.org/protobuf/types/known/structpb"
)

type CoreToModelConverter struct {
	diagnostics *diag.Diagnostics
}

func NewCoreToModelConverter(diagnostics *diag.Diagnostics) *CoreToModelConverter {
	return &CoreToModelConverter{
		diagnostics: diagnostics,
	}
}

func (c *CoreToModelConverter) BoolFromStructField(src *structpb.Struct, name string) types.Bool {
	if src == nil {
		return types.BoolNull()
	}
	v, ok := src.Fields[name]
	if !ok {
		return types.BoolNull()
	}
	sv, ok := v.GetKind().(*structpb.Value_BoolValue)
	if !ok {
		return types.BoolNull()
	}
	return types.BoolValue(sv.BoolValue)
}

func (c *CoreToModelConverter) Cluster(src *structpb.Struct) ClusterModel {
	return ClusterModel{
		CertificateAuthorityB64:  c.StringFromStructField(src, "certificate_authority_b64"),
		CertificateAuthorityFile: c.StringFromStructField(src, "certificate_authority_file"),
		DatabrokerServiceURL:     c.StringFromStructField(src, "databroker_service_url"),
		ID:                       c.StringFromStructField(src, "id"),
		InsecureSkipVerify:       c.BoolFromStructField(src, "insecure_skip_verify"),
		Name:                     c.StringFromStructField(src, "name"),
		NamespaceID:              c.StringFromStructField(src, "namespace_id"),
		OverrideCertificateName:  c.StringFromStructField(src, "override_certificate_name"),
		ParentNamespaceID:        c.StringFromStructField(src, "parent_namespace_id"),
		SharedSecretB64:          c.StringFromStructField(src, "shared_secret_b64"),
	}
}

func (c *CoreToModelConverter) StringFromStructField(src *structpb.Struct, name string) types.String {
	if src == nil {
		return types.StringNull()
	}
	v, ok := src.Fields[name]
	if !ok {
		return types.StringNull()
	}
	sv, ok := v.GetKind().(*structpb.Value_StringValue)
	if !ok {
		return types.StringNull()
	}
	return types.StringValue(sv.StringValue)
}
