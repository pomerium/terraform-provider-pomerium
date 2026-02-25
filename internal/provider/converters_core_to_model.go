package provider

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
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
		c.diagnostics.AddAttributeError(path.Root(name),
			"expected bool in struct", fmt.Sprintf("expected bool in struct but got %T", v.GetKind()))
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

func (c *CoreToModelConverter) DurationFromStructField(src *structpb.Struct, name string) timetypes.GoDuration {
	if src == nil {
		return timetypes.NewGoDurationNull()
	}
	v, ok := src.Fields[name]
	if !ok {
		return timetypes.NewGoDurationNull()
	}
	sv, ok := v.GetKind().(*structpb.Value_StringValue)
	if !ok {
		c.diagnostics.AddAttributeError(path.Root(name),
			"expected string in struct", fmt.Sprintf("expected string in struct but got %T", v.GetKind()))
		return timetypes.NewGoDurationNull()
	}

	dst, d := timetypes.NewGoDurationValueFromString(sv.StringValue)
	c.diagnostics.Append(d...)
	return dst
}

func (c *CoreToModelConverter) ExternalDataSource(src *structpb.Struct) ExternalDataSourceModel {
	return ExternalDataSourceModel{
		AllowInsecureTLS: c.BoolFromStructField(src, "allow_insecure_tls"),
		ClientTLSKeyID:   c.StringFromStructField(src, "client_tls_key_id"),
		ClusterID:        c.StringFromStructField(src, "cluster_id"),
		ForeignKey:       c.StringFromStructField(src, "foreign_key"),
		Headers:          c.StringMapFromStructField(src, "headers"),
		ID:               c.StringFromStructField(src, "id"),
		PollingMaxDelay:  c.DurationFromStructField(src, "polling_max_delay"),
		PollingMinDelay:  c.DurationFromStructField(src, "polling_min_delay"),
		RecordType:       c.StringFromStructField(src, "record_type"),
		URL:              c.StringFromStructField(src, "url"),
	}
}

func (c *CoreToModelConverter) Namespace(src *structpb.Struct) NamespaceModel {
	return NamespaceModel{
		ClusterID: c.StringFromStructField(src, "cluster_id"),
		ID:        c.StringFromStructField(src, "id"),
		Name:      c.StringFromStructField(src, "name"),
		ParentID:  c.StringFromStructField(src, "parent_id"),
	}
}

func (c *CoreToModelConverter) NamespacePermission(src *structpb.Struct) NamespacePermissionModel {
	return NamespacePermissionModel{
		ID:          c.StringFromStructField(src, "id"),
		NamespaceID: c.StringFromStructField(src, "namespace_id"),
		Role:        c.StringFromStructField(src, "role"),
		SubjectID:   c.StringFromStructField(src, "subject_id"),
		SubjectType: c.StringFromStructField(src, "subject_type"),
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
		c.diagnostics.AddAttributeError(path.Root(name),
			"expected string in struct", fmt.Sprintf("expected string in struct but got %T", v.GetKind()))
		return types.StringNull()
	}
	return types.StringValue(sv.StringValue)
}

func (c *CoreToModelConverter) StringMapFromStructField(src *structpb.Struct, name string) types.Map {
	if src == nil {
		return types.MapNull(types.StringType)
	}
	v, ok := src.Fields[name]
	if !ok {
		return types.MapNull(types.StringType)
	}
	sv, ok := v.GetKind().(*structpb.Value_StructValue)
	if !ok {
		c.diagnostics.AddAttributeError(path.Root(name),
			"expected map in struct", fmt.Sprintf("expected map in struct but got %T", v.GetKind()))
		return types.MapNull(types.StringType)
	}
	m := map[string]attr.Value{}
	for k, v := range sv.StructValue.Fields {
		vv, ok := v.GetKind().(*structpb.Value_StringValue)
		if !ok {
			c.diagnostics.AddAttributeError(path.Root(name),
				"expected string in map", fmt.Sprintf("expected string in map but got %T", v.GetKind()))
			return types.MapNull(types.StringType)
		}
		m[k] = types.StringValue(vv.StringValue)
	}
	dst, d := types.MapValue(types.StringType, m)
	c.diagnostics.Append(d...)
	return dst
}
