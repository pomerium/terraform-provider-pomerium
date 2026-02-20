package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
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

func (c *ModelToCoreConverter) ExternalDataSource(src ExternalDataSourceModel) *structpb.Struct {
	return &structpb.Struct{
		Fields: map[string]*structpb.Value{
			"allow_insecure_tls": c.StructBool(src.AllowInsecureTLS),
			"client_tls_key_id":  c.StructString(src.ClientTLSKeyID),
			"cluster_id":         c.StructString(src.ClusterID),
			"foreign_key":        c.StructString(src.ForeignKey),
			"headers":            c.StructMap(path.Root("headers"), src.Headers),
			"id":                 c.StructString(src.ID),
			"polling_max_delay":  c.StructDuration(src.PollingMaxDelay),
			"polling_min_delay":  c.StructDuration(src.PollingMinDelay),
			"record_type":        c.StructString(src.RecordType),
			"url":                c.StructString(src.URL),
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

func (c *ModelToCoreConverter) StructDuration(src timetypes.GoDuration) *structpb.Value {
	if src.IsNull() || src.IsUnknown() {
		return structpb.NewNullValue()
	}
	return structpb.NewStringValue(src.ValueString())
}

func (c *ModelToCoreConverter) StructMap(p path.Path, src types.Map) *structpb.Value {
	if src.IsNull() || src.IsUnknown() {
		return structpb.NewNullValue()
	}
	dst := make(map[string]string)
	appendAttributeDiagnostics(c.diagnostics, p, src.ElementsAs(context.Background(), &dst, false)...)
	s := &structpb.Struct{Fields: make(map[string]*structpb.Value)}
	for k, v := range dst {
		s.Fields[k] = structpb.NewStringValue(v)
	}
	return structpb.NewStructValue(s)
}

func (c *ModelToCoreConverter) StructString(src types.String) *structpb.Value {
	if src.IsNull() || src.IsUnknown() {
		return structpb.NewNullValue()
	}
	return structpb.NewStringValue(src.ValueString())
}
