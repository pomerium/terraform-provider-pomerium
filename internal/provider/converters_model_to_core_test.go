package provider_test

import (
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/enterprise-terraform-provider/internal/provider"
)

func TestModelToCoreConverter(t *testing.T) {
	t.Parallel()

	t.Run("StructBool", func(t *testing.T) {
		t.Parallel()

		t.Run("null", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewModelToCoreConverter(&diagnostics).StructBool(types.BoolNull())
			assert.Equal(t, structpb.NewNullValue(), result)
			assert.Empty(t, diagnostics)
		})
		t.Run("unknown", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewModelToCoreConverter(&diagnostics).StructBool(types.BoolUnknown())
			assert.Equal(t, structpb.NewNullValue(), result)
			assert.Empty(t, diagnostics)
		})
		t.Run("valid", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewModelToCoreConverter(&diagnostics).StructBool(types.BoolValue(true))
			assert.Equal(t, structpb.NewBoolValue(true), result)
			assert.Empty(t, diagnostics)
		})
	})
	t.Run("StructString", func(t *testing.T) {
		t.Parallel()

		t.Run("null", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewModelToCoreConverter(&diagnostics).StructString(types.StringNull())
			assert.Equal(t, structpb.NewNullValue(), result)
			assert.Empty(t, diagnostics)
		})
		t.Run("unknown", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewModelToCoreConverter(&diagnostics).StructString(types.StringUnknown())
			assert.Equal(t, structpb.NewNullValue(), result)
			assert.Empty(t, diagnostics)
		})
		t.Run("valid", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewModelToCoreConverter(&diagnostics).StructString(types.StringValue("Example"))
			assert.Equal(t, structpb.NewStringValue("Example"), result)
			assert.Empty(t, diagnostics)
		})
	})
	t.Run("StructDuration", func(t *testing.T) {
		t.Parallel()

		t.Run("null", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewModelToCoreConverter(&diagnostics).StructDuration(timetypes.NewGoDurationNull())
			assert.Equal(t, structpb.NewNullValue(), result)
			assert.Empty(t, diagnostics)
		})
		t.Run("unknown", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewModelToCoreConverter(&diagnostics).StructDuration(timetypes.NewGoDurationUnknown())
			assert.Equal(t, structpb.NewNullValue(), result)
			assert.Empty(t, diagnostics)
		})
		t.Run("valid", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewModelToCoreConverter(&diagnostics).StructDuration(timetypes.NewGoDurationValue(3 * time.Second))
			assert.Equal(t, structpb.NewStringValue("3s"), result)
			assert.Empty(t, diagnostics)
		})
	})
	t.Run("StructMap", func(t *testing.T) {
		t.Parallel()

		t.Run("null", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewModelToCoreConverter(&diagnostics).StructMap(
				path.Root("example"),
				types.MapNull(types.StringType),
			)
			assert.Equal(t, structpb.NewNullValue(), result)
			assert.Empty(t, diagnostics)
		})
		t.Run("unknown", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewModelToCoreConverter(&diagnostics).StructMap(
				path.Root("example"),
				types.MapUnknown(types.StringType),
			)
			assert.Equal(t, structpb.NewNullValue(), result)
			assert.Empty(t, diagnostics)
		})
		t.Run("valid", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewModelToCoreConverter(&diagnostics).StructMap(
				path.Root("example"),
				types.MapValueMust(types.StringType, map[string]attr.Value{
					"a": types.StringValue("1"),
					"b": types.StringValue("2"),
					"c": types.StringValue("3"),
				}),
			)
			assert.Equal(t, structpb.NewStructValue(&structpb.Struct{
				Fields: map[string]*structpb.Value{
					"a": structpb.NewStringValue("1"),
					"b": structpb.NewStringValue("2"),
					"c": structpb.NewStringValue("3"),
				},
			}), result)
			assert.Empty(t, diagnostics)
		})
	})
	t.Run("Cluster", func(t *testing.T) {
		t.Parallel()

		t.Run("empty", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewModelToCoreConverter(&diagnostics).Cluster(provider.ClusterModel{})
			assert.Equal(t, &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"certificate_authority_b64":  structpb.NewNullValue(),
					"certificate_authority_file": structpb.NewNullValue(),
					"databroker_service_url":     structpb.NewNullValue(),
					"id":                         structpb.NewNullValue(),
					"insecure_skip_verify":       structpb.NewNullValue(),
					"name":                       structpb.NewNullValue(),
					"namespace_id":               structpb.NewNullValue(),
					"override_certificate_name":  structpb.NewNullValue(),
					"parent_namespace_id":        structpb.NewNullValue(),
					"shared_secret_b64":          structpb.NewNullValue(),
				},
			}, result)
			assert.Empty(t, diagnostics)
		})
		t.Run("valid", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewModelToCoreConverter(&diagnostics).Cluster(provider.ClusterModel{
				CertificateAuthorityB64:  types.StringValue("CertificateAuthorityB64"),
				CertificateAuthorityFile: types.StringValue("CertificateAuthorityFile"),
				DatabrokerServiceURL:     types.StringValue("DatabrokerServiceURL"),
				ID:                       types.StringValue("ID"),
				InsecureSkipVerify:       types.BoolValue(true),
				Name:                     types.StringValue("Name"),
				NamespaceID:              types.StringValue("NamespaceID"),
				OverrideCertificateName:  types.StringValue("OverrideCertificateName"),
				ParentNamespaceID:        types.StringValue("ParentNamespaceID"),
				SharedSecretB64:          types.StringValue("SharedSecretB64"),
			})
			assert.Equal(t, &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"certificate_authority_b64":  structpb.NewStringValue("CertificateAuthorityB64"),
					"certificate_authority_file": structpb.NewStringValue("CertificateAuthorityFile"),
					"databroker_service_url":     structpb.NewStringValue("DatabrokerServiceURL"),
					"id":                         structpb.NewStringValue("ID"),
					"insecure_skip_verify":       structpb.NewBoolValue(true),
					"name":                       structpb.NewStringValue("Name"),
					"namespace_id":               structpb.NewStringValue("NamespaceID"),
					"override_certificate_name":  structpb.NewStringValue("OverrideCertificateName"),
					"parent_namespace_id":        structpb.NewStringValue("ParentNamespaceID"),
					"shared_secret_b64":          structpb.NewStringValue("SharedSecretB64"),
				},
			}, result)
			assert.Empty(t, diagnostics)
		})
	})
	t.Run("ExternalDataSource", func(t *testing.T) {
		t.Parallel()

		t.Run("empty", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewModelToCoreConverter(&diagnostics).ExternalDataSource(provider.ExternalDataSourceModel{})
			assert.Equal(t, &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"allow_insecure_tls": structpb.NewNullValue(),
					"client_tls_key_id":  structpb.NewNullValue(),
					"cluster_id":         structpb.NewNullValue(),
					"foreign_key":        structpb.NewNullValue(),
					"headers":            structpb.NewNullValue(),
					"id":                 structpb.NewNullValue(),
					"polling_max_delay":  structpb.NewNullValue(),
					"polling_min_delay":  structpb.NewNullValue(),
					"record_type":        structpb.NewNullValue(),
					"url":                structpb.NewNullValue(),
				},
			}, result)
			assert.Empty(t, diagnostics)
		})
		t.Run("valid", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewModelToCoreConverter(&diagnostics).ExternalDataSource(provider.ExternalDataSourceModel{
				AllowInsecureTLS: types.BoolValue(true),
				ClientTLSKeyID:   types.StringValue("ClientTLSKeyID"),
				ClusterID:        types.StringValue("ClusterID"),
				ForeignKey:       types.StringValue("ForeignKey"),
				Headers:          types.MapValueMust(types.StringType, map[string]attr.Value{"x": types.StringValue("y")}),
				ID:               types.StringValue("ID"),
				PollingMaxDelay:  timetypes.NewGoDurationValue(3 * time.Second),
				PollingMinDelay:  timetypes.NewGoDurationValue(2 * time.Second),
				RecordType:       types.StringValue("RecordType"),
				URL:              types.StringValue("URL"),
			})
			assert.Equal(t, &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"allow_insecure_tls": structpb.NewBoolValue(true),
					"client_tls_key_id":  structpb.NewStringValue("ClientTLSKeyID"),
					"cluster_id":         structpb.NewStringValue("ClusterID"),
					"foreign_key":        structpb.NewStringValue("ForeignKey"),
					"headers": structpb.NewStructValue(&structpb.Struct{
						Fields: map[string]*structpb.Value{
							"x": structpb.NewStringValue("y"),
						},
					}),
					"id":                structpb.NewStringValue("ID"),
					"polling_max_delay": structpb.NewStringValue("3s"),
					"polling_min_delay": structpb.NewStringValue("2s"),
					"record_type":       structpb.NewStringValue("RecordType"),
					"url":               structpb.NewStringValue("URL"),
				},
			}, result)
			assert.Empty(t, diagnostics)
		})
	})
	t.Run("Namespace", func(t *testing.T) {
		t.Parallel()

		t.Run("empty", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewModelToCoreConverter(&diagnostics).Namespace(provider.NamespaceModel{})
			assert.Equal(t, &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"cluster_id": structpb.NewNullValue(),
					"id":         structpb.NewNullValue(),
					"name":       structpb.NewNullValue(),
					"parent_id":  structpb.NewNullValue(),
				},
			}, result)
			assert.Empty(t, diagnostics)
		})
		t.Run("valid", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewModelToCoreConverter(&diagnostics).Namespace(provider.NamespaceModel{
				ClusterID: types.StringValue("ClusterID"),
				ID:        types.StringValue("ID"),
				Name:      types.StringValue("Name"),
				ParentID:  types.StringValue("ParentID"),
			})
			assert.Equal(t, &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"cluster_id": structpb.NewStringValue("ClusterID"),
					"id":         structpb.NewStringValue("ID"),
					"name":       structpb.NewStringValue("Name"),
					"parent_id":  structpb.NewStringValue("ParentID"),
				},
			}, result)
			assert.Empty(t, diagnostics)
		})
	})
	t.Run("NamespacePermission", func(t *testing.T) {
		t.Parallel()

		t.Run("empty", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewModelToCoreConverter(&diagnostics).NamespacePermission(provider.NamespacePermissionModel{})
			assert.Equal(t, &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"id":           structpb.NewNullValue(),
					"namespace_id": structpb.NewNullValue(),
					"role":         structpb.NewNullValue(),
					"subject_id":   structpb.NewNullValue(),
					"subject_type": structpb.NewNullValue(),
				},
			}, result)
			assert.Empty(t, diagnostics)
		})
		t.Run("valid", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewModelToCoreConverter(&diagnostics).NamespacePermission(provider.NamespacePermissionModel{
				ID:          types.StringValue("ID"),
				NamespaceID: types.StringValue("NamespaceID"),
				Role:        types.StringValue("Role"),
				SubjectID:   types.StringValue("SubjectID"),
				SubjectType: types.StringValue("SubjectType"),
			})
			assert.Equal(t, &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"id":           structpb.NewStringValue("ID"),
					"namespace_id": structpb.NewStringValue("NamespaceID"),
					"role":         structpb.NewStringValue("Role"),
					"subject_id":   structpb.NewStringValue("SubjectID"),
					"subject_type": structpb.NewStringValue("SubjectType"),
				},
			}, result)
			assert.Empty(t, diagnostics)
		})
	})
}
