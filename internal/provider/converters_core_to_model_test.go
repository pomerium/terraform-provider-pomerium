package provider_test

import (
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/enterprise-terraform-provider/internal/provider"
)

func TestCoreToModelConverter(t *testing.T) {
	t.Parallel()

	t.Run("BoolFromStructField", func(t *testing.T) {
		t.Parallel()

		t.Run("nil src", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewCoreToModelConverter(&diagnostics).BoolFromStructField(nil, "example")
			assert.Equal(t, types.BoolNull(), result)
			assert.Empty(t, diagnostics)
		})
		t.Run("missing", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewCoreToModelConverter(&diagnostics).BoolFromStructField(&structpb.Struct{
				Fields: map[string]*structpb.Value{},
			}, "example")
			assert.Equal(t, types.BoolNull(), result)
			assert.Empty(t, diagnostics)
		})
		t.Run("wrong type", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewCoreToModelConverter(&diagnostics).BoolFromStructField(&structpb.Struct{
				Fields: map[string]*structpb.Value{
					"example": structpb.NewStringValue("STRING"),
				},
			}, "example")
			assert.Equal(t, types.BoolNull(), result)
			assert.NotEmpty(t, diagnostics.Errors())
		})
		t.Run("valid", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewCoreToModelConverter(&diagnostics).BoolFromStructField(&structpb.Struct{
				Fields: map[string]*structpb.Value{
					"example": structpb.NewBoolValue(true),
				},
			}, "example")
			assert.Equal(t, types.BoolValue(true), result)
			assert.Empty(t, diagnostics)
		})
	})
	t.Run("Cluster", func(t *testing.T) {
		t.Parallel()
		t.Run("empty", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewCoreToModelConverter(&diagnostics).Cluster(&structpb.Struct{})
			assert.Equal(t, provider.ClusterModel{}, result)
			assert.Empty(t, diagnostics)
		})
		t.Run("valid", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewCoreToModelConverter(&diagnostics).Cluster(&structpb.Struct{
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
			})
			assert.Equal(t, provider.ClusterModel{
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
			}, result)
			assert.Empty(t, diagnostics)
		})
	})
	t.Run("DurationFromStructField", func(t *testing.T) {
		t.Parallel()
		t.Run("nil src", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewCoreToModelConverter(&diagnostics).DurationFromStructField(nil, "example")
			assert.Equal(t, timetypes.NewGoDurationNull(), result)
			assert.Empty(t, diagnostics)
		})
		t.Run("missing", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewCoreToModelConverter(&diagnostics).DurationFromStructField(&structpb.Struct{
				Fields: map[string]*structpb.Value{},
			}, "example")
			assert.Equal(t, timetypes.NewGoDurationNull(), result)
			assert.Empty(t, diagnostics)
		})
		t.Run("wrong type", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewCoreToModelConverter(&diagnostics).DurationFromStructField(&structpb.Struct{
				Fields: map[string]*structpb.Value{
					"example": structpb.NewBoolValue(true),
				},
			}, "example")
			assert.Equal(t, timetypes.NewGoDurationNull(), result)
			assert.NotEmpty(t, diagnostics.Errors())
		})
		t.Run("invalid", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewCoreToModelConverter(&diagnostics).DurationFromStructField(&structpb.Struct{
				Fields: map[string]*structpb.Value{
					"example": structpb.NewStringValue("544z"),
				},
			}, "example")
			assert.Equal(t, timetypes.NewGoDurationUnknown(), result)
			assert.NotEmpty(t, diagnostics.Errors())
		})
		t.Run("valid", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewCoreToModelConverter(&diagnostics).DurationFromStructField(&structpb.Struct{
				Fields: map[string]*structpb.Value{
					"example": structpb.NewStringValue("3s"),
				},
			}, "example")
			assert.Equal(t, timetypes.NewGoDurationValue(3*time.Second), result)
			assert.Empty(t, diagnostics)
		})
	})
	t.Run("ExternalDataSource", func(t *testing.T) {
		t.Parallel()
		t.Run("empty", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewCoreToModelConverter(&diagnostics).ExternalDataSource(&structpb.Struct{})
			assert.Equal(t, provider.ExternalDataSourceDataSourceModel{
				Headers: types.MapNull(types.StringType),
			}, result)
			assert.Empty(t, diagnostics)
		})
		t.Run("valid", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewCoreToModelConverter(&diagnostics).ExternalDataSource(&structpb.Struct{
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
			})
			assert.Equal(t, provider.ExternalDataSourceDataSourceModel{
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
			}, result)
			assert.Empty(t, diagnostics)
		})
	})
	t.Run("Namespace", func(t *testing.T) {
		t.Parallel()
		t.Run("empty", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewCoreToModelConverter(&diagnostics).Namespace(&structpb.Struct{})
			assert.Equal(t, provider.NamespaceModel{}, result)
			assert.Empty(t, diagnostics)
		})
		t.Run("valid", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewCoreToModelConverter(&diagnostics).Namespace(&structpb.Struct{
				Fields: map[string]*structpb.Value{
					"cluster_id": structpb.NewStringValue("ClusterID"),
					"id":         structpb.NewStringValue("ID"),
					"name":       structpb.NewStringValue("Name"),
					"parent_id":  structpb.NewStringValue("ParentID"),
				},
			})
			assert.Equal(t, provider.NamespaceModel{
				ClusterID: types.StringValue("ClusterID"),
				ID:        types.StringValue("ID"),
				Name:      types.StringValue("Name"),
				ParentID:  types.StringValue("ParentID"),
			}, result)
			assert.Empty(t, diagnostics)
		})
	})
	t.Run("NamespacePermission", func(t *testing.T) {
		t.Parallel()
		t.Run("empty", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewCoreToModelConverter(&diagnostics).NamespacePermission(&structpb.Struct{})
			assert.Equal(t, provider.NamespacePermissionModel{}, result)
			assert.Empty(t, diagnostics)
		})
		t.Run("valid", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewCoreToModelConverter(&diagnostics).NamespacePermission(&structpb.Struct{
				Fields: map[string]*structpb.Value{
					"id":           structpb.NewStringValue("ID"),
					"namespace_id": structpb.NewStringValue("NamespaceID"),
					"role":         structpb.NewStringValue("Role"),
					"subject_id":   structpb.NewStringValue("SubjectID"),
					"subject_type": structpb.NewStringValue("SubjectType"),
				},
			})
			assert.Equal(t, provider.NamespacePermissionModel{
				ID:          types.StringValue("ID"),
				NamespaceID: types.StringValue("NamespaceID"),
				Role:        types.StringValue("Role"),
				SubjectID:   types.StringValue("SubjectID"),
				SubjectType: types.StringValue("SubjectType"),
			}, result)
			assert.Empty(t, diagnostics)
		})
	})
	t.Run("StringFromStructField", func(t *testing.T) {
		t.Parallel()
		t.Run("nil src", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewCoreToModelConverter(&diagnostics).StringFromStructField(nil, "example")
			assert.Equal(t, types.StringNull(), result)
			assert.Empty(t, diagnostics)
		})
		t.Run("missing", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewCoreToModelConverter(&diagnostics).StringFromStructField(&structpb.Struct{
				Fields: map[string]*structpb.Value{},
			}, "example")
			assert.Equal(t, types.StringNull(), result)
			assert.Empty(t, diagnostics)
		})
		t.Run("wrong type", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewCoreToModelConverter(&diagnostics).StringFromStructField(&structpb.Struct{
				Fields: map[string]*structpb.Value{
					"example": structpb.NewBoolValue(true),
				},
			}, "example")
			assert.Equal(t, types.StringNull(), result)
			assert.NotEmpty(t, diagnostics.Errors())
		})
		t.Run("valid", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewCoreToModelConverter(&diagnostics).StringFromStructField(&structpb.Struct{
				Fields: map[string]*structpb.Value{
					"example": structpb.NewStringValue("Example"),
				},
			}, "example")
			assert.Equal(t, types.StringValue("Example"), result)
			assert.Empty(t, diagnostics)
		})
	})
	t.Run("StringMapFromStructField", func(t *testing.T) {
		t.Parallel()
		t.Run("nil src", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewCoreToModelConverter(&diagnostics).StringMapFromStructField(nil, "example")
			assert.Equal(t, types.MapNull(types.StringType), result)
			assert.Empty(t, diagnostics)
		})
		t.Run("missing", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewCoreToModelConverter(&diagnostics).StringMapFromStructField(&structpb.Struct{
				Fields: map[string]*structpb.Value{},
			}, "example")
			assert.Equal(t, types.MapNull(types.StringType), result)
			assert.Empty(t, diagnostics)
		})
		t.Run("wrong type", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewCoreToModelConverter(&diagnostics).StringMapFromStructField(&structpb.Struct{
				Fields: map[string]*structpb.Value{
					"example": structpb.NewBoolValue(true),
				},
			}, "example")
			assert.Equal(t, types.MapNull(types.StringType), result)
			assert.NotEmpty(t, diagnostics.Errors())
		})
		t.Run("wrong value type", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewCoreToModelConverter(&diagnostics).StringMapFromStructField(&structpb.Struct{
				Fields: map[string]*structpb.Value{
					"example": structpb.NewStructValue(&structpb.Struct{
						Fields: map[string]*structpb.Value{
							"a": structpb.NewBoolValue(true),
						},
					}),
				},
			}, "example")
			assert.Equal(t, types.MapNull(types.StringType), result)
			assert.NotEmpty(t, diagnostics.Errors())
		})
		t.Run("valid", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewCoreToModelConverter(&diagnostics).StringMapFromStructField(&structpb.Struct{
				Fields: map[string]*structpb.Value{
					"example": structpb.NewStructValue(&structpb.Struct{
						Fields: map[string]*structpb.Value{
							"a": structpb.NewStringValue("1"),
							"b": structpb.NewStringValue("2"),
							"c": structpb.NewStringValue("3"),
						},
					}),
				},
			}, "example")
			assert.Equal(t, types.MapValueMust(types.StringType, map[string]attr.Value{
				"a": types.StringValue("1"),
				"b": types.StringValue("2"),
				"c": types.StringValue("3"),
			}), result)
			assert.Empty(t, diagnostics)
		})
	})
}
