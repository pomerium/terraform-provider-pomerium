package provider_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"

	"github.com/pomerium/enterprise-terraform-provider/internal/provider"
	"github.com/pomerium/sdk-go/pkg/zeroapi"
)

func TestZeroToModelConverter(t *testing.T) {
	t.Parallel()

	t.Run("ClusterFlavor", func(t *testing.T) {
		t.Parallel()

		t.Run("nil", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewZeroToModelConverter(&diagnostics).ClusterFlavor(nil)
			assert.Equal(t, types.StringNull(), result)
			assert.Empty(t, diagnostics)
		})
		t.Run("valid", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			flavor := zeroapi.Hosted
			result := provider.NewZeroToModelConverter(&diagnostics).ClusterFlavor(&flavor)
			assert.Equal(t, types.StringValue("hosted"), result)
			assert.Empty(t, diagnostics)
		})
	})
	t.Run("Cluster", func(t *testing.T) {
		t.Parallel()

		t.Run("empty", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewZeroToModelConverter(&diagnostics).Cluster(
				zeroapi.Cluster{},
				zeroapi.NamespaceWithRole{},
			)
			assert.Equal(t, provider.ClusterModel{
				Domain:      types.StringValue(""),
				FQDN:        types.StringValue(""),
				ID:          types.StringValue(""),
				Name:        types.StringValue(""),
				NamespaceID: types.StringValue(""),
			}, result)
			assert.Empty(t, diagnostics)
		})
		t.Run("valid", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewZeroToModelConverter(&diagnostics).Cluster(
				zeroapi.Cluster{
					Domain:                  "example.com",
					Flavor:                  new(zeroapi.Hosted),
					Fqdn:                    "cluster.example.com",
					Id:                      "ID",
					ManualOverrideIpAddress: new("1.2.3.4"),
					Name:                    "Name",
					NamespaceId:             "NamespaceID",
				},
				zeroapi.NamespaceWithRole{
					ParentId: new("ParentID"),
				},
			)
			assert.Equal(t, provider.ClusterModel{
				Domain:                  types.StringValue("example.com"),
				Flavor:                  types.StringValue("hosted"),
				FQDN:                    types.StringValue("cluster.example.com"),
				ID:                      types.StringValue("ID"),
				ManualOverrideIPAddress: types.StringValue("1.2.3.4"),
				Name:                    types.StringValue("Name"),
				NamespaceID:             types.StringValue("NamespaceID"),
				ParentNamespaceID:       types.StringValue("ParentID"),
			}, result)
			assert.Empty(t, diagnostics)
		})
	})
	t.Run("Namespace", func(t *testing.T) {
		t.Parallel()

		t.Run("empty", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewZeroToModelConverter(&diagnostics).Namespace(zeroapi.NamespaceWithRole{})
			assert.Equal(t, provider.NamespaceModel{
				ID:   types.StringValue(""),
				Name: types.StringValue(""),
			}, result)
			assert.Empty(t, diagnostics)
		})
		t.Run("valid non-cluster", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewZeroToModelConverter(&diagnostics).Namespace(zeroapi.NamespaceWithRole{
				Id:       "ID",
				Name:     "Name",
				ParentId: new("ParentID"),
				Type:     zeroapi.NamespaceType("organization"),
			})
			assert.Equal(t, provider.NamespaceModel{
				ID:       types.StringValue("ID"),
				Name:     types.StringValue("Name"),
				ParentID: types.StringValue("ParentID"),
			}, result)
			assert.Empty(t, diagnostics)
		})
		t.Run("valid cluster", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewZeroToModelConverter(&diagnostics).Namespace(zeroapi.NamespaceWithRole{
				Id:       "ID",
				Name:     "Name",
				ParentId: new("ParentID"),
				Type:     zeroapi.NamespaceTypeCluster,
			})
			assert.Equal(t, provider.NamespaceModel{
				ClusterID: types.StringValue("ID"),
				ID:        types.StringValue("ID"),
				Name:      types.StringValue("Name"),
				ParentID:  types.StringValue("ParentID"),
			}, result)
			assert.Empty(t, diagnostics)
		})
	})
}
