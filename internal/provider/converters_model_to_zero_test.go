package provider_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"

	"github.com/pomerium/enterprise-terraform-provider/internal/provider"
	"github.com/pomerium/sdk-go/pkg/zeroapi"
)

func TestModelToZeroConverter(t *testing.T) {
	t.Parallel()
	t.Run("ClusterFlavor", func(t *testing.T) {
		t.Parallel()
		t.Run("null", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewModelToZeroConverter(&diagnostics).ClusterFlavor(path.Root("cluster_flavor"), types.StringNull())
			assert.Nil(t, result)
			assert.Empty(t, diagnostics)
		})
		t.Run("unknown", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewModelToZeroConverter(&diagnostics).ClusterFlavor(path.Root("cluster_flavor"), types.StringUnknown())
			assert.Nil(t, result)
			assert.Empty(t, diagnostics)
		})
		t.Run("standard", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewModelToZeroConverter(&diagnostics).ClusterFlavor(path.Root("cluster_flavor"), types.StringValue("standard"))
			assert.Equal(t, new(zeroapi.Standard), result)
			assert.Empty(t, diagnostics)
		})
		t.Run("hosted", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewModelToZeroConverter(&diagnostics).ClusterFlavor(path.Root("cluster_flavor"), types.StringValue("hosted"))
			assert.Equal(t, new(zeroapi.Hosted), result)
			assert.Empty(t, diagnostics)
		})
		t.Run("invalid", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewModelToZeroConverter(&diagnostics).ClusterFlavor(path.Root("cluster_flavor"), types.StringValue("invalid"))
			assert.Nil(t, result)
			assert.NotEmpty(t, diagnostics.Errors())
		})
	})
	t.Run("CreateClusterRequest", func(t *testing.T) {
		t.Parallel()
		t.Run("empty", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewModelToZeroConverter(&diagnostics).CreateClusterRequest(provider.ClusterModel{})
			assert.Equal(t, zeroapi.CreateClusterRequest{}, result)
			assert.Empty(t, diagnostics)
		})
		t.Run("valid", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewModelToZeroConverter(&diagnostics).CreateClusterRequest(provider.ClusterModel{
				Domain:                  types.StringValue("Domain"),
				Flavor:                  types.StringValue("standard"),
				ManualOverrideIPAddress: types.StringValue("ManualOverrideIPAddress"),
				Name:                    types.StringValue("Name"),
			})
			assert.Equal(t, zeroapi.CreateClusterRequest{
				Domain:                  "Domain",
				Flavor:                  new(zeroapi.Standard),
				ManualOverrideIpAddress: new("ManualOverrideIPAddress"),
				Name:                    "Name",
			}, result)
			assert.Empty(t, diagnostics)
		})
	})
	t.Run("NullableString", func(t *testing.T) {
		t.Parallel()
		t.Run("null", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewModelToZeroConverter(&diagnostics).NullableString(types.StringNull())
			assert.Nil(t, result)
			assert.Empty(t, diagnostics)
		})
		t.Run("unknown", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewModelToZeroConverter(&diagnostics).NullableString(types.StringUnknown())
			assert.Nil(t, result)
			assert.Empty(t, diagnostics)
		})
		t.Run("valid", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewModelToZeroConverter(&diagnostics).NullableString(types.StringValue("test"))
			assert.Equal(t, new("test"), result)
			assert.Empty(t, diagnostics)
		})
	})
	t.Run("UpdateClusterRequest", func(t *testing.T) {
		t.Parallel()
		t.Run("empty", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewModelToZeroConverter(&diagnostics).UpdateClusterRequest(provider.ClusterModel{})
			assert.Equal(t, zeroapi.UpdateClusterRequest{}, result)
			assert.Empty(t, diagnostics)
		})
		t.Run("valid", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			result := provider.NewModelToZeroConverter(&diagnostics).UpdateClusterRequest(provider.ClusterModel{
				Flavor:                  types.StringValue("standard"),
				ManualOverrideIPAddress: types.StringValue("ManualOverrideIPAddress"),
				Name:                    types.StringValue("Name"),
			})
			assert.Equal(t, zeroapi.UpdateClusterRequest{
				Flavor:                  new(zeroapi.Standard),
				ManualOverrideIpAddress: new("ManualOverrideIPAddress"),
				Name:                    "Name",
			}, result)
			assert.Empty(t, diagnostics)
		})
	})
}
