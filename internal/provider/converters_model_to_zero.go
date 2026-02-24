package provider

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pomerium/sdk-go/pkg/zeroapi"
)

type ModelToZeroConverter struct {
	diagnostics *diag.Diagnostics
}

func NewModelToZeroConverter(diagnostics *diag.Diagnostics) *ModelToZeroConverter {
	return &ModelToZeroConverter{
		diagnostics: diagnostics,
	}
}

func (c *ModelToZeroConverter) ClusterFlavor(p path.Path, src types.String) *zeroapi.ClusterFlavor {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}
	switch src.ValueString() {
	case "hosted":
		return new(zeroapi.Hosted)
	case "standard":
		return new(zeroapi.Standard)
	default:
		c.diagnostics.AddAttributeError(p, "unknown cluster flavor", fmt.Sprintf("unknown cluster flavor: %s", src.ValueString()))
		return nil
	}
}

func (c *ModelToZeroConverter) CreateClusterRequest(src ClusterModel) zeroapi.CreateClusterRequest {
	return zeroapi.CreateClusterRequest{
		Domain:                  src.Domain.ValueString(),
		Flavor:                  c.ClusterFlavor(path.Root("flavor"), src.Flavor),
		ManualOverrideIpAddress: c.NullableString(src.ManualOverrideIPAddress),
		Name:                    src.Name.ValueString(),
	}
}

func (c *ModelToZeroConverter) NullableString(src types.String) *string {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}
	return src.ValueStringPointer()
}

func (c *ModelToZeroConverter) UpdateClusterRequest(src ClusterModel) zeroapi.UpdateClusterRequest {
	return zeroapi.UpdateClusterRequest{
		Flavor:                  c.ClusterFlavor(path.Root("flavor"), src.Flavor),
		ManualOverrideIpAddress: c.NullableString(src.ManualOverrideIPAddress),
		Name:                    src.Name.ValueString(),
	}
}
