package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pomerium/sdk-go/pkg/zeroapi"
)

type ZeroToModelConverter struct {
	diagnostics *diag.Diagnostics
}

func NewZeroToModelConverter(diagnostics *diag.Diagnostics) *ZeroToModelConverter {
	return &ZeroToModelConverter{
		diagnostics: diagnostics,
	}
}

func (c *ZeroToModelConverter) Cluster(src zeroapi.Cluster, namespace zeroapi.NamespaceWithRole) ClusterModel {
	return ClusterModel{
		CertificateAuthorityB64:  types.StringNull(),
		CertificateAuthorityFile: types.StringNull(),
		DatabrokerServiceURL:     types.StringNull(),
		Domain:                   types.StringValue(src.Domain),
		Flavor:                   c.ClusterFlavor(src.Flavor),
		FQDN:                     types.StringValue(src.Fqdn),
		ID:                       types.StringValue(src.Id),
		InsecureSkipVerify:       types.BoolNull(),
		ManualOverrideIPAddress:  types.StringPointerValue(src.ManualOverrideIpAddress),
		Name:                     types.StringValue(src.Name),
		NamespaceID:              types.StringValue(src.NamespaceId),
		OverrideCertificateName:  types.StringNull(),
		ParentNamespaceID:        types.StringPointerValue(namespace.ParentId),
		SharedSecretB64:          types.StringNull(),
	}
}

func (c *ZeroToModelConverter) ClusterFlavor(src *zeroapi.ClusterFlavor) types.String {
	if src == nil {
		return types.StringNull()
	}
	return types.StringValue(string(*src))
}

func (c *ZeroToModelConverter) Namespace(src zeroapi.NamespaceWithRole) NamespaceModel {
	dst := NamespaceModel{
		ClusterID: types.StringNull(),
		ID:        types.StringValue(src.Id),
		Name:      types.StringValue(src.Name),
		ParentID:  types.StringPointerValue(src.ParentId),
	}
	if src.Type == zeroapi.NamespaceTypeCluster {
		dst.ClusterID = types.StringValue(src.Id)
	}
	return dst
}
