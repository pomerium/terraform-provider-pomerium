package provider

import (
	"encoding/base64"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pomerium/enterprise-client-go/pb"
)

type consoleToModelConverter struct {
	diagnostics diag.Diagnostics
}

func newConsoleToModelConverter() *consoleToModelConverter {
	return &consoleToModelConverter{
		diagnostics: nil,
	}
}

func (c *consoleToModelConverter) Base64String(src []byte) types.String {
	if len(src) == 0 {
		return types.StringNull()
	}
	return types.StringValue(base64.StdEncoding.EncodeToString(src))
}

func (c *consoleToModelConverter) Cluster(src *pb.Cluster, namespace *pb.Namespace) *ClusterModel {
	if src == nil {
		return nil
	}
	return &ClusterModel{
		CertificateAuthorityB64:  c.Base64String(src.CertificateAuthority),
		CertificateAuthorityFile: types.StringPointerValue(src.CertificateAuthorityFile),
		DatabrokerServiceURL:     types.StringValue(src.DatabrokerServiceUrl),
		ID:                       types.StringValue(src.Id),
		InsecureSkipVerify:       types.BoolPointerValue(src.InsecureSkipVerify),
		Name:                     types.StringValue(src.Name),
		NamespaceID:              c.NullOnEmptyString(namespace.GetId()),
		OverrideCertificateName:  types.StringPointerValue(src.OverrideCertificateName),
		ParentNamespaceID:        c.NullOnEmptyString(namespace.GetParentId()),
		SharedSecretB64:          c.Base64String(src.SharedSecret),
	}
}

func (c *consoleToModelConverter) Namespace(src *pb.Namespace) *NamespaceModel {
	if src == nil {
		return nil
	}
	return &NamespaceModel{
		ClusterID: types.StringPointerValue(src.ClusterId),
		ID:        types.StringValue(src.Id),
		Name:      types.StringValue(src.Name),
		ParentID:  c.NullOnEmptyString(src.ParentId),
	}
}

func (c *consoleToModelConverter) NullOnEmptyString(src string) types.String {
	if src == "" {
		return types.StringNull()
	}
	return types.StringValue(src)
}
