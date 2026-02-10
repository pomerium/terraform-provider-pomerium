package provider

import (
	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/sdk-go/proto/pomerium"
)

type modelToCoreConverter struct {
	diagnostics diag.Diagnostics
}

func newModelToCoreConverter() *modelToCoreConverter {
	return &modelToCoreConverter{
		diagnostics: nil,
	}
}

func (c *modelToCoreConverter) ListFilter(clusterID, namespaceID, query types.String) *structpb.Struct {
	if clusterID.IsNull() && namespaceID.IsNull() && query.IsNull() {
		return nil
	}
	dst := &structpb.Struct{Fields: make(map[string]*structpb.Value)}
	if !clusterID.IsNull() {
		dst.Fields["cluster_id"] = structpb.NewStringValue(clusterID.ValueString())
	}
	if !namespaceID.IsNull() {
		dst.Fields["namespace_id"] = structpb.NewStringValue(namespaceID.ValueString())
	}
	if !query.IsNull() {
		dst.Fields["query"] = structpb.NewStringValue(query.ValueString())
	}
	return dst
}

func (c *modelToCoreConverter) ListPoliciesRequest(src *PoliciesDataSourceModel) *connect.Request[pomerium.ListPoliciesRequest] {
	if src == nil {
		return nil
	}
	dst := connect.NewRequest(&pomerium.ListPoliciesRequest{
		Filter:  c.ListFilter(src.ClusterID, src.NamespaceID, src.Query),
		Limit:   c.Uint64(src.Limit),
		Offset:  c.Uint64(src.Offset),
		OrderBy: src.OrderBy.ValueStringPointer(),
	})
	if !src.ClusterID.IsNull() {
		dst.Header().Set("Cluster-Id", src.ClusterID.ValueString())
	}
	return dst
}

func (c *modelToCoreConverter) ListRoutesRequest(src *RoutesDataSourceModel) *connect.Request[pomerium.ListRoutesRequest] {
	if src == nil {
		return nil
	}
	dst := connect.NewRequest(&pomerium.ListRoutesRequest{
		Filter:  c.ListFilter(src.ClusterID, src.NamespaceID, src.Query),
		Limit:   c.Uint64(src.Limit),
		Offset:  c.Uint64(src.Offset),
		OrderBy: src.OrderBy.ValueStringPointer(),
	})
	if !src.ClusterID.IsNull() {
		dst.Header().Set("Cluster-Id", src.ClusterID.ValueString())
	}
	return dst
}

func (c *modelToCoreConverter) Uint64(src types.Int64) *uint64 {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}
	return proto.Uint64(uint64(src.ValueInt64()))
}
