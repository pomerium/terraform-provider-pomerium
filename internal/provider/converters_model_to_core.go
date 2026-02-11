package provider

import (
	"context"
	"time"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/sdk-go/proto/pomerium"
)

type modelToCoreConverter struct {
	diagnostics *diag.Diagnostics
}

func newModelToCoreConverter(diagnostics *diag.Diagnostics) *modelToCoreConverter {
	return &modelToCoreConverter{
		diagnostics: diagnostics,
	}
}

func (c *modelToCoreConverter) CreateKeyPairRequest(src *KeyPairResourceModel) *connect.Request[pomerium.CreateKeyPairRequest] {
	if src == nil {
		return nil
	}
	return connect.NewRequest(&pomerium.CreateKeyPairRequest{
		KeyPair: c.KeyPair(src),
	})
}

func (c *modelToCoreConverter) CreatePolicyRequest(src *PolicyResourceModel) *connect.Request[pomerium.CreatePolicyRequest] {
	if src == nil {
		return nil
	}
	return connect.NewRequest(&pomerium.CreatePolicyRequest{
		Policy: c.Policy(src),
	})
}

func (c *modelToCoreConverter) CreateRouteRequest(src *RouteResourceModel) *connect.Request[pomerium.CreateRouteRequest] {
	if src == nil {
		return nil
	}
	return connect.NewRequest(&pomerium.CreateRouteRequest{
		Route: c.Route(src, nil),
	})
}

func (c *modelToCoreConverter) KeyPair(src *KeyPairResourceModel) *pomerium.KeyPair {
	if src == nil {
		return nil
	}
	return &pomerium.KeyPair{
		Certificate:     []byte(src.Certificate.ValueString()),
		CertificateInfo: nil,
		CreatedAt:       nil,
		Id:              src.ID.ValueStringPointer(),
		Key:             []byte(src.Key.ValueString()),
		ModifiedAt:      nil,
		Name:            src.Name.ValueStringPointer(),
		NamespaceId:     src.NamespaceID.ValueStringPointer(),
		Origin:          pomerium.KeyPairOrigin_KEY_PAIR_ORIGIN_UNKNOWN,
		OriginatorId:    proto.String(OriginatorID),
		Status:          pomerium.KeyPairStatus_KEY_PAIR_STATUS_UNKNOWN,
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

func (c *modelToCoreConverter) Policy(src *PolicyResourceModel) *pomerium.Policy {
	if src == nil {
		return nil
	}
	return &pomerium.Policy{
		AllowedDomains:   nil,
		AllowedIdpClaims: nil,
		AllowedUsers:     nil,
		AssignedRoutes:   nil,
		CreatedAt:        nil,
		Description:      src.Description.ValueStringPointer(),
		Enforced:         src.Enforced.ValueBoolPointer(),
		EnforcedRoutes:   nil,
		Explanation:      src.Explanation.ValueStringPointer(),
		Id:               src.ID.ValueStringPointer(),
		ModifiedAt:       nil,
		Name:             src.Name.ValueStringPointer(),
		NamespaceId:      src.NamespaceID.ValueStringPointer(),
		NamespaceName:    nil,
		OriginatorId:     proto.String(OriginatorID),
		Rego:             c.StringSliceFromList(src.Rego),
		Remediation:      src.Remediation.ValueStringPointer(),
		SourcePpl:        src.PPL.ValueStringPointer(),
	}
}

func (c *modelToCoreConverter) Route(src *RouteResourceModel, current *pomerium.Route) *pomerium.Route {
	if src == nil {
		return nil
	}
	dst := proto.CloneOf(current)
	if dst == nil {
		dst = new(pomerium.Route)
	}
	proto.Merge(dst, &pomerium.Route{
		Description:  src.Description.ValueStringPointer(),
		From:         src.From.ValueString(),
		Id:           src.ID.ValueStringPointer(),
		LogoUrl:      src.LogoURL.ValueStringPointer(),
		Name:         src.Name.ValueStringPointer(),
		NamespaceId:  src.NamespaceID.ValueStringPointer(),
		OriginatorId: proto.String(OriginatorID),
		StatName:     src.StatName.ValueStringPointer(),
		To:           c.StringSliceFromSet(src.To),
	})
	return dst
}

func (c *modelToCoreConverter) ServiceAccount(src *ServiceAccountResourceModel) *pomerium.ServiceAccount {
	if src == nil {
		return nil
	}
	return &pomerium.ServiceAccount{
		Id:           src.ID.ValueStringPointer(),
		NamespaceId:  src.NamespaceID.ValueStringPointer(),
		OriginatorId: proto.String(OriginatorID),
		Description:  src.Description.ValueStringPointer(),
		UserId:       src.UserID.ValueStringPointer(),
		ExpiresAt:    c.Timestamp(src.ExpiresAt),
		CreatedAt:    nil,
		ModifiedAt:   nil,
		AccessedAt:   nil,
	}
}

func (c *modelToCoreConverter) Settings(src *SettingsModel) *pomerium.Settings {
	if src == nil {
		return nil
	}
	return &pomerium.Settings{}
}

func (c *modelToCoreConverter) StringSliceFromList(src types.List) []string {
	if src.IsNull() {
		return nil
	}
	var dst []string
	c.diagnostics.Append(src.ElementsAs(context.Background(), &dst, false)...)
	return dst
}

func (c *modelToCoreConverter) StringSliceFromSet(src types.Set) []string {
	if src.IsNull() {
		return nil
	}
	var dst []string
	c.diagnostics.Append(src.ElementsAs(context.Background(), &dst, false)...)
	return dst
}

func (c *modelToCoreConverter) Timestamp(src types.String) *timestamppb.Timestamp {
	if src.IsNull() {
		return nil
	}
	tm, err := time.Parse(time.RFC1123Z, src.ValueString())
	if err != nil {
		c.diagnostics.AddError("invalid timestamp", err.Error())
		return nil
	}
	return timestamppb.New(tm)
}

func (c *modelToCoreConverter) Uint64(src types.Int64) *uint64 {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}
	return proto.Uint64(uint64(src.ValueInt64()))
}

func (c *modelToCoreConverter) UpdateKeyPairRequest(src *KeyPairResourceModel) *connect.Request[pomerium.UpdateKeyPairRequest] {
	if src == nil {
		return nil
	}
	return connect.NewRequest(&pomerium.UpdateKeyPairRequest{
		KeyPair: c.KeyPair(src),
	})
}

func (c *modelToCoreConverter) UpdatePolicyRequest(src *PolicyResourceModel) *connect.Request[pomerium.UpdatePolicyRequest] {
	if src == nil {
		return nil
	}
	return connect.NewRequest(&pomerium.UpdatePolicyRequest{
		Policy: c.Policy(src),
	})
}

func (c *modelToCoreConverter) UpdateRouteRequest(src *RouteResourceModel) *connect.Request[pomerium.UpdateRouteRequest] {
	if src == nil {
		return nil
	}
	return connect.NewRequest(&pomerium.UpdateRouteRequest{
		Route: c.Route(src, nil),
	})
}

func (c *modelToCoreConverter) UpdateSettingsRequest(src *SettingsModel) *connect.Request[pomerium.UpdateSettingsRequest] {
	if src == nil {
		return nil
	}
	return connect.NewRequest(&pomerium.UpdateSettingsRequest{
		Settings: c.Settings(src),
	})
}
