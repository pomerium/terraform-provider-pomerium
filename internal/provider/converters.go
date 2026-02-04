package provider

import (
	"encoding/base64"

	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/pomerium/sdk-go/proto/pomerium"
)

type protoToModelConverter struct {
	diagnostics diag.Diagnostics
}

func newProtoToModelConverter() *protoToModelConverter {
	return &protoToModelConverter{
		diagnostics: nil,
	}
}

func (c *protoToModelConverter) Duration(src *durationpb.Duration) timetypes.GoDuration {
	if src == nil {
		return timetypes.NewGoDurationNull()
	}
	return timetypes.NewGoDurationValue(src.AsDuration())
}

func (c *protoToModelConverter) Route(src *pomerium.Route) *RouteResourceModel {
	return &RouteResourceModel{
		AllowSPDY:                types.BoolValue(src.AllowSpdy),
		AllowWebsockets:          types.BoolValue(src.AllowWebsockets),
		BearerTokenFormat:        c.BearerTokenFormat(src.BearerTokenFormat),
		CircuitBreakerThresholds: c.CircuitBreakerThresholds(src.CircuitBreakerThresholds),
		DependsOnHosts:           c.SetFromStringSlice(src.DependsOn),
		Description:              types.StringPointerValue(src.Description),
		EnableGoogleCloudServerlessAuthentication: types.BoolValue(src.EnableGoogleCloudServerlessAuthentication),
		From:                              types.StringValue(src.From),
		HealthChecks:                      c.HealthChecks(src.HealthChecks),
		HealthyPanicThreshold:             types.Int32PointerValue(src.HealthyPanicThreshold),
		HostPathRegexRewritePattern:       types.StringPointerValue(src.HostPathRegexRewritePattern),
		HostPathRegexRewriteSubstitution:  types.StringPointerValue(src.HostPathRegexRewriteSubstitution),
		HostRewrite:                       types.StringPointerValue(src.HostRewrite),
		HostRewriteHeader:                 types.StringPointerValue(src.HostRewriteHeader),
		ID:                                types.StringPointerValue(src.Id),
		IdleTimeout:                       c.Duration(src.IdleTimeout),
		IDPAccessTokenAllowedAudiences:    c.SetFromStringSlice(src.IdpAccessTokenAllowedAudiences.GetValues()),
		IDPClientID:                       types.StringPointerValue(src.IdpClientId),
		IDPClientSecret:                   types.StringPointerValue(src.IdpClientSecret),
		JWTGroupsFilter:                   c.JWTGroupsFilter(src),
		JWTIssuerFormat:                   c.IssuerFormat(src.JwtIssuerFormat),
		KubernetesServiceAccountToken:     types.StringValue(src.KubernetesServiceAccountToken),
		KubernetesServiceAccountTokenFile: types.StringValue(src.KubernetesServiceAccountTokenFile),
		LoadBalancingPolicy:               c.LoadBalancingPolicy(src.LoadBalancingPolicy),
		LogoURL:                           types.StringPointerValue(src.LogoUrl),
		Name:                              types.StringPointerValue(src.Name),
		NamespaceID:                       types.StringPointerValue(src.NamespaceId),
		PassIdentityHeaders:               types.BoolPointerValue(src.PassIdentityHeaders),
		Path:                              types.StringValue(src.Path),
		Policies:                          c.SetFromStringSlice(src.PolicyIds),
		Prefix:                            types.StringValue(src.Prefix),
		PrefixRewrite:                     types.StringValue(src.PrefixRewrite),
		PreserveHostHeader:                types.BoolValue(src.PreserveHostHeader),
		Regex:                             types.StringValue(src.Regex),
		RegexPriorityOrder:                types.Int64PointerValue(src.RegexPriorityOrder),
		RegexRewritePattern:               types.StringValue(src.RegexRewritePattern),
		RegexRewriteSubstitution:          types.StringValue(src.RegexRewriteSubstitution),
		RemoveRequestHeaders:              c.SetFromStringSlice(src.RemoveRequestHeaders),
		RewriteResponseHeaders:            c.RouteRewriteHeaders(src.RewriteResponseHeaders),
		SetRequestHeaders:                 c.Map(src.SetRequestHeaders),
		SetResponseHeaders:                c.Map(src.SetResponseHeaders),
		ShowErrorDetails:                  types.BoolValue(src.ShowErrorDetails),
		StatName:                          types.StringPointerValue(src.StatName),
		Timeout:                           c.Duration(src.Timeout),
		TLSClientKeyPairID:                types.StringPointerValue(src.TlsClientKeyPairId),
		TLSCustomCAKeyPairID:              types.StringPointerValue(src.TlsCustomCaKeyPairId),
		TLSDownstreamServerName:           types.StringValue(src.TlsDownstreamServerName),
		TLSSkipVerify:                     types.BoolValue(src.TlsSkipVerify),
		TLSUpstreamAllowRenegotiation:     types.BoolValue(src.TlsUpstreamAllowRenegotiation),
		TLSUpstreamServerName:             types.StringValue(src.TlsUpstreamServerName),
		To:                                c.SetFromStringSlice(src.To),
	}
}

func (c *protoToModelConverter) BearerTokenFormat(src *pomerium.BearerTokenFormat) types.String {
	if src == nil {
		return types.StringNull()
	}
	switch *src {
	case pomerium.BearerTokenFormat_BEARER_TOKEN_FORMAT_DEFAULT:
		return types.StringValue("default")
	case pomerium.BearerTokenFormat_BEARER_TOKEN_FORMAT_IDP_ACCESS_TOKEN:
		return types.StringValue("idp_access_token")
	case pomerium.BearerTokenFormat_BEARER_TOKEN_FORMAT_IDP_IDENTITY_TOKEN:
		return types.StringValue("idp_identity_token")
	case pomerium.BearerTokenFormat_BEARER_TOKEN_FORMAT_UNKNOWN:
		fallthrough
	default:
		return types.StringValue("")
	}
}

func (c *protoToModelConverter) CircuitBreakerThresholds(src *pomerium.CircuitBreakerThresholds) types.Object {
	if src == nil {
		return types.ObjectNull(CircuitBreakerThresholdsAttributes)
	}
	dst, d := types.ObjectValue(CircuitBreakerThresholdsAttributes, map[string]attr.Value{
		"max_connections":      Int64PointerValue(src.MaxConnections),
		"max_pending_requests": Int64PointerValue(src.MaxPendingRequests),
		"max_requests":         Int64PointerValue(src.MaxRequests),
		"max_retries":          Int64PointerValue(src.MaxRetries),
		"max_connection_pools": Int64PointerValue(src.MaxConnectionPools),
	})
	c.diagnostics.Append(d...)
	return dst
}

func (c *protoToModelConverter) GRPCHealthCheck(src *pomerium.HealthCheck_GrpcHealthCheck) types.Object {
	if src == nil {
		return types.ObjectNull(GrpcHealthCheckObjectType().AttrTypes)
	}
	dst, d := types.ObjectValue(GrpcHealthCheckObjectType().AttrTypes, map[string]attr.Value{
		"authority":    types.StringValue(src.Authority),
		"service_name": types.StringValue(src.ServiceName),
	})
	c.diagnostics.Append(d...)
	return dst
}

func (c *protoToModelConverter) HealthCheck(src *pomerium.HealthCheck) types.Object {
	if src == nil {
		return types.ObjectNull(HealthCheckObjectType().AttrTypes)
	}
	dst, d := types.ObjectValue(HealthCheckObjectType().AttrTypes, map[string]attr.Value{
		"grpc_health_check":       c.GRPCHealthCheck(src.GetGrpcHealthCheck()),
		"healthy_threshold":       UInt32ToInt64OrNull(src.HealthyThreshold.GetValue()),
		"http_health_check":       c.HTTPHealthCheck(src.GetHttpHealthCheck()),
		"initial_jitter":          c.Duration(src.InitialJitter),
		"interval_jitter_percent": UInt32ToInt64OrNull(src.IntervalJitterPercent),
		"interval_jitter":         c.Duration(src.IntervalJitter),
		"interval":                c.Duration(src.Interval),
		"tcp_health_check":        c.TCPHealthCheck(src.GetTcpHealthCheck()),
		"timeout":                 c.Duration(src.Timeout),
		"unhealthy_threshold":     UInt32ToInt64OrNull(src.UnhealthyThreshold.GetValue()),
	})
	c.diagnostics.Append(d...)
	return dst
}

func (c *protoToModelConverter) HealthCheckPayload(src *pomerium.HealthCheck_Payload) types.Object {
	if src == nil {
		return types.ObjectNull(HealthCheckPayloadObjectType().AttrTypes)
	}
	dst, d := types.ObjectValue(HealthCheckPayloadObjectType().AttrTypes, map[string]attr.Value{
		"binary_b64": c.HealthCheckPayloadBinary(src),
		"text":       c.HealthCheckPayloadText(src),
	})
	c.diagnostics.Append(d...)
	return dst
}

func (c *protoToModelConverter) HealthCheckPayloads(srcs []*pomerium.HealthCheck_Payload) types.Set {
	if len(srcs) == 0 {
		return types.SetNull(HealthCheckPayloadObjectType())
	}
	elements := make([]attr.Value, 0, len(srcs))
	for _, src := range srcs {
		elements = append(elements, c.HealthCheckPayload(src))
	}
	dst, d := types.SetValue(HealthCheckPayloadObjectType(), elements)
	c.diagnostics.Append(d...)
	return dst
}

func (c *protoToModelConverter) HealthCheckPayloadBinary(src *pomerium.HealthCheck_Payload) types.String {
	if src == nil {
		return types.StringNull()
	}

	payload, ok := src.Payload.(*pomerium.HealthCheck_Payload_Binary)
	if !ok {
		return types.StringNull()
	}

	return types.StringValue(base64.StdEncoding.EncodeToString(payload.Binary))
}

func (c *protoToModelConverter) HealthCheckPayloadText(src *pomerium.HealthCheck_Payload) types.String {
	if src == nil {
		return types.StringNull()
	}

	payload, ok := src.Payload.(*pomerium.HealthCheck_Payload_Text)
	if !ok {
		return types.StringNull()
	}

	return types.StringValue(payload.Text)
}

func (c *protoToModelConverter) HealthChecks(srcs []*pomerium.HealthCheck) types.Set {
	if len(srcs) == 0 {
		return types.SetNull(HealthCheckObjectType())
	}
	elements := make([]attr.Value, 0, len(srcs))
	for _, src := range srcs {
		elements = append(elements, c.HealthCheck(src))
	}
	dst, d := types.SetValue(HealthCheckObjectType(), elements)
	c.diagnostics.Append(d...)
	return dst
}

func (c *protoToModelConverter) HTTPHealthCheck(src *pomerium.HealthCheck_HttpHealthCheck) types.Object {
	if src == nil {
		return types.ObjectNull(HTTPHealthCheckObjectType().AttrTypes)
	}
	dst, d := types.ObjectValue(HTTPHealthCheckObjectType().AttrTypes, map[string]attr.Value{
		"codec_client_type":  types.StringValue(src.CodecClientType.String()),
		"expected_statuses":  c.Int64Ranges(src.ExpectedStatuses),
		"host":               types.StringValue(src.Host),
		"path":               types.StringValue(src.Path),
		"retriable_statuses": c.Int64Ranges(src.RetriableStatuses),
	})
	c.diagnostics.Append(d...)
	return dst
}

func (c *protoToModelConverter) Int64Range(src *pomerium.HealthCheck_Int64Range) types.Object {
	if src == nil {
		return types.ObjectNull(Int64RangeObjectType().AttrTypes)
	}
	dst, d := types.ObjectValue(Int64RangeObjectType().AttrTypes, map[string]attr.Value{
		"end":   types.Int64Value(src.End),
		"start": types.Int64Value(src.Start),
	})
	c.diagnostics.Append(d...)
	return dst
}

func (c *protoToModelConverter) Int64Ranges(srcs []*pomerium.HealthCheck_Int64Range) types.Set {
	if srcs == nil {
		return types.SetNull(Int64RangeObjectType())
	}
	elements := make([]attr.Value, 0, len(srcs))
	for _, src := range srcs {
		elements = append(elements, c.Int64Range(src))
	}
	dst, d := types.SetValue(Int64RangeObjectType(), elements)
	c.diagnostics.Append(d...)
	return dst
}

func (c *protoToModelConverter) IssuerFormat(src *pomerium.IssuerFormat) types.String {
	if src == nil {
		return types.StringNull()
	}
	switch *src {
	case pomerium.IssuerFormat_IssuerHostOnly:
		return types.StringValue("IssuerHostOnly")
	case pomerium.IssuerFormat_IssuerURI:
		return types.StringValue("IssuerUri")
	default:
		return types.StringUnknown()
	}
}

func (c *protoToModelConverter) JWTGroupsFilter(src *pomerium.Route) types.Object {
	if src == nil {
		return types.ObjectNull(JWTGroupsFilterSchemaAttr)
	}
	dst, d := types.ObjectValue(JWTGroupsFilterSchemaAttr, map[string]attr.Value{
		"groups":         c.SetFromStringSlice(src.JwtGroupsFilter),
		"infer_from_ppl": types.BoolPointerValue(src.JwtGroupsFilterInferFromPpl),
	})
	c.diagnostics.Append(d...)
	return dst
}

func (c *protoToModelConverter) LoadBalancingPolicy(src *pomerium.LoadBalancingPolicy) types.String {
	if src == nil {
		return types.StringNull()
	}
	return types.StringValue(src.String())
}

func (c *protoToModelConverter) Map(src map[string]string) types.Map {
	if src == nil {
		return types.MapNull(types.StringType)
	}
	elements := make(map[string]attr.Value)
	for k, v := range src {
		elements[k] = types.StringValue(v)
	}
	return types.MapValueMust(types.StringType, elements)
}

func (c *protoToModelConverter) RouteRewriteHeader(src *pomerium.RouteRewriteHeader) types.Object {
	if src == nil {
		return types.ObjectNull(RewriteHeaderObjectType().AttrTypes)
	}
	dst, d := types.ObjectValue(RewriteHeaderObjectType().AttrTypes, map[string]attr.Value{
		"header": types.StringValue(src.GetHeader()),
		"prefix": types.StringValue(src.GetPrefix()),
		"value":  types.StringValue(src.GetValue()),
	})
	c.diagnostics.Append(d...)
	return dst
}

func (c *protoToModelConverter) RouteRewriteHeaders(srcs []*pomerium.RouteRewriteHeader) types.Set {
	if srcs == nil {
		return types.SetNull(RewriteHeaderObjectType())
	}
	elements := make([]attr.Value, 0, len(srcs))
	for _, src := range srcs {
		elements = append(elements, c.RouteRewriteHeader(src))
	}
	dst, d := types.SetValue(RewriteHeaderObjectType(), elements)
	c.diagnostics.Append(d...)
	return dst
}

func (c *protoToModelConverter) SetFromStringSlice(slice []string) types.Set {
	if slice == nil {
		return types.SetNull(types.StringType)
	}
	fields := make([]attr.Value, 0)
	for _, v := range slice {
		fields = append(fields, types.StringValue(v))
	}
	return types.SetValueMust(types.StringType, fields)
}

func (c *protoToModelConverter) TCPHealthCheck(src *pomerium.HealthCheck_TcpHealthCheck) types.Object {
	if src == nil {
		return types.ObjectNull(TCPHealthCheckObjectType().AttrTypes)
	}
	dst, d := types.ObjectValue(TCPHealthCheckObjectType().AttrTypes, map[string]attr.Value{
		"receive": c.HealthCheckPayloads(src.Receive),
		"send":    c.HealthCheckPayload(src.Send),
	})
	c.diagnostics.Append(d...)
	return dst
}
