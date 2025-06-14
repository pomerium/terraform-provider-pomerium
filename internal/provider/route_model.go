package provider

import (
	"context"
	"encoding/base64"

	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pomerium/enterprise-client-go/pb"
)

// RouteModel represents the shared model for route resources and data sources
type RouteModel struct {
	AllowSPDY                                 types.Bool           `tfsdk:"allow_spdy"`
	AllowWebsockets                           types.Bool           `tfsdk:"allow_websockets"`
	BearerTokenFormat                         types.String         `tfsdk:"bearer_token_format"`
	CircuitBreakerThresholds                  types.Object         `tfsdk:"circuit_breaker_thresholds"`
	DependsOnHosts                            types.Set            `tfsdk:"depends_on_hosts"`
	Description                               types.String         `tfsdk:"description"`
	EnableGoogleCloudServerlessAuthentication types.Bool           `tfsdk:"enable_google_cloud_serverless_authentication"`
	From                                      types.String         `tfsdk:"from"`
	HealthChecks                              types.Set            `tfsdk:"health_checks"`
	HostPathRegexRewritePattern               types.String         `tfsdk:"host_path_regex_rewrite_pattern"`
	HostPathRegexRewriteSubstitution          types.String         `tfsdk:"host_path_regex_rewrite_substitution"`
	HostRewrite                               types.String         `tfsdk:"host_rewrite"`
	HostRewriteHeader                         types.String         `tfsdk:"host_rewrite_header"`
	ID                                        types.String         `tfsdk:"id"`
	IdleTimeout                               timetypes.GoDuration `tfsdk:"idle_timeout"`
	IDPAccessTokenAllowedAudiences            types.Set            `tfsdk:"idp_access_token_allowed_audiences"`
	IDPClientID                               types.String         `tfsdk:"idp_client_id"`
	IDPClientSecret                           types.String         `tfsdk:"idp_client_secret"`
	JWTGroupsFilter                           types.Object         `tfsdk:"jwt_groups_filter"`
	JWTIssuerFormat                           types.String         `tfsdk:"jwt_issuer_format"`
	KubernetesServiceAccountToken             types.String         `tfsdk:"kubernetes_service_account_token"`
	KubernetesServiceAccountTokenFile         types.String         `tfsdk:"kubernetes_service_account_token_file"`
	LoadBalancingPolicy                       types.String         `tfsdk:"load_balancing_policy"`
	LogoURL                                   types.String         `tfsdk:"logo_url"`
	Name                                      types.String         `tfsdk:"name"`
	NamespaceID                               types.String         `tfsdk:"namespace_id"`
	PassIdentityHeaders                       types.Bool           `tfsdk:"pass_identity_headers"`
	Path                                      types.String         `tfsdk:"path"`
	Policies                                  types.Set            `tfsdk:"policies"`
	Prefix                                    types.String         `tfsdk:"prefix"`
	PrefixRewrite                             types.String         `tfsdk:"prefix_rewrite"`
	PreserveHostHeader                        types.Bool           `tfsdk:"preserve_host_header"`
	Regex                                     types.String         `tfsdk:"regex"`
	RegexPriorityOrder                        types.Int64          `tfsdk:"regex_priority_order"`
	RegexRewritePattern                       types.String         `tfsdk:"regex_rewrite_pattern"`
	RegexRewriteSubstitution                  types.String         `tfsdk:"regex_rewrite_substitution"`
	RemoveRequestHeaders                      types.Set            `tfsdk:"remove_request_headers"`
	RewriteResponseHeaders                    types.Set            `tfsdk:"rewrite_response_headers"`
	SetRequestHeaders                         types.Map            `tfsdk:"set_request_headers"`
	SetResponseHeaders                        types.Map            `tfsdk:"set_response_headers"`
	ShowErrorDetails                          types.Bool           `tfsdk:"show_error_details"`
	StatName                                  types.String         `tfsdk:"stat_name"`
	Timeout                                   timetypes.GoDuration `tfsdk:"timeout"`
	TLSClientKeyPairID                        types.String         `tfsdk:"tls_client_key_pair_id"`
	TLSCustomCAKeyPairID                      types.String         `tfsdk:"tls_custom_ca_key_pair_id"`
	TLSDownstreamServerName                   types.String         `tfsdk:"tls_downstream_server_name"`
	TLSSkipVerify                             types.Bool           `tfsdk:"tls_skip_verify"`
	TLSUpstreamAllowRenegotiation             types.Bool           `tfsdk:"tls_upstream_allow_renegotiation"`
	TLSUpstreamServerName                     types.String         `tfsdk:"tls_upstream_server_name"`
	To                                        types.Set            `tfsdk:"to"`
}

var rewriteHeaderAttrTypes = map[string]attr.Type{
	"header": types.StringType,
	"value":  types.StringType,
	"prefix": types.StringType,
}

// RewriteHeaderAttrTypes returns the attribute type map for rewrite headers
func RewriteHeaderAttrTypes() map[string]attr.Type {
	return rewriteHeaderAttrTypes
}

func rewriteHeadersToPB(src types.Set) []*pb.RouteRewriteHeader {
	if (src).IsNull() {
		return nil
	}

	headers := make([]*pb.RouteRewriteHeader, 0)
	elements := src.Elements()
	for _, element := range elements {
		obj := element.(types.Object)
		prefixAttr := obj.Attributes()["prefix"].(types.String)

		header := &pb.RouteRewriteHeader{
			Header: obj.Attributes()["header"].(types.String).ValueString(),
			Value:  obj.Attributes()["value"].(types.String).ValueString(),
		}

		if !prefixAttr.IsNull() && prefixAttr.ValueString() != "" {
			header.Matcher = &pb.RouteRewriteHeader_Prefix{Prefix: prefixAttr.ValueString()}
		}

		headers = append(headers, header)
	}
	return headers
}

func rewriteHeadersFromPB(headers []*pb.RouteRewriteHeader) types.Set {
	if len(headers) == 0 {
		return types.SetNull(RewriteHeaderObjectType())
	}

	elements := make([]attr.Value, 0, len(headers))
	for _, header := range headers {
		prefix := header.GetPrefix()
		prefixValue := types.StringNull()
		if prefix != "" {
			prefixValue = types.StringValue(prefix)
		}

		attrs := map[string]attr.Value{
			"header": types.StringValue(header.Header),
			"value":  types.StringValue(header.Value),
			"prefix": prefixValue,
		}
		obj, _ := types.ObjectValue(rewriteHeaderAttrTypes, attrs)
		elements = append(elements, obj)
	}
	result, _ := types.SetValue(RewriteHeaderObjectType(), elements)
	return result
}

func RewriteHeaderObjectType() attr.Type {
	return types.ObjectType{AttrTypes: rewriteHeaderAttrTypes}
}

// Type definitions for health check objects
func HealthCheckPayloadObjectType() types.ObjectType {
	return types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"text":       types.StringType,
			"binary_b64": types.StringType,
		},
	}
}

func Int64RangeObjectType() types.ObjectType {
	return types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"start": types.Int64Type,
			"end":   types.Int64Type,
		},
	}
}

func HTTPHealthCheckObjectType() types.ObjectType {
	return types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"host":               types.StringType,
			"path":               types.StringType,
			"expected_statuses":  types.SetType{ElemType: Int64RangeObjectType()},
			"retriable_statuses": types.SetType{ElemType: Int64RangeObjectType()},
			"codec_client_type":  types.StringType,
		},
	}
}

func TCPHealthCheckObjectType() types.ObjectType {
	return types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"send":    HealthCheckPayloadObjectType(),
			"receive": types.SetType{ElemType: HealthCheckPayloadObjectType()},
		},
	}
}

func GrpcHealthCheckObjectType() types.ObjectType {
	return types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"service_name": types.StringType,
			"authority":    types.StringType,
		},
	}
}

func HealthCheckObjectType() types.ObjectType {
	return types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"timeout":                 timetypes.GoDurationType{},
			"interval":                timetypes.GoDurationType{},
			"initial_jitter":          timetypes.GoDurationType{},
			"interval_jitter":         timetypes.GoDurationType{},
			"interval_jitter_percent": types.Int64Type,
			"unhealthy_threshold":     types.Int64Type,
			"healthy_threshold":       types.Int64Type,
			"http_health_check":       HTTPHealthCheckObjectType(),
			"tcp_health_check":        TCPHealthCheckObjectType(),
			"grpc_health_check":       GrpcHealthCheckObjectType(),
		},
	}
}

// Convert health check payload between Terraform and protobuf
func payloadFromPB(payload *pb.HealthCheck_Payload) (types.Object, diag.Diagnostics) {
	var diags diag.Diagnostics

	if payload == nil {
		return types.ObjectNull(HealthCheckPayloadObjectType().AttrTypes), diags
	}

	attrs := map[string]attr.Value{
		"text":       types.StringNull(),
		"binary_b64": types.StringNull(),
	}

	switch p := payload.GetPayload().(type) {
	case *pb.HealthCheck_Payload_Text:
		attrs["text"] = types.StringValue(p.Text)
	case *pb.HealthCheck_Payload_Binary:
		attrs["binary_b64"] = types.StringValue(base64.StdEncoding.EncodeToString(p.Binary))
	}

	return types.ObjectValue(HealthCheckPayloadObjectType().AttrTypes, attrs)
}

func payloadToPB(obj types.Object) (*pb.HealthCheck_Payload, diag.Diagnostics) {
	var diags diag.Diagnostics

	if obj.IsNull() {
		return nil, diags
	}

	attrs := obj.Attributes()
	payload := &pb.HealthCheck_Payload{}

	text := attrs["text"].(types.String)
	binaryB64 := attrs["binary_b64"].(types.String)

	if !text.IsNull() {
		payload.Payload = &pb.HealthCheck_Payload_Text{
			Text: text.ValueString(),
		}
	} else if !binaryB64.IsNull() {
		binaryData, err := base64.StdEncoding.DecodeString(binaryB64.ValueString())
		if err != nil {
			diags.AddError("Invalid base64 data", "Could not decode base64 binary payload: "+err.Error())
			return nil, diags
		}
		payload.Payload = &pb.HealthCheck_Payload_Binary{
			Binary: binaryData,
		}
	}

	return payload, diags
}

// Convert Int64Range between Terraform and protobuf
func int64RangeFromPB(r *pb.Int64Range) (types.Object, diag.Diagnostics) {
	var diags diag.Diagnostics

	if r == nil {
		return types.ObjectNull(Int64RangeObjectType().AttrTypes), diags
	}

	attrs := map[string]attr.Value{
		"start": types.Int64Value(r.Start),
		"end":   types.Int64Value(r.End),
	}

	return types.ObjectValue(Int64RangeObjectType().AttrTypes, attrs)
}

func int64RangeToPB(obj types.Object) (*pb.Int64Range, diag.Diagnostics) {
	var diags diag.Diagnostics

	if obj.IsNull() {
		return nil, diags
	}

	attrs := obj.Attributes()
	r := &pb.Int64Range{
		Start: attrs["start"].(types.Int64).ValueInt64(),
		End:   attrs["end"].(types.Int64).ValueInt64(),
	}

	return r, diags
}

// Convert HealthCheck between Terraform and protobuf
func HealthCheckFromPB(hc *pb.HealthCheck) (types.Object, diag.Diagnostics) {
	var diags diag.Diagnostics

	if hc == nil {
		return types.ObjectNull(HealthCheckObjectType().AttrTypes), diags
	}

	attrs := map[string]attr.Value{
		"timeout":                 FromDuration(hc.Timeout),
		"interval":                FromDuration(hc.Interval),
		"initial_jitter":          FromDuration(hc.InitialJitter),
		"interval_jitter":         FromDuration(hc.IntervalJitter),
		"interval_jitter_percent": UInt32ToInt64OrNull(hc.IntervalJitterPercent),
		"unhealthy_threshold":     UInt32ToInt64OrNull(hc.UnhealthyThreshold),
		"healthy_threshold":       UInt32ToInt64OrNull(hc.HealthyThreshold),
		"http_health_check":       types.ObjectNull(HTTPHealthCheckObjectType().AttrTypes),
		"tcp_health_check":        types.ObjectNull(TCPHealthCheckObjectType().AttrTypes),
		"grpc_health_check":       types.ObjectNull(GrpcHealthCheckObjectType().AttrTypes),
	}

	if httpHc := hc.GetHttpHealthCheck(); httpHc != nil {
		expectedStatusesElem := []attr.Value{}
		for _, status := range httpHc.ExpectedStatuses {
			statusObj, diagsStatus := int64RangeFromPB(status)
			diags.Append(diagsStatus...)
			expectedStatusesElem = append(expectedStatusesElem, statusObj)
		}
		expectedStatuses, _ := types.SetValue(Int64RangeObjectType(), expectedStatusesElem)

		retriableStatusesElem := []attr.Value{}
		for _, status := range httpHc.RetriableStatuses {
			statusObj, diagsStatus := int64RangeFromPB(status)
			diags.Append(diagsStatus...)
			retriableStatusesElem = append(retriableStatusesElem, statusObj)
		}
		retriableStatuses, _ := types.SetValue(Int64RangeObjectType(), retriableStatusesElem)

		httpAttrs := map[string]attr.Value{
			"host":               types.StringValue(httpHc.Host),
			"path":               types.StringValue(httpHc.Path),
			"expected_statuses":  expectedStatuses,
			"retriable_statuses": retriableStatuses,
			"codec_client_type":  types.StringValue(httpHc.CodecClientType.String()),
		}

		httpHealthCheck, _ := types.ObjectValue(HTTPHealthCheckObjectType().AttrTypes, httpAttrs)
		attrs["http_health_check"] = httpHealthCheck
	} else if tcpHc := hc.GetTcpHealthCheck(); tcpHc != nil {
		sendPayload, diagsSend := payloadFromPB(tcpHc.Send)
		diags.Append(diagsSend...)

		receiveElements := []attr.Value{}
		for _, payload := range tcpHc.Receive {
			payloadObj, diagsPayload := payloadFromPB(payload)
			diags.Append(diagsPayload...)
			receiveElements = append(receiveElements, payloadObj)
		}
		receiveSet, _ := types.SetValue(HealthCheckPayloadObjectType(), receiveElements)

		tcpAttrs := map[string]attr.Value{
			"send":    sendPayload,
			"receive": receiveSet,
		}

		tcpHealthCheck, _ := types.ObjectValue(TCPHealthCheckObjectType().AttrTypes, tcpAttrs)
		attrs["tcp_health_check"] = tcpHealthCheck
	} else if grpcHc := hc.GetGrpcHealthCheck(); grpcHc != nil {
		grpcAttrs := map[string]attr.Value{
			"service_name": types.StringValue(grpcHc.ServiceName),
			"authority":    types.StringValue(grpcHc.Authority),
		}

		grpcHealthCheck, _ := types.ObjectValue(GrpcHealthCheckObjectType().AttrTypes, grpcAttrs)
		attrs["grpc_health_check"] = grpcHealthCheck
	} else {
		diags.AddAttributeError(path.Root("health_checks"), "health check not specified", "must specify one of http_health_check, tcp_health_check, or grpc_health_check")
	}

	return types.ObjectValue(HealthCheckObjectType().AttrTypes, attrs)
}

func HealthCheckToPB(obj types.Object) (*pb.HealthCheck, diag.Diagnostics) {
	var diags diag.Diagnostics

	if obj.IsNull() {
		return nil, diags
	}

	attrs := obj.Attributes()
	hc := &pb.HealthCheck{}

	// Convert basic fields
	timeout := attrs["timeout"].(timetypes.GoDuration)
	interval := attrs["interval"].(timetypes.GoDuration)
	initialJitter := attrs["initial_jitter"].(timetypes.GoDuration)
	intervalJitter := attrs["interval_jitter"].(timetypes.GoDuration)
	intervalJitterPercent := attrs["interval_jitter_percent"].(types.Int64)
	unhealthyThreshold := attrs["unhealthy_threshold"].(types.Int64)
	healthyThreshold := attrs["healthy_threshold"].(types.Int64)

	ToDuration(&hc.Timeout, timeout, &diags)
	ToDuration(&hc.Interval, interval, &diags)
	ToDuration(&hc.InitialJitter, initialJitter, &diags)
	ToDuration(&hc.IntervalJitter, intervalJitter, &diags)
	if !intervalJitterPercent.IsNull() {
		hc.IntervalJitterPercent = uint32(intervalJitterPercent.ValueInt64())
	}
	if !unhealthyThreshold.IsNull() {
		hc.UnhealthyThreshold = uint32(unhealthyThreshold.ValueInt64())
	}
	if !healthyThreshold.IsNull() {
		hc.HealthyThreshold = uint32(healthyThreshold.ValueInt64())
	}

	httpHc := attrs["http_health_check"].(types.Object)
	tcpHc := attrs["tcp_health_check"].(types.Object)
	grpcHc := attrs["grpc_health_check"].(types.Object)

	if !httpHc.IsNull() {
		httpAttrs := httpHc.Attributes()
		httpHealthCheck := &pb.HealthCheck_HttpHealthCheck{}

		host := httpAttrs["host"].(types.String)
		path := httpAttrs["path"].(types.String)
		codecType := httpAttrs["codec_client_type"].(types.String)
		expectedStatuses := httpAttrs["expected_statuses"].(types.Set)
		retriableStatuses := httpAttrs["retriable_statuses"].(types.Set)

		if !host.IsNull() {
			httpHealthCheck.Host = host.ValueString()
		}
		if !path.IsNull() {
			httpHealthCheck.Path = path.ValueString()
		}
		if !codecType.IsNull() {
			// Handle codec client type enum properly
			switch codecType.ValueString() {
			case "HTTP1":
				httpHealthCheck.CodecClientType = pb.CodecClientType_HTTP1
			case "HTTP2":
				httpHealthCheck.CodecClientType = pb.CodecClientType_HTTP2
			default:
				// Default to HTTP1 if not specified or invalid
				httpHealthCheck.CodecClientType = pb.CodecClientType_HTTP1
			}
		}

		if !expectedStatuses.IsNull() {
			for _, elem := range expectedStatuses.Elements() {
				obj := elem.(types.Object)
				statusRange, diagsRange := int64RangeToPB(obj)
				diags.Append(diagsRange...)
				httpHealthCheck.ExpectedStatuses = append(httpHealthCheck.ExpectedStatuses, statusRange)
			}
		}

		if !retriableStatuses.IsNull() {
			for _, elem := range retriableStatuses.Elements() {
				obj := elem.(types.Object)
				statusRange, diagsRange := int64RangeToPB(obj)
				diags.Append(diagsRange...)
				httpHealthCheck.RetriableStatuses = append(httpHealthCheck.RetriableStatuses, statusRange)
			}
		}

		hc.HealthChecker = &pb.HealthCheck_HttpHealthCheck_{
			HttpHealthCheck: httpHealthCheck,
		}
	} else if !tcpHc.IsNull() {
		tcpAttrs := tcpHc.Attributes()
		tcpHealthCheck := &pb.HealthCheck_TcpHealthCheck{}

		send := tcpAttrs["send"].(types.Object)
		receive := tcpAttrs["receive"].(types.Set)

		if !send.IsNull() {
			sendPayload, diagsSend := payloadToPB(send)
			diags.Append(diagsSend...)
			tcpHealthCheck.Send = sendPayload
		}

		if !receive.IsNull() {
			for _, elem := range receive.Elements() {
				obj := elem.(types.Object)
				payload, diagsPayload := payloadToPB(obj)
				diags.Append(diagsPayload...)
				tcpHealthCheck.Receive = append(tcpHealthCheck.Receive, payload)
			}
		}

		hc.HealthChecker = &pb.HealthCheck_TcpHealthCheck_{
			TcpHealthCheck: tcpHealthCheck,
		}
	} else if !grpcHc.IsNull() {
		grpcAttrs := grpcHc.Attributes()
		grpcHealthCheck := &pb.HealthCheck_GrpcHealthCheck{}

		serviceName := grpcAttrs["service_name"].(types.String)
		authority := grpcAttrs["authority"].(types.String)

		if !serviceName.IsNull() {
			grpcHealthCheck.ServiceName = serviceName.ValueString()
		}
		if !authority.IsNull() {
			grpcHealthCheck.Authority = authority.ValueString()
		}

		hc.HealthChecker = &pb.HealthCheck_GrpcHealthCheck_{
			GrpcHealthCheck: grpcHealthCheck,
		}
	} else {
		diags.AddAttributeError(path.Root("health_checks"), "health check not specified", "must specify one of http_health_check, tcp_health_check, or grpc_health_check")
	}

	return hc, diags
}

// Convert health checks between Terraform and protobuf
func healthChecksFromPB(dst *types.Set, src []*pb.HealthCheck, diags *diag.Diagnostics) {
	if len(src) == 0 {
		*dst = types.SetNull(HealthCheckObjectType())
		return
	}

	elements := make([]attr.Value, 0, len(src))
	for _, hc := range src {
		healthCheck, diagsHc := HealthCheckFromPB(hc)
		diags.Append(diagsHc...)
		elements = append(elements, healthCheck)
	}

	result, diagsSet := types.SetValue(HealthCheckObjectType(), elements)
	diags.Append(diagsSet...)
	*dst = result
}

func healthChecksToPB(dst *[]*pb.HealthCheck, src types.Set, diags *diag.Diagnostics) {
	if src.IsNull() {
		return
	}

	elements := src.Elements()
	healthChecks := make([]*pb.HealthCheck, 0, len(elements))

	for _, element := range elements {
		obj := element.(types.Object)
		hc, diagsHc := HealthCheckToPB(obj)
		diags.Append(diagsHc...)
		if hc != nil {
			healthChecks = append(healthChecks, hc)
		}
	}

	*dst = healthChecks
}

func ConvertRouteToPB(
	ctx context.Context,
	src *RouteResourceModel,
) (*pb.Route, diag.Diagnostics) {
	dst := new(pb.Route)
	var diagnostics diag.Diagnostics

	dst.Id = src.ID.ValueString()
	dst.Name = src.Name.ValueString()
	dst.From = src.From.ValueString()
	dst.NamespaceId = src.NamespaceID.ValueString()
	dst.StatName = src.StatName.ValueString()
	dst.Prefix = src.Prefix.ValueStringPointer()
	dst.Path = src.Path.ValueStringPointer()
	dst.Regex = src.Regex.ValueStringPointer()
	dst.PrefixRewrite = src.PrefixRewrite.ValueStringPointer()
	dst.RegexRewritePattern = src.RegexRewritePattern.ValueStringPointer()
	dst.RegexRewriteSubstitution = src.RegexRewriteSubstitution.ValueStringPointer()
	dst.HostRewrite = src.HostRewrite.ValueStringPointer()
	dst.HostRewriteHeader = src.HostRewriteHeader.ValueStringPointer()
	dst.HostPathRegexRewritePattern = src.HostPathRegexRewritePattern.ValueStringPointer()
	dst.HostPathRegexRewriteSubstitution = src.HostPathRegexRewriteSubstitution.ValueStringPointer()
	dst.RegexPriorityOrder = src.RegexPriorityOrder.ValueInt64Pointer()
	ToDuration(&dst.Timeout, src.Timeout, &diagnostics)
	ToDuration(&dst.IdleTimeout, src.IdleTimeout, &diagnostics)
	dst.AllowWebsockets = src.AllowWebsockets.ValueBoolPointer()
	dst.AllowSpdy = src.AllowSPDY.ValueBoolPointer()
	dst.TlsSkipVerify = src.TLSSkipVerify.ValueBoolPointer()
	dst.TlsUpstreamServerName = src.TLSUpstreamServerName.ValueStringPointer()
	dst.TlsDownstreamServerName = src.TLSDownstreamServerName.ValueStringPointer()
	dst.TlsUpstreamAllowRenegotiation = src.TLSUpstreamAllowRenegotiation.ValueBoolPointer()
	ToStringMap(ctx, &dst.SetRequestHeaders, src.SetRequestHeaders, &diagnostics)
	ToStringSliceFromSet(ctx, &dst.RemoveRequestHeaders, src.RemoveRequestHeaders, &diagnostics)
	ToStringMap(ctx, &dst.SetResponseHeaders, src.SetResponseHeaders, &diagnostics)
	dst.PreserveHostHeader = src.PreserveHostHeader.ValueBoolPointer()
	dst.PassIdentityHeaders = src.PassIdentityHeaders.ValueBoolPointer()
	dst.KubernetesServiceAccountToken = src.KubernetesServiceAccountToken.ValueStringPointer()
	dst.IdpClientId = src.IDPClientID.ValueStringPointer()
	dst.IdpClientSecret = src.IDPClientSecret.ValueStringPointer()
	dst.ShowErrorDetails = src.ShowErrorDetails.ValueBool()
	JWTGroupsFilterToPB(ctx, &dst.JwtGroupsFilter, src.JWTGroupsFilter, &diagnostics)
	ToStringSliceFromSet(ctx, &dst.To, src.To, &diagnostics)
	ToStringSliceFromSet(ctx, &dst.PolicyIds, src.Policies, &diagnostics)
	dst.TlsClientKeyPairId = src.TLSClientKeyPairID.ValueStringPointer()
	dst.TlsCustomCaKeyPairId = src.TLSCustomCAKeyPairID.ValueStringPointer()
	dst.Description = src.Description.ValueStringPointer()
	dst.LogoUrl = src.LogoURL.ValueStringPointer()
	if !src.EnableGoogleCloudServerlessAuthentication.IsNull() {
		dst.EnableGoogleCloudServerlessAuthentication = src.EnableGoogleCloudServerlessAuthentication.ValueBool()
	}
	dst.KubernetesServiceAccountTokenFile = src.KubernetesServiceAccountTokenFile.ValueStringPointer()
	dst.JwtIssuerFormat = ToIssuerFormat(src.JWTIssuerFormat, &diagnostics)
	dst.RewriteResponseHeaders = rewriteHeadersToPB(src.RewriteResponseHeaders)
	dst.BearerTokenFormat = ToBearerTokenFormat(src.BearerTokenFormat)
	ToRouteStringList(ctx, &dst.IdpAccessTokenAllowedAudiences, src.IDPAccessTokenAllowedAudiences, &diagnostics)
	dst.OriginatorId = OriginatorID
	OptionalEnumValueToPB(&dst.LoadBalancingPolicy, src.LoadBalancingPolicy, "LOAD_BALANCING_POLICY", &diagnostics)
	healthChecksToPB(&dst.HealthChecks, src.HealthChecks, &diagnostics)
	ToStringSliceFromSet(ctx, &dst.DependsOn, src.DependsOnHosts, &diagnostics)
	dst.CircuitBreakerThresholds = CircuitBreakerThresholdsToPB(src.CircuitBreakerThresholds)

	return dst, diagnostics
}

func ConvertRouteFromPB(
	dst *RouteResourceModel,
	src *pb.Route,
) diag.Diagnostics {
	var diagnostics diag.Diagnostics

	dst.ID = types.StringValue(src.Id)
	dst.Name = types.StringValue(src.Name)
	dst.From = types.StringValue(src.From)
	dst.NamespaceID = types.StringValue(src.NamespaceId)
	dst.To = FromStringSliceToSet(src.To)
	dst.Policies = FromStringSliceToSet(StringSliceExclude(src.PolicyIds, src.EnforcedPolicyIds))
	dst.StatName = types.StringValue(src.StatName)
	dst.Prefix = types.StringPointerValue(src.Prefix)
	dst.Path = types.StringPointerValue(src.Path)
	dst.Regex = types.StringPointerValue(src.Regex)
	dst.PrefixRewrite = types.StringPointerValue(src.PrefixRewrite)
	dst.RegexRewritePattern = types.StringPointerValue(src.RegexRewritePattern)
	dst.RegexRewriteSubstitution = types.StringPointerValue(src.RegexRewriteSubstitution)
	dst.HostRewrite = types.StringPointerValue(src.HostRewrite)
	dst.HostRewriteHeader = types.StringPointerValue(src.HostRewriteHeader)
	dst.HostPathRegexRewritePattern = types.StringPointerValue(src.HostPathRegexRewritePattern)
	dst.HostPathRegexRewriteSubstitution = types.StringPointerValue(src.HostPathRegexRewriteSubstitution)
	dst.RegexPriorityOrder = types.Int64PointerValue(src.RegexPriorityOrder)
	dst.Timeout = FromDuration(src.Timeout)
	dst.IdleTimeout = FromDuration(src.IdleTimeout)
	dst.AllowWebsockets = types.BoolPointerValue(src.AllowWebsockets)
	dst.AllowSPDY = types.BoolPointerValue(src.AllowSpdy)
	dst.TLSSkipVerify = types.BoolPointerValue(src.TlsSkipVerify)
	dst.TLSUpstreamServerName = types.StringPointerValue(src.TlsUpstreamServerName)
	dst.TLSDownstreamServerName = types.StringPointerValue(src.TlsDownstreamServerName)
	dst.TLSUpstreamAllowRenegotiation = types.BoolPointerValue(src.TlsUpstreamAllowRenegotiation)
	dst.SetRequestHeaders = FromStringMap(src.SetRequestHeaders)
	dst.RemoveRequestHeaders = FromStringSliceToSet(src.RemoveRequestHeaders)
	dst.SetResponseHeaders = FromStringMap(src.SetResponseHeaders)
	dst.PreserveHostHeader = types.BoolPointerValue(src.PreserveHostHeader)
	dst.PassIdentityHeaders = types.BoolPointerValue(src.PassIdentityHeaders)
	dst.KubernetesServiceAccountToken = types.StringPointerValue(src.KubernetesServiceAccountToken)
	dst.IDPClientID = types.StringPointerValue(src.IdpClientId)
	dst.IDPClientSecret = types.StringPointerValue(src.IdpClientSecret)
	dst.ShowErrorDetails = types.BoolValue(src.ShowErrorDetails)
	JWTGroupsFilterFromPB(&dst.JWTGroupsFilter, src.JwtGroupsFilter)
	dst.TLSClientKeyPairID = types.StringPointerValue(src.TlsClientKeyPairId)
	dst.TLSCustomCAKeyPairID = types.StringPointerValue(src.TlsCustomCaKeyPairId)
	dst.Description = types.StringPointerValue(src.Description)
	dst.LogoURL = types.StringPointerValue(src.LogoUrl)
	dst.EnableGoogleCloudServerlessAuthentication = types.BoolNull()
	if src.EnableGoogleCloudServerlessAuthentication {
		dst.EnableGoogleCloudServerlessAuthentication = types.BoolValue(true)
	}
	dst.KubernetesServiceAccountTokenFile = types.StringPointerValue(src.KubernetesServiceAccountTokenFile)
	dst.JWTIssuerFormat = FromIssuerFormat(src.JwtIssuerFormat)
	dst.RewriteResponseHeaders = rewriteHeadersFromPB(src.RewriteResponseHeaders)
	dst.BearerTokenFormat = FromBearerTokenFormat(src.BearerTokenFormat)
	dst.IDPAccessTokenAllowedAudiences = FromStringList(src.IdpAccessTokenAllowedAudiences)
	dst.LoadBalancingPolicy = OptionalEnumValueFromPB(src.LoadBalancingPolicy, "LOAD_BALANCING_POLICY")
	healthChecksFromPB(&dst.HealthChecks, src.HealthChecks, &diagnostics)
	dst.DependsOnHosts = FromStringSliceToSet(src.DependsOn)
	dst.CircuitBreakerThresholds = CircuitBreakerThresholdsFromPB(src.CircuitBreakerThresholds, &diagnostics)

	return diagnostics
}
