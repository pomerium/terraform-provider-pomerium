package provider

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/sdk-go/proto/pomerium"
)

type ModelToAPIConverter struct {
	baseModelConverter
	diagnostics *diag.Diagnostics
}

func NewModelToAPIConverter(diagnostics *diag.Diagnostics) *ModelToAPIConverter {
	return &ModelToAPIConverter{
		baseModelConverter: baseModelConverter{
			diagnostics: diagnostics,
		},
		diagnostics: diagnostics,
	}
}

func (c *ModelToAPIConverter) BlobStorageSettings(src types.Object) *pomerium.BlobStorageSettings {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	attrs := src.Attributes()
	bucketURI, _ := attrs["bucket_uri"].(types.String)
	managedPrefix, _ := attrs["managed_prefix"].(types.String)
	return &pomerium.BlobStorageSettings{
		BucketUri:     c.NullableString(bucketURI),
		ManagedPrefix: c.NullableString(managedPrefix),
	}
}

func (c *ModelToAPIConverter) CircuitBreakerThresholds(src types.Object) *pomerium.CircuitBreakerThresholds {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	attrs := src.Attributes()
	maxConnectionPools, _ := attrs["max_connection_pools"].(types.Int64)
	maxConnections, _ := attrs["max_connections"].(types.Int64)
	maxPendingRequests, _ := attrs["max_pending_requests"].(types.Int64)
	maxRequests, _ := attrs["max_requests"].(types.Int64)
	maxRetries, _ := attrs["max_retries"].(types.Int64)

	return &pomerium.CircuitBreakerThresholds{
		MaxConnectionPools: c.NullableUint32(maxConnectionPools),
		MaxConnections:     c.NullableUint32(maxConnections),
		MaxPendingRequests: c.NullableUint32(maxPendingRequests),
		MaxRequests:        c.NullableUint32(maxRequests),
		MaxRetries:         c.NullableUint32(maxRetries),
	}
}

func (c *ModelToAPIConverter) EntityInfosFromIDs(src []string) []*pomerium.EntityInfo {
	if src == nil {
		return nil
	}
	dst := make([]*pomerium.EntityInfo, len(src))
	for i := range src {
		dst[i] = &pomerium.EntityInfo{
			Id:         new(src[i]),
			Name:       nil,
			ModifiedAt: nil,
		}
	}
	return dst
}

func (c *ModelToAPIConverter) Filter(src map[string]types.String) *structpb.Struct {
	var dst *structpb.Struct
	for field, value := range src {
		if value.IsNull() || value.IsUnknown() {
			continue
		}
		if dst == nil {
			dst = &structpb.Struct{Fields: map[string]*structpb.Value{}}
		}
		dst.Fields[field] = structpb.NewStringValue(value.ValueString())
	}
	return dst
}

func (c *ModelToAPIConverter) HealthCheck(src types.Object) *pomerium.HealthCheck {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	attrs := src.Attributes()

	// Convert basic fields
	timeout := attrs["timeout"].(timetypes.GoDuration)
	interval := attrs["interval"].(timetypes.GoDuration)
	initialJitter := attrs["initial_jitter"].(timetypes.GoDuration)
	intervalJitter := attrs["interval_jitter"].(timetypes.GoDuration)
	intervalJitterPercent := attrs["interval_jitter_percent"].(types.Int64)
	unhealthyThreshold := attrs["unhealthy_threshold"].(types.Int64)
	healthyThreshold := attrs["healthy_threshold"].(types.Int64)

	dst := &pomerium.HealthCheck{
		AltPort:                      nil,   // not supported
		AlwaysLogHealthCheckFailures: false, // not supported
		AlwaysLogHealthCheckSuccess:  false, // not supported
		HealthChecker:                nil,   // set below
		HealthyEdgeInterval:          nil,   // not supported
		HealthyThreshold:             c.WrappedUint32(healthyThreshold),
		InitialJitter:                c.Duration(path.Root("initial_jitter"), initialJitter),
		Interval:                     c.Duration(path.Root("interval"), interval),
		IntervalJitter:               c.Duration(path.Root("interval_jitter"), intervalJitter),
		IntervalJitterPercent:        uint32(intervalJitterPercent.ValueInt64()),
		NoTrafficHealthyInterval:     nil, // not supported
		NoTrafficInterval:            nil, // not supported
		ReuseConnection:              nil, // not supported
		Timeout:                      c.Duration(path.Root("timeout"), timeout),
		TransportSocketMatchCriteria: nil, // not supported
		UnhealthyEdgeInterval:        nil, // not supported
		UnhealthyInterval:            nil, // not supported
		UnhealthyThreshold:           c.WrappedUint32(unhealthyThreshold),
	}

	httpHc := attrs["http_health_check"].(types.Object)
	tcpHc := attrs["tcp_health_check"].(types.Object)
	grpcHc := attrs["grpc_health_check"].(types.Object)

	if !httpHc.IsNull() {
		httpAttrs := httpHc.Attributes()
		httpHealthCheck := &pomerium.HealthCheck_HttpHealthCheck{
			CodecClientType:        0,   // set below
			ExpectedStatuses:       nil, // set below
			Host:                   "",  // set below
			Path:                   "",  // set below
			Receive:                nil, // not supported
			RequestHeadersToRemove: nil, // not supported
			ResponseBufferSize:     nil, // not supported
			RetriableStatuses:      nil, // set below
			Send:                   nil, // not supported
		}

		host := httpAttrs["host"].(types.String)
		httpPath := httpAttrs["path"].(types.String)
		codecType := httpAttrs["codec_client_type"].(types.String)
		expectedStatuses := httpAttrs["expected_statuses"].(types.Set)
		retriableStatuses := httpAttrs["retriable_statuses"].(types.Set)

		if !host.IsNull() {
			httpHealthCheck.Host = host.ValueString()
		}
		if !httpPath.IsNull() {
			httpHealthCheck.Path = httpPath.ValueString()
		}
		if codecClientType := c.HealthCheckCodecClientType(path.Root("codec_client_type"), codecType); codecClientType != nil {
			httpHealthCheck.CodecClientType = *codecClientType
		} else {
			httpHealthCheck.CodecClientType = pomerium.HealthCheck_HTTP1
		}

		if !expectedStatuses.IsNull() {
			for _, elem := range expectedStatuses.Elements() {
				obj := elem.(types.Object)
				httpHealthCheck.ExpectedStatuses = append(httpHealthCheck.ExpectedStatuses, c.Int64Range(obj))
			}
		}

		if !retriableStatuses.IsNull() {
			for _, elem := range retriableStatuses.Elements() {
				obj := elem.(types.Object)
				httpHealthCheck.RetriableStatuses = append(httpHealthCheck.RetriableStatuses, c.Int64Range(obj))
			}
		}

		dst.HealthChecker = &pomerium.HealthCheck_HttpHealthCheck_{
			HttpHealthCheck: httpHealthCheck,
		}
	} else if !tcpHc.IsNull() {
		tcpAttrs := tcpHc.Attributes()
		tcpHealthCheck := &pomerium.HealthCheck_TcpHealthCheck{
			Receive: nil, // set below
			Send:    nil, // set below
		}

		send := tcpAttrs["send"].(types.Object)
		receive := tcpAttrs["receive"].(types.Set)

		if !send.IsNull() {
			tcpHealthCheck.Send = c.HealthCheckPayload(send)
		}

		if !receive.IsNull() {
			for _, elem := range receive.Elements() {
				obj := elem.(types.Object)
				tcpHealthCheck.Receive = append(tcpHealthCheck.Receive, c.HealthCheckPayload(obj))
			}
		}

		dst.HealthChecker = &pomerium.HealthCheck_TcpHealthCheck_{
			TcpHealthCheck: tcpHealthCheck,
		}
	} else if !grpcHc.IsNull() {
		grpcAttrs := grpcHc.Attributes()
		grpcHealthCheck := &pomerium.HealthCheck_GrpcHealthCheck{
			Authority:   "", // set below
			ServiceName: "", // set below
		}

		serviceName := grpcAttrs["service_name"].(types.String)
		authority := grpcAttrs["authority"].(types.String)

		if !serviceName.IsNull() {
			grpcHealthCheck.ServiceName = serviceName.ValueString()
		}
		if !authority.IsNull() {
			grpcHealthCheck.Authority = authority.ValueString()
		}

		dst.HealthChecker = &pomerium.HealthCheck_GrpcHealthCheck_{
			GrpcHealthCheck: grpcHealthCheck,
		}
	} else {
		c.diagnostics.AddAttributeError(path.Root("health_checks"), "health check not specified", "must specify one of http_health_check, tcp_health_check, or grpc_health_check")
	}

	return dst
}

func (c *ModelToAPIConverter) HealthCheckPayload(src types.Object) *pomerium.HealthCheck_Payload {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	attrs := src.Attributes()
	payload := new(pomerium.HealthCheck_Payload)

	text := attrs["text"].(types.String)
	binaryB64 := attrs["binary_b64"].(types.String)

	if !text.IsNull() {
		payload.Payload = &pomerium.HealthCheck_Payload_Text{
			Text: text.ValueString(),
		}
	} else if !binaryB64.IsNull() {
		binaryData, err := base64.StdEncoding.DecodeString(binaryB64.ValueString())
		if err != nil {
			c.diagnostics.AddError("Invalid base64 data", "Could not decode base64 binary payload: "+err.Error())
			return nil
		}
		payload.Payload = &pomerium.HealthCheck_Payload_Binary{
			Binary: binaryData,
		}
	}

	return payload
}

func (c *ModelToAPIConverter) Int64Range(src types.Object) *pomerium.HealthCheck_Int64Range {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	attrs := src.Attributes()
	return &pomerium.HealthCheck_Int64Range{
		Start: attrs["start"].(types.Int64).ValueInt64(),
		End:   attrs["end"].(types.Int64).ValueInt64(),
	}
}

func (c *ModelToAPIConverter) JWTGroupsFilter(src types.Object) []string {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}
	var obj struct {
		Groups       []string `tfsdk:"groups"`
		InferFromPpl *bool    `tfsdk:"infer_from_ppl"`
	}
	c.diagnostics.Append(src.As(context.Background(), &obj, basetypes.ObjectAsOptions{
		UnhandledNullAsEmpty:    true,
		UnhandledUnknownAsEmpty: false,
	})...)
	return obj.Groups
}

func (c *ModelToAPIConverter) JWTGroupsFilterInferFromPpl(src types.Object) *bool {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}
	var obj struct {
		Groups       []string `tfsdk:"groups"`
		InferFromPpl *bool    `tfsdk:"infer_from_ppl"`
	}
	c.diagnostics.Append(src.As(context.Background(), &obj, basetypes.ObjectAsOptions{
		UnhandledNullAsEmpty:    true,
		UnhandledUnknownAsEmpty: false,
	})...)
	return obj.InferFromPpl
}

func (c *ModelToAPIConverter) KeyPair(src KeyPairModel) *pomerium.KeyPair {
	return &pomerium.KeyPair{
		Certificate:     c.Bytes(src.Certificate),
		CertificateInfo: nil, // not supported
		CreatedAt:       nil, // not supported
		Id:              c.NullableString(src.ID),
		Key:             c.Bytes(src.Key),
		ModifiedAt:      nil, // not supported
		Name:            c.NullableString(src.Name),
		NamespaceId:     c.NullableString(src.NamespaceID),
		Origin:          pomerium.KeyPairOrigin_KEY_PAIR_ORIGIN_USER,
		OriginatorId:    new(OriginatorID),
		Status:          pomerium.KeyPairStatus_KEY_PAIR_STATUS_READY,
	}
}

func (c *ModelToAPIConverter) ListPoliciesRequest(src PoliciesDataSourceModel) *pomerium.ListPoliciesRequest {
	filter := c.Filter(map[string]types.String{
		"cluster_id":   src.ClusterID,
		"namespace_id": src.NamespaceID,
		"query":        src.Query,
	})
	return &pomerium.ListPoliciesRequest{
		Filter:  filter,
		Limit:   c.NullableUint64(src.Limit),
		Offset:  c.NullableUint64(src.Offset),
		OrderBy: c.NullableString(src.OrderBy),
	}
}

func (c *ModelToAPIConverter) ListRoutesRequest(src RoutesDataSourceModel) *pomerium.ListRoutesRequest {
	filter := c.Filter(map[string]types.String{
		"cluster_id":   src.ClusterID,
		"namespace_id": src.NamespaceID,
		"query":        src.Query,
	})
	return &pomerium.ListRoutesRequest{
		Filter:  filter,
		Limit:   c.NullableUint64(src.Limit),
		Offset:  c.NullableUint64(src.Offset),
		OrderBy: c.NullableString(src.OrderBy),
	}
}

func (c *ModelToAPIConverter) ListServiceAccountsRequest(src ServiceAccountsDataSourceModel) *pomerium.ListServiceAccountsRequest {
	filter := c.Filter(map[string]types.String{
		"namespace_id": src.NamespaceID,
	})
	return &pomerium.ListServiceAccountsRequest{
		Filter:  filter,
		Limit:   nil, // not supported
		Offset:  nil, // not supported
		OrderBy: nil, // not supported
	}
}

func (c *ModelToAPIConverter) Policy(src PolicyModel) *pomerium.Policy {
	return &pomerium.Policy{
		AllowedDomains:   nil, // not supported
		AllowedIdpClaims: nil, // not supported
		AllowedUsers:     nil, // not supported
		AssignedRoutes:   nil, // not supported
		CreatedAt:        nil, // not supported
		Description:      new(src.Description.ValueString()),
		Enforced:         new(src.Enforced.ValueBool()),
		EnforcedRoutes:   nil, // not supported
		Explanation:      new(src.Explanation.ValueString()),
		Id:               c.NullableString(src.ID),
		ModifiedAt:       nil, // not supported
		Name:             new(src.Name.ValueString()),
		NamespaceId:      c.NullableString(src.NamespaceID),
		NamespaceName:    nil, // not supported
		OriginatorId:     new(OriginatorID),
		Rego:             c.StringSliceFromList(path.Root("rego"), src.Rego),
		Remediation:      new(src.Remediation.ValueString()),
		SourcePpl:        new(string(src.PPL.PolicyJSON)),
	}
}

func (c *ModelToAPIConverter) Route(src RouteModel) *pomerium.Route {
	return &pomerium.Route{
		AllowAnyAuthenticatedUser:        false, // not supported
		AllowedDomains:                   nil,   // not supported
		AllowedIdpClaims:                 nil,   // not supported
		AllowedUsers:                     nil,   // not supported
		AllowPublicUnauthenticatedAccess: false, // not supported
		AllowSpdy:                        src.AllowSPDY.ValueBool(),
		AllowWebsockets:                  src.AllowWebsockets.ValueBool(),
		AssignedPolicies:                 c.EntityInfosFromIDs(c.StringSliceFromSet(path.Root("policies"), src.Policies)),
		BearerTokenFormat:                c.BearerTokenFormat(path.Root("bearer_token_format"), src.BearerTokenFormat),
		CircuitBreakerThresholds:         c.CircuitBreakerThresholds(src.CircuitBreakerThresholds),
		CorsAllowPreflight:               false, // not supported
		CreatedAt:                        nil,   // computed
		DependsOn:                        c.StringSliceFromSet(path.Root("depends_on"), src.DependsOnHosts),
		Description:                      src.Description.ValueStringPointer(),
		EnableGoogleCloudServerlessAuthentication: src.EnableGoogleCloudServerlessAuthentication.ValueBool(),
		EnforcedPolicies:                       nil, // computed
		From:                                   src.From.ValueString(),
		HealthChecks:                           fromSetOfObjects(src.HealthChecks, HealthCheckObjectType(), c.HealthCheck),
		HealthyPanicThreshold:                  src.HealthyPanicThreshold.ValueInt32Pointer(),
		HostPathRegexRewritePattern:            src.HostPathRegexRewritePattern.ValueStringPointer(),
		HostPathRegexRewriteSubstitution:       src.HostPathRegexRewriteSubstitution.ValueStringPointer(),
		HostRewrite:                            src.HostRewrite.ValueStringPointer(),
		HostRewriteHeader:                      src.HostRewriteHeader.ValueStringPointer(),
		Id:                                     c.NullableString(src.ID),
		IdleTimeout:                            c.Duration(path.Root("idle_timeout"), src.IdleTimeout),
		IdpAccessTokenAllowedAudiences:         c.RouteStringList(path.Root("idp_access_token_allowed_audiences"), src.IDPAccessTokenAllowedAudiences),
		IdpClientId:                            src.IDPClientID.ValueStringPointer(),
		IdpClientSecret:                        src.IDPClientSecret.ValueStringPointer(),
		JwtGroupsFilter:                        c.JWTGroupsFilter(src.JWTGroupsFilter),
		JwtGroupsFilterInferFromPpl:            c.JWTGroupsFilterInferFromPpl(src.JWTGroupsFilter),
		JwtIssuerFormat:                        c.IssuerFormat(path.Root("jwt_issuer_format"), src.JWTIssuerFormat),
		KubernetesServiceAccountToken:          src.KubernetesServiceAccountToken.ValueString(),
		KubernetesServiceAccountTokenFile:      src.KubernetesServiceAccountTokenFile.ValueString(),
		KubernetesServiceAccountTokenKeyPairId: nil, // not supported
		LoadBalancingPolicy:                    c.LoadBalancingPolicy(path.Root("load_balancing_policy"), src.LoadBalancingPolicy),
		LoadBalancingWeights:                   nil, // not supported
		LogoUrl:                                src.LogoURL.ValueStringPointer(),
		Mcp:                                    c.RouteMCP(path.Root("mcp"), src.MCP),
		ModifiedAt:                             nil, // computed
		Name:                                   c.NullableString(src.Name),
		NamespaceId:                            c.NullableString(src.NamespaceID),
		NamespaceName:                          nil, // computed
		OriginatorId:                           new(OriginatorID),
		OutlierDetection:                       nil, // not supported
		PassIdentityHeaders:                    src.PassIdentityHeaders.ValueBoolPointer(),
		Path:                                   src.Path.ValueString(),
		Policies:                               nil, // not supported (uses PolicyIds)
		PolicyIds:                              c.StringSliceFromSet(path.Root("policies"), src.Policies),
		PplPolicies:                            nil, // not supported (uses PolicyIds)
		Prefix:                                 src.Prefix.ValueString(),
		PrefixRewrite:                          src.PrefixRewrite.ValueString(),
		PreserveHostHeader:                     src.PreserveHostHeader.ValueBool(),
		Redirect:                               nil, // not supported
		Regex:                                  src.Regex.ValueString(),
		RegexPriorityOrder:                     src.RegexPriorityOrder.ValueInt64Pointer(),
		RegexRewritePattern:                    src.RegexRewritePattern.ValueString(),
		RegexRewriteSubstitution:               src.RegexRewriteSubstitution.ValueString(),
		RemoveRequestHeaders:                   c.StringSliceFromSet(path.Root("remove_request_headers"), src.RemoveRequestHeaders),
		Response:                               nil, // not supported
		RewriteResponseHeaders:                 fromSetOfObjects(src.RewriteResponseHeaders, RewriteHeaderObjectType(), c.RouteRewriteHeader),
		SetRequestHeaders:                      c.StringMap(path.Root("set_request_headers"), src.SetRequestHeaders),
		SetResponseHeaders:                     c.StringMap(path.Root("set_response_headers"), src.SetResponseHeaders),
		ShowErrorDetails:                       src.ShowErrorDetails.ValueBool(),
		StatName:                               c.NullableString(src.StatName),
		Timeout:                                c.Duration(path.Root("timeout"), src.Timeout),
		TlsClientCert:                          "", // not supported
		TlsClientCertFile:                      "", // not supported
		TlsClientKey:                           "", // not supported
		TlsClientKeyFile:                       "", // not supported
		TlsClientKeyPairId:                     src.TLSClientKeyPairID.ValueStringPointer(),
		TlsCustomCa:                            "", // not supported
		TlsCustomCaFile:                        "", // not supported
		TlsCustomCaKeyPairId:                   src.TLSCustomCAKeyPairID.ValueStringPointer(),
		TlsDownstreamClientCa:                  "",  // not supported
		TlsDownstreamClientCaFile:              "",  // not supported
		TlsDownstreamClientCaKeyPairId:         nil, // not supported
		TlsDownstreamServerName:                src.TLSDownstreamServerName.ValueString(),
		TlsServerName:                          "", // not supported
		TlsSkipVerify:                          src.TLSSkipVerify.ValueBool(),
		TlsUpstreamAllowRenegotiation:          src.TLSUpstreamAllowRenegotiation.ValueBool(),
		TlsUpstreamServerName:                  src.TLSUpstreamServerName.ValueString(),
		To:                                     c.StringSliceFromSet(path.Root("to"), src.To),
		UpstreamTunnel:                         c.UpstreamTunnel(path.Root("upstream_tunnel"), src.UpstreamTunnel),
	}
}

func (c *ModelToAPIConverter) RouteMCP(p path.Path, src types.Object) *pomerium.MCP {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}
	attrs := src.Attributes()
	dst := &pomerium.MCP{Mode: nil}
	if v := getObjectAttribute(attrs, "client"); !v.IsNull() && !v.IsUnknown() {
		dst.Mode = &pomerium.MCP_Client{
			Client: c.RouteMCPClient(p.AtName("client"), v),
		}
	} else if v := getObjectAttribute(attrs, "server"); !v.IsNull() && !v.IsUnknown() {
		dst.Mode = &pomerium.MCP_Server{
			Server: c.RouteMCPServer(p.AtName("server"), v),
		}
	}
	return dst
}

func (c *ModelToAPIConverter) RouteMCPClient(_ path.Path, src types.Object) *pomerium.MCPClient {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}
	return &pomerium.MCPClient{}
}

func (c *ModelToAPIConverter) RouteMCPServer(p path.Path, src types.Object) *pomerium.MCPServer {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}
	attrs := src.Attributes()
	return &pomerium.MCPServer{
		AuthorizationServerUrl: c.NullableString(getStringAttribute(attrs, "authorization_server_url")),
		MaxRequestBytes:        c.NullableUint32(getInt64Attribute(attrs, "max_request_bytes")),
		Path:                   c.NullableString(getStringAttribute(attrs, "path")),
		UpstreamOauth2:         c.RouteMCPServerUpstreamOAuth2(p.AtName("upstream_oauth2"), getObjectAttribute(attrs, "upstream_oauth2")),
	}
}

func (c *ModelToAPIConverter) RouteMCPServerUpstreamOAuth2(p path.Path, src types.Object) *pomerium.UpstreamOAuth2 {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}
	attrs := src.Attributes()
	return &pomerium.UpstreamOAuth2{
		AuthorizationUrlParams: c.StringMap(p.AtName("authorization_url_params"), getMapAttribute(attrs, "authorization_url_params")),
		ClientId:               getStringAttribute(attrs, "client_id").ValueString(),
		ClientSecret:           getStringAttribute(attrs, "client_secret").ValueString(),
		Oauth2Endpoint:         c.RouteMCPServerUpstreamOAuth2OAuth2Endpoint(p.AtName("oauth2_endpoint"), getObjectAttribute(attrs, "oauth2_endpoint")),
		Scopes:                 c.StringSliceFromSet(p.AtName("scopes"), getSetAttribute(attrs, "scopes")),
	}
}

func (c *ModelToAPIConverter) RouteMCPServerUpstreamOAuth2OAuth2Endpoint(p path.Path, src types.Object) *pomerium.OAuth2Endpoint {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}
	attrs := src.Attributes()
	return &pomerium.OAuth2Endpoint{
		AuthStyle: c.OAuth2AuthStyle(p.AtName("auth_style"), getStringAttribute(attrs, "auth_style")),
		AuthUrl:   getStringAttribute(attrs, "auth_url").ValueString(),
		TokenUrl:  getStringAttribute(attrs, "token_url").ValueString(),
	}
}

func (c *ModelToAPIConverter) RouteRewriteHeader(src types.Object) *pomerium.RouteRewriteHeader {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	prefixAttr := src.Attributes()["prefix"].(types.String)
	dst := &pomerium.RouteRewriteHeader{
		Header:  src.Attributes()["header"].(types.String).ValueString(),
		Matcher: nil, // set below
		Value:   src.Attributes()["value"].(types.String).ValueString(),
	}
	if !prefixAttr.IsNull() && prefixAttr.ValueString() != "" {
		dst.Matcher = &pomerium.RouteRewriteHeader_Prefix{Prefix: prefixAttr.ValueString()}
	}
	return dst
}

func (c *ModelToAPIConverter) RouteStringList(p path.Path, src types.Set) *pomerium.Route_StringList {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}
	var values []string
	appendAttributeDiagnostics(c.diagnostics, p, src.ElementsAs(context.Background(), &values, false)...)
	return &pomerium.Route_StringList{Values: values}
}

func (c *ModelToAPIConverter) ServiceAccount(src ServiceAccountModel) *pomerium.ServiceAccount {
	return &pomerium.ServiceAccount{
		AccessedAt:   nil, // not supported
		CreatedAt:    nil, // not supported
		Description:  c.NullableString(src.Description),
		ExpiresAt:    c.Timestamp(path.Root("expires_at"), src.ExpiresAt),
		Id:           c.NullableString(src.ID),
		ModifiedAt:   nil, // not supported
		NamespaceId:  zeroToNil(src.NamespaceID.ValueString()),
		OriginatorId: new(OriginatorID),
		UserId:       c.NullableString(src.Name),
	}
}

func (c *ModelToAPIConverter) Settings(src SettingsModel) *pomerium.Settings {
	if !src.CacheServiceURL.IsNull() && !src.CacheServiceURL.IsUnknown() {
		c.diagnostics.AddAttributeError(path.Root("cache_service_url"), "cache_service_url is not supported by the consolidated api", "cache_service_url is not supported by the consolidated api")
	}
	if !src.CertificateAuthorityFile.IsNull() && !src.CertificateAuthorityFile.IsUnknown() {
		c.diagnostics.AddAttributeError(path.Root("certificate_authority_file"), "certificate_authority_file is not supported by the consolidated api", "certificate_authority_file is not supported by the consolidated api")
	}
	if !src.ClientCA.IsNull() && !src.ClientCA.IsUnknown() {
		c.diagnostics.AddAttributeError(path.Root("client_ca"), "client_ca is not supported by the consolidated api", "client_ca is not supported by the consolidated api")
	}
	if !src.ClientCAFile.IsNull() && !src.ClientCAFile.IsUnknown() {
		c.diagnostics.AddAttributeError(path.Root("client_ca_file"), "client_ca_file is not supported by the consolidated api", "client_ca_file is not supported by the consolidated api")
	}
	if !src.ClientCAKeyPairID.IsNull() && !src.ClientCAKeyPairID.IsUnknown() {
		c.diagnostics.AddAttributeError(path.Root("client_ca_key_pair_id"), "client_ca_key_pair_id is not supported by the consolidated api", "client_ca_key_pair_id is not supported by the consolidated api")
	}
	if !src.CookieSecure.IsNull() && !src.CookieSecure.IsUnknown() {
		c.diagnostics.AddAttributeError(path.Root("cookie_secure"), "cookie_secure is not supported by the consolidated api", "cookie_secure is not supported by the consolidated api")
	}
	if !src.IdpServiceAccount.IsNull() && !src.IdpServiceAccount.IsUnknown() {
		c.diagnostics.AddAttributeError(path.Root("idp_service_account"), "idp_service_account is not supported by the consolidated api", "idp_service_account is not supported by the consolidated api")
	}
	if !src.IdpRefreshDirectoryInterval.IsNull() && !src.IdpRefreshDirectoryInterval.IsUnknown() {
		c.diagnostics.AddAttributeError(path.Root("idp_refresh_directory_interval"), "idp_refresh_directory_interval is not supported by the consolidated api", "idp_refresh_directory_interval is not supported by the consolidated api")
	}
	if !src.IdpRefreshDirectoryTimeout.IsNull() && !src.IdpRefreshDirectoryTimeout.IsUnknown() {
		c.diagnostics.AddAttributeError(path.Root("idp_refresh_directory_timeout"), "idp_refresh_directory_timeout is not supported by the consolidated api", "idp_refresh_directory_timeout is not supported by the consolidated api")
	}
	return &pomerium.Settings{
		AccessLogFields:                   c.SettingsStringList(path.Root("access_log_fields"), src.AccessLogFields),
		Address:                           c.NullableString(src.Address),
		AuthenticateInternalServiceUrl:    nil, // not supported
		AuthenticateServiceUrl:            c.NullableString(src.AuthenticateServiceURL),
		AuthorizeInternalServiceUrl:       nil, // not supported
		AuthorizeLogFields:                c.SettingsStringList(path.Root("authorize_log_fields"), src.AuthorizeLogFields),
		AuthorizeServiceUrls:              c.StringSliceFromString(src.AuthorizeServiceURL),
		AutoApplyChangesets:               c.NullableBool(src.AutoApplyChangesets),
		Autocert:                          c.NullableBool(src.Autocert),
		AutocertCa:                        nil, // not supported
		AutocertCaKeyPairId:               nil, // not supported
		AutocertDir:                       c.NullableString(src.AutocertDir),
		AutocertEabKeyId:                  nil, // not supported
		AutocertEabMacKey:                 nil, // not supported
		AutocertEmail:                     nil, // not supported
		AutocertMustStaple:                c.NullableBool(src.AutocertMustStaple),
		AutocertTrustedCa:                 nil, // not supported
		AutocertTrustedCaKeyPairId:        nil, // not supported
		AutocertUseStaging:                c.NullableBool(src.AutocertUseStaging),
		BearerTokenFormat:                 c.BearerTokenFormat(path.Root("bearer_token_format"), src.BearerTokenFormat),
		BlobStorage:                       c.BlobStorageSettings(src.BlobStorage),
		CertificateAuthority:              c.NullableString(src.CertificateAuthority),
		CertificateAuthorityKeyPairId:     c.NullableString(src.CertificateAuthorityKeyPairID),
		CertificateKeyPairIds:             nil, // not supported
		Certificates:                      nil, // not supported
		CircuitBreakerThresholds:          c.CircuitBreakerThresholds(src.CircuitBreakerThresholds),
		ClusterId:                         c.NullableString(src.ClusterID),
		CodecType:                         c.CodecType(path.Root("codec_type"), src.CodecType),
		CookieDomain:                      c.NullableString(src.CookieDomain),
		CookieExpire:                      c.Duration(path.Root("cookie_expire"), src.CookieExpire),
		CookieHttpOnly:                    c.NullableBool(src.CookieHTTPOnly),
		CookieName:                        c.NullableString(src.CookieName),
		CookieSameSite:                    c.NullableString(src.CookieSameSite),
		CookieSecret:                      c.NullableString(src.CookieSecret),
		CreatedAt:                         nil, // not supported
		DarkmodePrimaryColor:              c.NullableString(src.DarkmodePrimaryColor),
		DarkmodeSecondaryColor:            c.NullableString(src.DarkmodeSecondaryColor),
		DatabrokerClusterLeaderId:         nil, // not supported
		DatabrokerClusterNodeId:           nil, // not supported
		DatabrokerClusterNodes:            nil, // not supported
		DatabrokerInternalServiceUrl:      nil, // not supported
		DatabrokerRaftBindAddress:         nil, // not supported
		DatabrokerServiceUrls:             c.StringSliceFromString(src.DatabrokerServiceURL),
		DatabrokerStorageConnectionString: c.NullableString(src.DatabrokerStorageConnectionString),
		DatabrokerStorageType:             nil, // not supported
		DebugAddress:                      nil, // not supported
		DefaultUpstreamTimeout:            c.Duration(path.Root("default_upstream_timeout"), src.DefaultUpstreamTimeout),
		DeriveTls:                         nil, // not supported
		DirectoryProvider:                 c.DirectoryProvider(src),
		DirectoryProviderOptions:          c.DirectoryProviderOptions(src),
		DirectoryProviderRefreshInterval:  c.Duration(path.Root("identity_provider_refresh_interval"), src.IdentityProviderRefreshInterval),
		DirectoryProviderRefreshTimeout:   c.Duration(path.Root("identity_provider_refresh_timeout"), src.IdentityProviderRefreshTimeout),
		DnsFailureRefreshRate:             c.Duration(path.Root("dns_failure_refresh_rate"), src.DNSFailureRefreshRate),
		DnsLookupFamily:                   c.NullableString(src.DNSLookupFamily),
		DnsQueryTimeout:                   c.Duration(path.Root("dns_query_timeout"), src.DNSQueryTimeout),
		DnsQueryTries:                     c.NullableUint32(src.DNSQueryTries),
		DnsRefreshRate:                    c.Duration(path.Root("dns_refresh_rate"), src.DNSRefreshRate),
		DnsUdpMaxQueries:                  c.NullableUint32(src.DNSUDPMaxQueries),
		DnsUseTcp:                         c.NullableBool(src.DNSUseTCP),
		DownstreamMtls:                    nil, // not supported
		EnvoyAdminAccessLogPath:           nil, // not supported
		EnvoyAdminAddress:                 nil, // not supported
		EnvoyAdminProfilePath:             nil, // not supported
		EnvoyBindConfigFreebind:           nil, // not supported
		EnvoyBindConfigSourceAddress:      nil, // not supported
		ErrorMessageFirstParagraph:        c.NullableString(src.ErrorMessageFirstParagraph),
		FaviconUrl:                        c.NullableString(src.FaviconURL),
		GoogleCloudServerlessAuthenticationServiceAccount: c.NullableString(src.GoogleCloudServerlessAuthenticationServiceAccount),
		GrpcAddress:                         c.NullableString(src.GRPCAddress),
		GrpcClientTimeout:                   nil, // not supported
		GrpcInsecure:                        c.NullableBool(src.GRPCInsecure),
		Http3AdvertisePort:                  nil, // not supported
		HttpRedirectAddr:                    c.NullableString(src.HTTPRedirectAddr),
		Id:                                  c.NullableString(src.ID),
		IdpAccessTokenAllowedAudiences:      c.SettingsStringList(path.Root("idp_access_token_allowed_audiences"), src.IDPAccessTokenAllowedAudiences),
		IdpClientId:                         c.NullableString(src.IdpClientID),
		IdpClientSecret:                     c.NullableString(src.IdpClientSecret),
		IdpProvider:                         c.NullableString(src.IdpProvider),
		IdpProviderUrl:                      c.NullableString(src.IdpProviderURL),
		InsecureServer:                      c.NullableBool(src.InsecureServer),
		InstallationId:                      c.NullableString(src.InstallationID),
		JwtClaimsHeaders:                    c.StringMap(path.Root("jwt_claims_headers"), src.JWTClaimsHeaders),
		JwtGroupsFilter:                     c.JWTGroupsFilter(src.JWTGroupsFilter),
		JwtGroupsFilterInferFromPpl:         c.JWTGroupsFilterInferFromPpl(src.JWTGroupsFilter),
		JwtIssuerFormat:                     c.IssuerFormat(path.Root("jwt_issuer_format"), src.JWTIssuerFormat),
		LogLevel:                            c.NullableString(src.LogLevel),
		LogoUrl:                             c.NullableString(src.LogoURL),
		McpAllowedAsMetadataDomains:         c.StringSliceFromSet(path.Root("mcp_allowed_as_metadata_domains"), src.MCPAllowedAsMetadataDomains),
		McpAllowedClientIdDomains:           c.StringSliceFromSet(path.Root("mcp_allowed_client_id_domains"), src.MCPAllowedClientIDDomains),
		MetricsAddress:                      c.NullableString(src.MetricsAddress),
		MetricsBasicAuth:                    nil, // not supported
		MetricsCertificate:                  nil, // not supported
		MetricsClientCa:                     nil, // not supported
		MetricsClientCaKeyPairId:            nil, // not supported
		ModifiedAt:                          nil, // not supported
		Name:                                nil, // not supported
		NamespaceId:                         c.NullableString(src.NamespaceID),
		OriginatorId:                        new(OriginatorID),
		OtelAttributeValueLengthLimit:       c.NullableInt32(src.OtelAttributeValueLengthLimit),
		OtelBspMaxExportBatchSize:           c.NullableInt32(src.OtelBspMaxExportBatchSize),
		OtelBspScheduleDelay:                c.Duration(path.Root("otel_bsp_schedule_delay"), src.OtelBspScheduleDelay),
		OtelExporterOtlpEndpoint:            c.NullableString(src.OtelExporterOtlpEndpoint),
		OtelExporterOtlpHeaders:             c.StringSliceFromSet(path.Root("otel_exporter_otlp_headers"), src.OtelExporterOtlpHeaders),
		OtelExporterOtlpProtocol:            c.NullableString(src.OtelExporterOtlpProtocol),
		OtelExporterOtlpTimeout:             c.Duration(path.Root("otel_exporter_otlp_timeout"), src.OtelExporterOtlpTimeout),
		OtelExporterOtlpTracesEndpoint:      c.NullableString(src.OtelExporterOtlpTracesEndpoint),
		OtelExporterOtlpTracesHeaders:       c.StringSliceFromSet(path.Root("otel_exporter_otlp_traces_headers"), src.OtelExporterOtlpTracesHeaders),
		OtelExporterOtlpTracesProtocol:      c.NullableString(src.OtelExporterOtlpTracesProtocol),
		OtelExporterOtlpTracesTimeout:       c.Duration(path.Root("otel_exporter_otlp_traces_timeout"), src.OtelExporterOtlpTracesTimeout),
		OtelLogLevel:                        c.NullableString(src.OtelLogLevel),
		OtelResourceAttributes:              c.StringSliceFromSet(path.Root("otel_resource_attributes"), src.OtelResourceAttributes),
		OtelTracesExporter:                  c.NullableString(src.OtelTracesExporter),
		OtelTracesSamplerArg:                c.NullableFloat64(src.OtelTracesSamplerArg),
		OverrideCertificateName:             nil, // not supported
		PassIdentityHeaders:                 c.NullableBool(src.PassIdentityHeaders),
		PrimaryColor:                        c.NullableString(src.PrimaryColor),
		ProgrammaticRedirectDomainWhitelist: nil, // not supported
		ProxyLogLevel:                       c.NullableString(src.ProxyLogLevel),
		RequestParams:                       c.StringMap(path.Root("request_params"), src.RequestParams),
		RuntimeFlags:                        nil, // not supported
		Scopes:                              c.StringSliceFromSet(path.Root("scopes"), src.Scopes),
		SecondaryColor:                      c.NullableString(src.SecondaryColor),
		Services:                            nil, // not supported
		SessionRecordingEnabled:             c.NullableBool(src.SessionRecordingEnabled),
		SetResponseHeaders:                  c.StringMap(path.Root("set_response_headers"), src.SetResponseHeaders),
		SharedSecret:                        nil, // not supported
		SigningKey:                          nil, // not supported
		SignoutRedirectUrl:                  nil, // not supported
		SkipXffAppend:                       c.NullableBool(src.SkipXFFAppend),
		SshAddress:                          c.NullableString(src.SSHAddress),
		SshHostKeyFiles:                     c.SettingsStringList(path.Root("ssh_host_key_files"), src.SSHHostKeyFiles),
		SshHostKeyPairIds:                   nil, // not supported
		SshHostKeys:                         c.SettingsStringList(path.Root("ssh_host_keys"), src.SSHHostKeys),
		SshUserCaKey:                        c.NullableString(src.SSHUserCAKey),
		SshUserCaKeyFile:                    c.NullableString(src.SSHUserCAKeyFile),
		SshUserCaKeyPairId:                  nil, // not supported
		TimeoutIdle:                         c.Duration(path.Root("timeout_idle"), src.TimeoutIdle),
		TimeoutRead:                         c.Duration(path.Root("timeout_read"), src.TimeoutRead),
		TimeoutWrite:                        c.Duration(path.Root("timeout_write"), src.TimeoutWrite),
		UseProxyProtocol:                    nil, // not supported
		XffNumTrustedHops:                   nil, // not supported
	}
}

func (c *ModelToAPIConverter) SettingsStringList(p path.Path, src types.Set) *pomerium.Settings_StringList {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}
	var values []string
	appendAttributeDiagnostics(c.diagnostics, p, src.ElementsAs(context.Background(), &values, false)...)
	return &pomerium.Settings_StringList{Values: values}
}

func (c *ModelToAPIConverter) UpstreamTunnel(p path.Path, src types.Object) *pomerium.UpstreamTunnel {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	dst := new(pomerium.UpstreamTunnel)
	for k, v := range src.Attributes() {
		switch k {
		case "ssh_policy":
			str, ok := v.(types.String)
			if ok {
				dst.SshPolicyId = str.ValueStringPointer()
			} else {
				c.diagnostics.AddAttributeError(p.AtName("ssh_policy"), "unexpected type for field", fmt.Sprintf("unexpected type for field: %T", v))
			}
		default:
			c.diagnostics.AddAttributeError(p, "unknown object field", fmt.Sprintf("unknown object field: %s", k))
		}
	}
	return dst
}
