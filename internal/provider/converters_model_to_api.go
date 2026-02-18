package provider

import (
	"context"
	"encoding/base64"

	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

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
		Timeout:               c.Duration(path.Root("timeout"), timeout),
		Interval:              c.Duration(path.Root("interval"), interval),
		InitialJitter:         c.Duration(path.Root("initial_jitter"), initialJitter),
		IntervalJitter:        c.Duration(path.Root("interval_jitter"), intervalJitter),
		IntervalJitterPercent: uint32(intervalJitterPercent.ValueInt64()),
		UnhealthyThreshold:    wrapperspb.UInt32(uint32(unhealthyThreshold.ValueInt64())),
		HealthyThreshold:      wrapperspb.UInt32(uint32(healthyThreshold.ValueInt64())),
	}

	httpHc := attrs["http_health_check"].(types.Object)
	tcpHc := attrs["tcp_health_check"].(types.Object)
	grpcHc := attrs["grpc_health_check"].(types.Object)

	if !httpHc.IsNull() {
		httpAttrs := httpHc.Attributes()
		httpHealthCheck := &pomerium.HealthCheck_HttpHealthCheck{}

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
		tcpHealthCheck := &pomerium.HealthCheck_TcpHealthCheck{}

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
		grpcHealthCheck := &pomerium.HealthCheck_GrpcHealthCheck{}

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
		OriginatorId:    proto.String(OriginatorID),
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
		Description:      proto.String(src.Description.ValueString()),
		Enforced:         proto.Bool(src.Enforced.ValueBool()),
		EnforcedRoutes:   nil, // not supported
		Explanation:      proto.String(src.Explanation.ValueString()),
		Id:               c.NullableString(src.ID),
		ModifiedAt:       nil, // not supported
		Name:             proto.String(src.Name.ValueString()),
		NamespaceId:      c.NullableString(src.NamespaceID),
		NamespaceName:    nil, // not supported
		OriginatorId:     proto.String(OriginatorID),
		Rego:             c.StringSliceFromList(path.Root("rego"), src.Rego),
		Remediation:      proto.String(src.Remediation.ValueString()),
		SourcePpl:        proto.String(string(src.PPL.PolicyJSON)),
	}
}

func (c *ModelToAPIConverter) Route(src RouteModel) *pomerium.Route {
	return &pomerium.Route{
		AllowSpdy:                src.AllowSPDY.ValueBool(),
		AllowWebsockets:          src.AllowWebsockets.ValueBool(),
		BearerTokenFormat:        c.BearerTokenFormat(path.Root("bearer_token_format"), src.BearerTokenFormat),
		CircuitBreakerThresholds: c.CircuitBreakerThresholds(src.CircuitBreakerThresholds),
		DependsOn:                c.StringSliceFromSet(path.Root("depends_on"), src.DependsOnHosts),
		Description:              src.Description.ValueStringPointer(),
		EnableGoogleCloudServerlessAuthentication: src.EnableGoogleCloudServerlessAuthentication.ValueBool(),
		From:                              src.From.ValueString(),
		HealthChecks:                      fromSetOfObjects(src.HealthChecks, HealthCheckObjectType(), c.HealthCheck),
		HealthyPanicThreshold:             src.HealthyPanicThreshold.ValueInt32Pointer(),
		HostPathRegexRewritePattern:       src.HostPathRegexRewritePattern.ValueStringPointer(),
		HostPathRegexRewriteSubstitution:  src.HostPathRegexRewriteSubstitution.ValueStringPointer(),
		HostRewrite:                       src.HostRewrite.ValueStringPointer(),
		HostRewriteHeader:                 src.HostRewriteHeader.ValueStringPointer(),
		Id:                                c.NullableString(src.ID),
		IdleTimeout:                       c.Duration(path.Root("idle_timeout"), src.IdleTimeout),
		IdpAccessTokenAllowedAudiences:    c.RouteStringList(path.Root("idp_access_token_allowed_audiences"), src.IDPAccessTokenAllowedAudiences),
		IdpClientId:                       src.IDPClientID.ValueStringPointer(),
		IdpClientSecret:                   src.IDPClientSecret.ValueStringPointer(),
		JwtGroupsFilter:                   c.JWTGroupsFilter(src.JWTGroupsFilter),
		JwtIssuerFormat:                   c.IssuerFormat(path.Root("jwt_issuer_format"), src.JWTIssuerFormat),
		KubernetesServiceAccountToken:     src.KubernetesServiceAccountToken.ValueString(),
		KubernetesServiceAccountTokenFile: src.KubernetesServiceAccountTokenFile.ValueString(),
		LoadBalancingPolicy:               c.LoadBalancingPolicy(path.Root("load_balancing_policy"), src.LoadBalancingPolicy),
		LogoUrl:                           src.LogoURL.ValueStringPointer(),
		Name:                              c.NullableString(src.Name),
		NamespaceId:                       c.NullableString(src.NamespaceID),
		OriginatorId:                      proto.String(OriginatorID),
		PassIdentityHeaders:               src.PassIdentityHeaders.ValueBoolPointer(),
		Path:                              src.Path.ValueString(),
		PolicyIds:                         c.StringSliceFromSet(path.Root("policies"), src.Policies),
		Prefix:                            src.Prefix.ValueString(),
		PrefixRewrite:                     src.PrefixRewrite.ValueString(),
		PreserveHostHeader:                src.PreserveHostHeader.ValueBool(),
		Regex:                             src.Regex.ValueString(),
		RegexPriorityOrder:                src.RegexPriorityOrder.ValueInt64Pointer(),
		RegexRewritePattern:               src.RegexRewritePattern.ValueString(),
		RegexRewriteSubstitution:          src.RegexRewriteSubstitution.ValueString(),
		RemoveRequestHeaders:              c.StringSliceFromSet(path.Root("remove_request_headers"), src.RemoveRequestHeaders),
		RewriteResponseHeaders:            fromSetOfObjects(src.RewriteResponseHeaders, RewriteHeaderObjectType(), c.RouteRewriteHeader),
		SetRequestHeaders:                 c.StringMap(path.Root("set_request_headers"), src.SetRequestHeaders),
		SetResponseHeaders:                c.StringMap(path.Root("set_response_headers"), src.SetResponseHeaders),
		ShowErrorDetails:                  src.ShowErrorDetails.ValueBool(),
		StatName:                          c.NullableString(src.StatName),
		Timeout:                           c.Duration(path.Root("timeout"), src.Timeout),
		TlsClientKeyPairId:                src.TLSClientKeyPairID.ValueStringPointer(),
		TlsCustomCaKeyPairId:              src.TLSCustomCAKeyPairID.ValueStringPointer(),
		TlsDownstreamServerName:           src.TLSDownstreamServerName.ValueString(),
		TlsSkipVerify:                     src.TLSSkipVerify.ValueBool(),
		TlsUpstreamAllowRenegotiation:     src.TLSUpstreamAllowRenegotiation.ValueBool(),
		TlsUpstreamServerName:             src.TLSUpstreamServerName.ValueString(),
		To:                                c.StringSliceFromSet(path.Root("to"), src.To),
	}
}

func (c *ModelToAPIConverter) RouteRewriteHeader(src types.Object) *pomerium.RouteRewriteHeader {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	prefixAttr := src.Attributes()["prefix"].(types.String)
	dst := &pomerium.RouteRewriteHeader{
		Header: src.Attributes()["header"].(types.String).ValueString(),
		Value:  src.Attributes()["value"].(types.String).ValueString(),
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
		OriginatorId: proto.String(OriginatorID),
		UserId:       c.NullableString(src.UserID),
	}
}

func (c *ModelToAPIConverter) Settings(src SettingsModel) *pomerium.Settings {
	return &pomerium.Settings{
		AccessLogFields:                   c.SettingsStringList(path.Root("access_log_fields"), src.AccessLogFields),
		Address:                           src.Address.ValueStringPointer(),
		AuthenticateInternalServiceUrl:    nil, // not supported
		AuthenticateServiceUrl:            src.AuthenticateServiceURL.ValueStringPointer(),
		AuthorizeInternalServiceUrl:       nil, // not supported
		AuthorizeLogFields:                c.SettingsStringList(path.Root("authorize_log_fields"), src.AuthorizeLogFields),
		AuthorizeServiceUrls:              c.StringSliceFromString(src.AuthorizeServiceURL),
		Autocert:                          src.Autocert.ValueBoolPointer(),
		AutocertCa:                        nil, // not supported
		AutocertCaKeyPairId:               nil, // not supported
		AutocertDir:                       src.AutocertDir.ValueStringPointer(),
		AutocertEabKeyId:                  nil, // not supported
		AutocertEabMacKey:                 nil, // not supported
		AutocertEmail:                     nil, // not supported
		AutocertMustStaple:                src.AutocertMustStaple.ValueBoolPointer(),
		AutocertTrustedCa:                 nil, // not supported
		AutocertTrustedCaKeyPairId:        nil, // not supported
		AutocertUseStaging:                src.AutocertUseStaging.ValueBoolPointer(),
		BearerTokenFormat:                 c.BearerTokenFormat(path.Root("bearer_token_format"), src.BearerTokenFormat),
		CertificateAuthority:              src.CertificateAuthority.ValueStringPointer(),
		CertificateAuthorityKeyPairId:     src.CertificateAuthorityKeyPairID.ValueStringPointer(),
		CertificateKeyPairIds:             nil, // not supported
		Certificates:                      nil, // not supported
		CircuitBreakerThresholds:          c.CircuitBreakerThresholds(src.CircuitBreakerThresholds),
		ClusterId:                         src.ClusterID.ValueStringPointer(),
		CodecType:                         c.CodecType(path.Root("codec_type"), src.CodecType),
		CookieDomain:                      src.CookieDomain.ValueStringPointer(),
		CookieExpire:                      c.Duration(path.Root("cookie_expire"), src.CookieExpire),
		CookieHttpOnly:                    src.CookieHTTPOnly.ValueBoolPointer(),
		CookieName:                        src.CookieName.ValueStringPointer(),
		CookieSameSite:                    src.CookieSameSite.ValueStringPointer(),
		CookieSecret:                      src.CookieSecret.ValueStringPointer(),
		CreatedAt:                         nil, // not supported
		DarkmodePrimaryColor:              src.DarkmodePrimaryColor.ValueStringPointer(),
		DarkmodeSecondaryColor:            src.DarkmodeSecondaryColor.ValueStringPointer(),
		DatabrokerClusterLeaderId:         nil, // not supported
		DatabrokerClusterNodeId:           nil, // not supported
		DatabrokerClusterNodes:            nil, // not supported
		DatabrokerInternalServiceUrl:      nil, // not supported
		DatabrokerRaftBindAddress:         nil, // not supported
		DatabrokerServiceUrls:             c.StringSliceFromString(src.DatabrokerServiceURL),
		DatabrokerStorageConnectionString: nil, // not supported
		DatabrokerStorageType:             nil, // not supported
		DebugAddress:                      nil, // not supported
		DefaultUpstreamTimeout:            c.Duration(path.Root("default_upstream_timeout"), src.DefaultUpstreamTimeout),
		DeriveTls:                         nil, // not supported
		DirectoryProvider:                 c.DirectoryProvider(src),
		DirectoryProviderOptions:          c.DirectoryProviderOptions(src),
		DirectoryProviderRefreshInterval:  c.Duration(path.Root("identity_provider_refresh_interval"), src.IdentityProviderRefreshInterval),
		DirectoryProviderRefreshTimeout:   c.Duration(path.Root("identity_provider_refresh_timeout"), src.IdentityProviderRefreshTimeout),
		DnsFailureRefreshRate:             c.Duration(path.Root("dns_failure_refresh_rate"), src.DNSFailureRefreshRate),
		DnsLookupFamily:                   src.DNSLookupFamily.ValueStringPointer(),
		DnsQueryTimeout:                   c.Duration(path.Root("dns_query_timeout"), src.DNSQueryTimeout),
		DnsQueryTries:                     c.NullableUint32(src.DNSQueryTries),
		DnsRefreshRate:                    c.Duration(path.Root("dns_refresh_rate"), src.DNSRefreshRate),
		DnsUdpMaxQueries:                  c.NullableUint32(src.DNSUDPMaxQueries),
		DnsUseTcp:                         src.DNSUseTCP.ValueBoolPointer(),
		DownstreamMtls:                    nil, // not supported
		EnvoyAdminAccessLogPath:           nil, // not supported
		EnvoyAdminAddress:                 nil, // not supported
		EnvoyAdminProfilePath:             nil, // not supported
		EnvoyBindConfigFreebind:           nil, // not supported
		EnvoyBindConfigSourceAddress:      nil, // not supported
		ErrorMessageFirstParagraph:        src.ErrorMessageFirstParagraph.ValueStringPointer(),
		FaviconUrl:                        src.FaviconURL.ValueStringPointer(),
		GoogleCloudServerlessAuthenticationServiceAccount: src.GoogleCloudServerlessAuthenticationServiceAccount.ValueStringPointer(),
		GrpcAddress:                         src.GRPCAddress.ValueStringPointer(),
		GrpcClientTimeout:                   nil, // not supported
		GrpcInsecure:                        src.GRPCInsecure.ValueBoolPointer(),
		Http3AdvertisePort:                  nil, // not supported
		HttpRedirectAddr:                    src.HTTPRedirectAddr.ValueStringPointer(),
		Id:                                  c.NullableString(src.ID),
		IdpAccessTokenAllowedAudiences:      c.SettingsStringList(path.Root("idp_access_token_allowed_audiences"), src.IDPAccessTokenAllowedAudiences),
		IdpClientId:                         src.IdpClientID.ValueStringPointer(),
		IdpClientSecret:                     src.IdpClientSecret.ValueStringPointer(),
		IdpProvider:                         src.IdpProvider.ValueStringPointer(),
		IdpProviderUrl:                      src.IdpProviderURL.ValueStringPointer(),
		InsecureServer:                      src.InsecureServer.ValueBoolPointer(),
		InstallationId:                      src.InstallationID.ValueStringPointer(),
		JwtClaimsHeaders:                    c.StringMap(path.Root("jwt_claims_headers"), src.JWTClaimsHeaders),
		JwtGroupsFilter:                     c.JWTGroupsFilter(src.JWTGroupsFilter),
		JwtGroupsFilterInferFromPpl:         c.JWTGroupsFilterInferFromPpl(src.JWTGroupsFilter),
		JwtIssuerFormat:                     c.IssuerFormat(path.Root("jwt_issuer_format"), src.JWTIssuerFormat),
		LogLevel:                            src.LogLevel.ValueStringPointer(),
		LogoUrl:                             src.LogoURL.ValueStringPointer(),
		McpAllowedClientIdDomains:           nil, // not supported
		MetricsAddress:                      src.MetricsAddress.ValueStringPointer(),
		MetricsBasicAuth:                    nil, // not supported
		MetricsCertificate:                  nil, // not supported
		MetricsClientCa:                     nil, // not supported
		MetricsClientCaKeyPairId:            nil, // not supported
		ModifiedAt:                          nil, // not supported
		Name:                                nil, // not supported
		NamespaceId:                         nil, // not supported
		OriginatorId:                        proto.String(OriginatorID),
		OtelAttributeValueLengthLimit:       c.NullableInt32(src.OtelAttributeValueLengthLimit),
		OtelBspMaxExportBatchSize:           c.NullableInt32(src.OtelBspMaxExportBatchSize),
		OtelBspScheduleDelay:                c.Duration(path.Root("otel_bsp_schedule_delay"), src.OtelBspScheduleDelay),
		OtelExporterOtlpEndpoint:            src.OtelExporterOtlpEndpoint.ValueStringPointer(),
		OtelExporterOtlpHeaders:             c.StringSliceFromSet(path.Root("otel_exporter_otlp_headers"), src.OtelExporterOtlpHeaders),
		OtelExporterOtlpProtocol:            src.OtelExporterOtlpProtocol.ValueStringPointer(),
		OtelExporterOtlpTimeout:             c.Duration(path.Root("otel_exporter_otlp_timeout"), src.OtelExporterOtlpTimeout),
		OtelExporterOtlpTracesEndpoint:      src.OtelExporterOtlpTracesEndpoint.ValueStringPointer(),
		OtelExporterOtlpTracesHeaders:       c.StringSliceFromSet(path.Root("otel_exporter_otlp_traces_headers"), src.OtelExporterOtlpTracesHeaders),
		OtelExporterOtlpTracesProtocol:      src.OtelExporterOtlpTracesProtocol.ValueStringPointer(),
		OtelExporterOtlpTracesTimeout:       c.Duration(path.Root("otel_exporter_otlp_traces_timeout"), src.OtelExporterOtlpTracesTimeout),
		OtelLogLevel:                        src.OtelLogLevel.ValueStringPointer(),
		OtelResourceAttributes:              c.StringSliceFromSet(path.Root("otel_resource_attributes"), src.OtelResourceAttributes),
		OtelTracesExporter:                  src.OtelTracesExporter.ValueStringPointer(),
		OtelTracesSamplerArg:                src.OtelTracesSamplerArg.ValueFloat64Pointer(),
		OverrideCertificateName:             nil, // not supported
		PassIdentityHeaders:                 src.PassIdentityHeaders.ValueBoolPointer(),
		PrimaryColor:                        src.PrimaryColor.ValueStringPointer(),
		ProgrammaticRedirectDomainWhitelist: nil, // not supported
		ProxyLogLevel:                       src.ProxyLogLevel.ValueStringPointer(),
		RequestParams:                       c.StringMap(path.Root("request_params"), src.RequestParams),
		RuntimeFlags:                        nil, // not supported
		Scopes:                              c.StringSliceFromSet(path.Root("scopes"), src.Scopes),
		SecondaryColor:                      src.SecondaryColor.ValueStringPointer(),
		Services:                            nil, // not supported
		SetResponseHeaders:                  c.StringMap(path.Root("set_response_headers"), src.SetResponseHeaders),
		SharedSecret:                        nil, // not supported
		SigningKey:                          nil, // not supported
		SignoutRedirectUrl:                  nil, // not supported
		SkipXffAppend:                       src.SkipXFFAppend.ValueBoolPointer(),
		SshAddress:                          src.SSHAddress.ValueStringPointer(),
		SshHostKeyFiles:                     c.SettingsStringList(path.Root("ssh_host_key_files"), src.SSHHostKeyFiles),
		SshHostKeyPairIds:                   nil, // not supported
		SshHostKeys:                         c.SettingsStringList(path.Root("ssh_host_keys"), src.SSHHostKeys),
		SshUserCaKey:                        src.SSHUserCAKey.ValueStringPointer(),
		SshUserCaKeyFile:                    src.SSHUserCAKeyFile.ValueStringPointer(),
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
