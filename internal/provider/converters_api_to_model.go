package provider

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pomerium/sdk-go/proto/pomerium"
)

type APIToModelConverter struct {
	baseProtoConverter
	diagnostics *diag.Diagnostics
}

func NewAPIToModelConverter(diagnostics *diag.Diagnostics) *APIToModelConverter {
	return &APIToModelConverter{
		baseProtoConverter: baseProtoConverter{
			diagnostics: diagnostics,
		},
		diagnostics: diagnostics,
	}
}

func (c *APIToModelConverter) CircuitBreakerThresholds(src *pomerium.CircuitBreakerThresholds) types.Object {
	if src == nil {
		return types.ObjectNull(CircuitBreakerThresholdsObjectType().AttrTypes)
	}

	dst, diagnostics := types.ObjectValue(CircuitBreakerThresholdsObjectType().AttrTypes, map[string]attr.Value{
		"max_connections":      Int64PointerValue(src.MaxConnections),
		"max_pending_requests": Int64PointerValue(src.MaxPendingRequests),
		"max_requests":         Int64PointerValue(src.MaxRequests),
		"max_retries":          Int64PointerValue(src.MaxRetries),
		"max_connection_pools": Int64PointerValue(src.MaxConnectionPools),
	})
	c.diagnostics.Append(diagnostics...)
	return dst
}

func (c *APIToModelConverter) HealthCheck(src *pomerium.HealthCheck) types.Object {
	if src == nil {
		return types.ObjectNull(HealthCheckObjectType().AttrTypes)
	}

	attrs := map[string]attr.Value{
		"timeout":                 c.Duration(src.Timeout),
		"interval":                c.Duration(src.Interval),
		"initial_jitter":          c.Duration(src.InitialJitter),
		"interval_jitter":         c.Duration(src.IntervalJitter),
		"interval_jitter_percent": UInt32ToInt64OrNull(src.IntervalJitterPercent),
		"unhealthy_threshold":     UInt32ToInt64OrNull(src.GetUnhealthyThreshold().GetValue()),
		"healthy_threshold":       UInt32ToInt64OrNull(src.GetHealthyThreshold().GetValue()),
		"http_health_check":       types.ObjectNull(HTTPHealthCheckObjectType().AttrTypes),
		"tcp_health_check":        types.ObjectNull(TCPHealthCheckObjectType().AttrTypes),
		"grpc_health_check":       types.ObjectNull(GrpcHealthCheckObjectType().AttrTypes),
	}

	if httpHc := src.GetHttpHealthCheck(); httpHc != nil {
		expectedStatusesElem := []attr.Value{}
		for _, status := range httpHc.ExpectedStatuses {
			expectedStatusesElem = append(expectedStatusesElem, c.HealthCheckInt64Range(status))
		}
		expectedStatuses, _ := types.SetValue(Int64RangeObjectType(), expectedStatusesElem)

		retriableStatusesElem := []attr.Value{}
		for _, status := range httpHc.RetriableStatuses {
			retriableStatusesElem = append(retriableStatusesElem, c.HealthCheckInt64Range(status))
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
	} else if tcpHc := src.GetTcpHealthCheck(); tcpHc != nil {
		sendPayload := c.HealthCheckPayload(tcpHc.Send)

		receiveElements := []attr.Value{}
		for _, payload := range tcpHc.Receive {
			payloadObj := c.HealthCheckPayload(payload)
			receiveElements = append(receiveElements, payloadObj)
		}
		receiveSet, _ := types.SetValue(HealthCheckPayloadObjectType(), receiveElements)

		tcpAttrs := map[string]attr.Value{
			"send":    sendPayload,
			"receive": receiveSet,
		}

		tcpHealthCheck, _ := types.ObjectValue(TCPHealthCheckObjectType().AttrTypes, tcpAttrs)
		attrs["tcp_health_check"] = tcpHealthCheck
	} else if grpcHc := src.GetGrpcHealthCheck(); grpcHc != nil {
		grpcAttrs := map[string]attr.Value{
			"service_name": types.StringValue(grpcHc.ServiceName),
			"authority":    types.StringValue(grpcHc.Authority),
		}

		grpcHealthCheck, _ := types.ObjectValue(GrpcHealthCheckObjectType().AttrTypes, grpcAttrs)
		attrs["grpc_health_check"] = grpcHealthCheck
	} else {
		c.diagnostics.AddAttributeError(path.Root("health_checks"), "health check not specified", "must specify one of http_health_check, tcp_health_check, or grpc_health_check")
	}

	dst, diagnostics := types.ObjectValue(HealthCheckObjectType().AttrTypes, attrs)
	c.diagnostics.Append(diagnostics...)
	return dst
}

func (c *APIToModelConverter) HealthCheckPayload(src *pomerium.HealthCheck_Payload) types.Object {
	if src == nil {
		return types.ObjectNull(HealthCheckPayloadObjectType().AttrTypes)
	}

	attrs := map[string]attr.Value{
		"text":       types.StringNull(),
		"binary_b64": types.StringNull(),
	}

	switch p := src.GetPayload().(type) {
	case *pomerium.HealthCheck_Payload_Text:
		attrs["text"] = types.StringValue(p.Text)
	case *pomerium.HealthCheck_Payload_Binary:
		attrs["binary_b64"] = types.StringValue(base64.StdEncoding.EncodeToString(p.Binary))
	}

	return types.ObjectValueMust(HealthCheckPayloadObjectType().AttrTypes, attrs)
}

func (c *APIToModelConverter) HealthCheckInt64Range(src *pomerium.HealthCheck_Int64Range) types.Object {
	if src == nil {
		return types.ObjectNull(Int64RangeObjectType().AttrTypes)
	}
	return types.ObjectValueMust(Int64RangeObjectType().AttrTypes, map[string]attr.Value{
		"start": types.Int64Value(src.Start),
		"end":   types.Int64Value(src.End),
	})
}

func (c *APIToModelConverter) JWTGroupsFilter(src []string, inferFromPPL *bool) types.Object {
	if src == nil && inferFromPPL == nil {
		return types.ObjectNull(JWTGroupsFilterObjectType().AttrTypes)
	}

	attrs := make(map[string]attr.Value)
	if src == nil {
		attrs["groups"] = types.SetNull(types.StringType)
	} else {
		var vals []attr.Value
		for _, v := range src {
			vals = append(vals, types.StringValue(v))
		}
		attrs["groups"] = types.SetValueMust(types.StringType, vals)
	}

	attrs["infer_from_ppl"] = types.BoolPointerValue(inferFromPPL)

	return types.ObjectValueMust(JWTGroupsFilterObjectType().AttrTypes, attrs)
}

func (c *APIToModelConverter) KeyPair(src *pomerium.KeyPair) KeyPairModel {
	return KeyPairModel{
		Certificate: c.StringFromBytes(src.Certificate),
		ID:          types.StringPointerValue(src.Id),
		Key:         c.StringFromBytes(src.Key),
		Name:        types.StringPointerValue(src.Name),
		NamespaceID: types.StringPointerValue(src.NamespaceId),
	}
}

func (c *APIToModelConverter) Policy(src *pomerium.Policy) PolicyModel {
	ppl, err := PolicyLanguageType{}.Parse(types.StringPointerValue(src.SourcePpl))
	if err != nil {
		c.diagnostics.AddError("error parsing ppl", err.Error())
	}
	return PolicyModel{
		Description: types.StringValue(src.GetDescription()),
		Enforced:    types.BoolValue(src.GetEnforced()),
		Explanation: types.StringValue(src.GetExplanation()),
		ID:          types.StringPointerValue(src.Id),
		Name:        types.StringPointerValue(src.Name),
		NamespaceID: types.StringPointerValue(src.NamespaceId),
		PPL:         ppl,
		Rego:        FromStringSliceToList(src.Rego),
		Remediation: types.StringValue(src.GetRemediation()),
	}
}

func (c *APIToModelConverter) Route(src *pomerium.Route) RouteModel {
	return RouteModel{
		AllowSPDY:                types.BoolValue(src.AllowSpdy),
		AllowWebsockets:          types.BoolValue(src.AllowWebsockets),
		BearerTokenFormat:        c.BearerTokenFormat(src.BearerTokenFormat),
		CircuitBreakerThresholds: c.CircuitBreakerThresholds(src.CircuitBreakerThresholds),
		DependsOnHosts:           FromStringSliceToSet(src.DependsOn),
		Description:              types.StringPointerValue(src.Description),
		EnableGoogleCloudServerlessAuthentication: types.BoolPointerValue(zeroToNil(src.EnableGoogleCloudServerlessAuthentication)),
		From:                              types.StringValue(src.From),
		HealthChecks:                      toSetOfObjects(src.HealthChecks, HealthCheckObjectType(), c.HealthCheck),
		HealthyPanicThreshold:             types.Int32PointerValue(src.HealthyPanicThreshold),
		HostPathRegexRewritePattern:       types.StringPointerValue(src.HostPathRegexRewritePattern),
		HostPathRegexRewriteSubstitution:  types.StringPointerValue(src.HostPathRegexRewriteSubstitution),
		HostRewrite:                       types.StringPointerValue(src.HostRewrite),
		HostRewriteHeader:                 types.StringPointerValue(src.HostRewriteHeader),
		ID:                                types.StringPointerValue(src.Id),
		IdleTimeout:                       c.Duration(src.IdleTimeout),
		IDPAccessTokenAllowedAudiences:    FromStringList(src.IdpAccessTokenAllowedAudiences),
		IDPClientID:                       types.StringPointerValue(src.IdpClientId),
		IDPClientSecret:                   types.StringPointerValue(src.IdpClientSecret),
		JWTGroupsFilter:                   c.JWTGroupsFilter(src.JwtGroupsFilter, src.JwtGroupsFilterInferFromPpl),
		JWTIssuerFormat:                   c.IssuerFormat(src.JwtIssuerFormat),
		KubernetesServiceAccountToken:     types.StringValue(src.KubernetesServiceAccountToken),
		KubernetesServiceAccountTokenFile: types.StringValue(src.KubernetesServiceAccountTokenFile),
		LoadBalancingPolicy:               OptionalEnumValueFromPB(src.LoadBalancingPolicy, "LOAD_BALANCING_POLICY"),
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
		RemoveRequestHeaders:              FromStringSliceToSet(src.RemoveRequestHeaders),
		RewriteResponseHeaders:            toSetOfObjects(src.RewriteResponseHeaders, RewriteHeaderObjectType(), c.RouteRewriteHeader),
		SetRequestHeaders:                 FromStringMap(src.SetRequestHeaders),
		SetResponseHeaders:                FromStringMap(src.SetResponseHeaders),
		ShowErrorDetails:                  types.BoolValue(src.ShowErrorDetails),
		StatName:                          types.StringPointerValue(src.StatName),
		Timeout:                           c.Duration(src.Timeout),
		TLSClientKeyPairID:                types.StringPointerValue(src.TlsClientKeyPairId),
		TLSCustomCAKeyPairID:              types.StringPointerValue(src.TlsCustomCaKeyPairId),
		TLSDownstreamServerName:           types.StringValue(src.TlsDownstreamServerName),
		TLSSkipVerify:                     types.BoolValue(src.TlsSkipVerify),
		TLSUpstreamAllowRenegotiation:     types.BoolValue(src.TlsUpstreamAllowRenegotiation),
		TLSUpstreamServerName:             types.StringValue(src.TlsUpstreamServerName),
		To:                                FromStringSliceToSet(src.To),
	}
}

func (c *APIToModelConverter) RouteRewriteHeader(src *pomerium.RouteRewriteHeader) types.Object {
	if src == nil {
		return types.ObjectNull(RewriteHeaderObjectType().AttrTypes)
	}

	return types.ObjectValueMust(RewriteHeaderObjectType().AttrTypes, map[string]attr.Value{
		"header": types.StringValue(src.GetHeader()),
		"value":  types.StringValue(src.GetValue()),
		"prefix": types.StringPointerValue(zeroToNil(src.GetPrefix())),
	})
}

func (c *APIToModelConverter) ServiceAccount(src *pomerium.ServiceAccount) ServiceAccountModel {
	return ServiceAccountModel{
		Description: types.StringPointerValue(src.Description),
		ExpiresAt:   c.Timestamp(src.ExpiresAt),
		ID:          types.StringPointerValue(src.Id),
		Name:        types.StringValue(strings.TrimSuffix(src.GetUserId(), "@"+src.GetNamespaceId()+".pomerium")),
		NamespaceID: types.StringPointerValue(src.NamespaceId),
		UserID:      types.StringPointerValue(src.UserId),
	}
}

func (c *APIToModelConverter) SetFromStringSlice(src []string) types.Set {
	if src == nil {
		return types.SetNull(types.StringType)
	}
	fields := make([]attr.Value, 0)
	for _, v := range src {
		fields = append(fields, types.StringValue(v))
	}
	return types.SetValueMust(types.StringType, fields)
}

func (c *APIToModelConverter) SetFromSettingsStringList(src *pomerium.Settings_StringList) types.Set {
	if src == nil {
		return types.SetNull(types.StringType)
	}
	return FromStringSliceToSet(src.Values)
}

func (c *APIToModelConverter) Settings(src *pomerium.Settings) SettingsModel {
	return SettingsModel{
		AccessLogFields:               c.SetFromSettingsStringList(src.AccessLogFields),
		Address:                       types.StringPointerValue(src.Address),
		AuthenticateServiceURL:        types.StringPointerValue(src.AuthenticateServiceUrl),
		AuthorizeLogFields:            c.SetFromSettingsStringList(src.AuthorizeLogFields),
		AuthorizeServiceURL:           c.StringFromSingleElementSlice(path.Root("authorize_service_url"), src.AuthorizeServiceUrls),
		Autocert:                      types.BoolPointerValue(src.Autocert),
		AutocertDir:                   types.StringPointerValue(src.AutocertDir),
		AutocertMustStaple:            types.BoolPointerValue(src.AutocertMustStaple),
		AutocertUseStaging:            types.BoolPointerValue(src.AutocertUseStaging),
		BearerTokenFormat:             c.BearerTokenFormat(src.BearerTokenFormat),
		CacheServiceURL:               types.StringNull(),
		CertificateAuthority:          types.StringPointerValue(src.CertificateAuthority),
		CertificateAuthorityFile:      types.StringNull(),
		CertificateAuthorityKeyPairID: types.StringPointerValue(src.CertificateAuthorityKeyPairId),
		CircuitBreakerThresholds:      c.CircuitBreakerThresholds(src.CircuitBreakerThresholds),
		ClientCA:                      types.StringNull(),
		ClientCAFile:                  types.StringNull(),
		ClientCAKeyPairID:             types.StringNull(),
		ClusterID:                     types.StringPointerValue(src.ClusterId),
		CodecType:                     c.CodecType(src.CodecType),
		CookieDomain:                  types.StringPointerValue(src.CookieDomain),
		CookieExpire:                  c.Duration(src.CookieExpire),
		CookieHTTPOnly:                types.BoolPointerValue(src.CookieHttpOnly),
		CookieName:                    types.StringPointerValue(src.CookieName),
		CookieSameSite:                types.StringPointerValue(src.CookieSameSite),
		CookieSecret:                  types.StringPointerValue(src.CookieSecret),
		CookieSecure:                  types.BoolNull(),
		DarkmodePrimaryColor:          types.StringPointerValue(src.DarkmodePrimaryColor),
		DarkmodeSecondaryColor:        types.StringPointerValue(src.DarkmodeSecondaryColor),
		DatabrokerServiceURL:          c.StringFromSingleElementSlice(path.Root("databroker_service_url"), src.DatabrokerServiceUrls),
		DefaultUpstreamTimeout:        c.Duration(src.DefaultUpstreamTimeout),
		DNSFailureRefreshRate:         c.Duration(src.DnsFailureRefreshRate),
		DNSLookupFamily:               types.StringPointerValue(src.DnsLookupFamily),
		DNSQueryTimeout:               c.Duration(src.DnsQueryTimeout),
		DNSQueryTries:                 Int64PointerValue(src.DnsQueryTries),
		DNSRefreshRate:                c.Duration(src.DnsRefreshRate),
		DNSUDPMaxQueries:              Int64PointerValue(src.DnsUdpMaxQueries),
		DNSUseTCP:                     types.BoolPointerValue(src.DnsUseTcp),
		ErrorMessageFirstParagraph:    types.StringPointerValue(src.ErrorMessageFirstParagraph),
		FaviconURL:                    types.StringPointerValue(src.FaviconUrl),
		GoogleCloudServerlessAuthenticationServiceAccount: types.StringPointerValue(src.GoogleCloudServerlessAuthenticationServiceAccount),
		GRPCAddress:                     types.StringPointerValue(src.GrpcAddress),
		GRPCInsecure:                    types.BoolPointerValue(src.GrpcInsecure),
		HTTPRedirectAddr:                types.StringPointerValue(src.HttpRedirectAddr),
		ID:                              types.StringPointerValue(src.Id),
		IdentityProviderAuth0:           c.IdentityProviderAuth0(src.GetDirectoryProvider(), src.GetDirectoryProviderOptions()),
		IdentityProviderAzure:           c.IdentityProviderAzure(src.GetDirectoryProvider(), src.GetDirectoryProviderOptions()),
		IdentityProviderBlob:            c.IdentityProviderBlob(src.GetDirectoryProvider(), src.GetDirectoryProviderOptions()),
		IdentityProviderCognito:         c.IdentityProviderCognito(src.GetDirectoryProvider(), src.GetDirectoryProviderOptions()),
		IdentityProviderGitHub:          c.IdentityProviderGitHub(src.GetDirectoryProvider(), src.GetDirectoryProviderOptions()),
		IdentityProviderGitLab:          c.IdentityProviderGitLab(src.GetDirectoryProvider(), src.GetDirectoryProviderOptions()),
		IdentityProviderGoogle:          c.IdentityProviderGoogle(src.GetDirectoryProvider(), src.GetDirectoryProviderOptions()),
		IdentityProviderOkta:            c.IdentityProviderOkta(src.GetDirectoryProvider(), src.GetDirectoryProviderOptions()),
		IdentityProviderOneLogin:        c.IdentityProviderOneLogin(src.GetDirectoryProvider(), src.GetDirectoryProviderOptions()),
		IdentityProviderPing:            c.IdentityProviderPing(src.GetDirectoryProvider(), src.GetDirectoryProviderOptions()),
		IdentityProviderRefreshInterval: c.Duration(src.DirectoryProviderRefreshInterval),
		IdentityProviderRefreshTimeout:  c.Duration(src.DirectoryProviderRefreshTimeout),
		IDPAccessTokenAllowedAudiences:  FromStringList(src.IdpAccessTokenAllowedAudiences),
		IdpClientID:                     types.StringPointerValue(src.IdpClientId),
		IdpClientSecret:                 types.StringPointerValue(src.IdpClientSecret),
		IdpProvider:                     types.StringPointerValue(src.IdpProvider),
		IdpProviderURL:                  types.StringPointerValue(src.IdpProviderUrl),
		IdpRefreshDirectoryInterval:     c.Duration(src.DirectoryProviderRefreshInterval),
		IdpRefreshDirectoryTimeout:      c.Duration(src.DirectoryProviderRefreshTimeout),
		IdpServiceAccount:               types.StringNull(),
		InsecureServer:                  types.BoolPointerValue(src.InsecureServer),
		InstallationID:                  types.StringPointerValue(src.InstallationId),
		JWTClaimsHeaders:                FromStringMap(src.JwtClaimsHeaders),
		JWTGroupsFilter:                 c.JWTGroupsFilter(src.JwtGroupsFilter, src.JwtGroupsFilterInferFromPpl),
		JWTIssuerFormat:                 c.IssuerFormat(src.JwtIssuerFormat),
		LogLevel:                        types.StringPointerValue(src.LogLevel),
		LogoURL:                         types.StringPointerValue(src.LogoUrl),
		MetricsAddress:                  types.StringPointerValue(src.MetricsAddress),
		OtelAttributeValueLengthLimit:   Int64PointerValue(src.OtelAttributeValueLengthLimit),
		OtelBspMaxExportBatchSize:       Int64PointerValue(src.OtelBspMaxExportBatchSize),
		OtelBspScheduleDelay:            c.Duration(src.OtelBspScheduleDelay),
		OtelExporterOtlpEndpoint:        types.StringPointerValue(src.OtelExporterOtlpEndpoint),
		OtelExporterOtlpHeaders:         FromStringSliceToSet(src.OtelExporterOtlpHeaders),
		OtelExporterOtlpProtocol:        types.StringPointerValue(src.OtelExporterOtlpProtocol),
		OtelExporterOtlpTimeout:         c.Duration(src.OtelExporterOtlpTimeout),
		OtelExporterOtlpTracesEndpoint:  types.StringPointerValue(src.OtelExporterOtlpTracesEndpoint),
		OtelExporterOtlpTracesHeaders:   FromStringSliceToSet(src.OtelExporterOtlpTracesHeaders),
		OtelExporterOtlpTracesProtocol:  types.StringPointerValue(src.OtelExporterOtlpTracesProtocol),
		OtelExporterOtlpTracesTimeout:   c.Duration(src.OtelExporterOtlpTracesTimeout),
		OtelLogLevel:                    types.StringPointerValue(src.OtelLogLevel),
		OtelResourceAttributes:          FromStringSliceToSet(src.OtelResourceAttributes),
		OtelTracesExporter:              types.StringPointerValue(src.OtelTracesExporter),
		OtelTracesSamplerArg:            types.Float64PointerValue(src.OtelTracesSamplerArg),
		PassIdentityHeaders:             types.BoolPointerValue(src.PassIdentityHeaders),
		PrimaryColor:                    types.StringPointerValue(src.PrimaryColor),
		ProxyLogLevel:                   types.StringPointerValue(src.ProxyLogLevel),
		RequestParams:                   FromStringMap(src.RequestParams),
		Scopes:                          FromStringSliceToSet(src.Scopes),
		SecondaryColor:                  types.StringPointerValue(src.SecondaryColor),
		SetResponseHeaders:              FromStringMap(src.SetResponseHeaders),
		SkipXFFAppend:                   types.BoolPointerValue(src.SkipXffAppend),
		SSHAddress:                      types.StringPointerValue(src.SshAddress),
		SSHHostKeyFiles:                 FromStringList(src.SshHostKeyFiles),
		SSHHostKeys:                     FromStringList(src.SshHostKeys),
		SSHUserCAKey:                    types.StringPointerValue(src.SshUserCaKey),
		SSHUserCAKeyFile:                types.StringPointerValue(src.SshUserCaKeyFile),
		TimeoutIdle:                     c.Duration(src.TimeoutIdle),
		TimeoutRead:                     c.Duration(src.TimeoutRead),
		TimeoutWrite:                    c.Duration(src.TimeoutWrite),
	}
}

func (c *APIToModelConverter) StringFromSingleElementSlice(p path.Path, src []string) types.String {
	if len(src) == 0 {
		return types.StringNull()
	}

	if len(src) > 1 {
		c.diagnostics.AddAttributeError(p, "only a single element is supported", fmt.Sprintf("only a single element is supported, got: %v", src))
	}

	return types.StringValue(src[0])
}
