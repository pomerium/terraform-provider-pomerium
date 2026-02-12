package provider

import (
	"encoding/base64"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"google.golang.org/protobuf/types/known/timestamppb"

	enterprise "github.com/pomerium/enterprise-client-go/pb"
)

type EnterpriseToModelConverter struct {
	baseProtoConverter
	diagnostics *diag.Diagnostics
}

func NewEnterpriseToModelConverter(diagnostics *diag.Diagnostics) *EnterpriseToModelConverter {
	return &EnterpriseToModelConverter{
		baseProtoConverter: baseProtoConverter{diagnostics: diagnostics},
		diagnostics:        diagnostics,
	}
}

func (c *EnterpriseToModelConverter) Base64String(src []byte) types.String {
	if len(src) == 0 {
		return types.StringNull()
	}
	return types.StringValue(base64.StdEncoding.EncodeToString(src))
}

func (c *EnterpriseToModelConverter) CircuitBreakerThresholds(src *enterprise.CircuitBreakerThresholds) types.Object {
	if src == nil {
		return types.ObjectNull(CircuitBreakerThresholdsAttributes)
	}

	dst, diagnostics := types.ObjectValue(CircuitBreakerThresholdsAttributes, map[string]attr.Value{
		"max_connections":      Int64PointerValue(src.MaxConnections),
		"max_pending_requests": Int64PointerValue(src.MaxPendingRequests),
		"max_requests":         Int64PointerValue(src.MaxRequests),
		"max_retries":          Int64PointerValue(src.MaxRetries),
		"max_connection_pools": Int64PointerValue(src.MaxConnectionPools),
	})
	c.diagnostics.Append(diagnostics...)
	return dst
}

func (c *EnterpriseToModelConverter) Cluster(src *enterprise.Cluster, namespace *enterprise.Namespace) ClusterModel {
	return ClusterModel{
		CertificateAuthorityB64:  c.Base64String(src.CertificateAuthority),
		CertificateAuthorityFile: types.StringPointerValue(src.CertificateAuthorityFile),
		DatabrokerServiceURL:     types.StringValue(src.DatabrokerServiceUrl),
		ID:                       types.StringValue(src.Id),
		InsecureSkipVerify:       types.BoolPointerValue(src.InsecureSkipVerify),
		Name:                     types.StringValue(src.Name),
		NamespaceID:              types.StringPointerValue(zeroToNil(namespace.GetId())),
		OverrideCertificateName:  types.StringPointerValue(src.OverrideCertificateName),
		ParentNamespaceID:        types.StringPointerValue(zeroToNil(namespace.GetParentId())),
		SharedSecretB64:          c.Base64String(src.SharedSecret),
	}
}

func (c *EnterpriseToModelConverter) ExternalDataSource(src *enterprise.ExternalDataSource) ExternalDataSourceModel {
	return ExternalDataSourceModel{
		AllowInsecureTLS: types.BoolPointerValue(src.AllowInsecureTls),
		ClientTLSKeyID:   types.StringPointerValue(src.ClientTlsKeyId),
		ClusterID:        types.StringPointerValue(src.ClusterId),
		ForeignKey:       types.StringValue(src.ForeignKey),
		Headers:          FromStringMap(src.Headers),
		ID:               types.StringValue(src.Id),
		PollingMaxDelay:  c.Duration(src.PollingMaxDelay),
		PollingMinDelay:  c.Duration(src.PollingMinDelay),
		RecordType:       types.StringValue(src.RecordType),
		URL:              types.StringValue(src.Url),
	}
}

func (c *EnterpriseToModelConverter) HealthCheck(src *enterprise.HealthCheck) types.Object {
	if src == nil {
		return types.ObjectNull(HealthCheckObjectType().AttrTypes)
	}

	attrs := map[string]attr.Value{
		"timeout":                 c.Duration(src.Timeout),
		"interval":                c.Duration(src.Interval),
		"initial_jitter":          c.Duration(src.InitialJitter),
		"interval_jitter":         c.Duration(src.IntervalJitter),
		"interval_jitter_percent": UInt32ToInt64OrNull(src.IntervalJitterPercent),
		"unhealthy_threshold":     UInt32ToInt64OrNull(src.UnhealthyThreshold),
		"healthy_threshold":       UInt32ToInt64OrNull(src.HealthyThreshold),
		"http_health_check":       types.ObjectNull(HTTPHealthCheckObjectType().AttrTypes),
		"tcp_health_check":        types.ObjectNull(TCPHealthCheckObjectType().AttrTypes),
		"grpc_health_check":       types.ObjectNull(GrpcHealthCheckObjectType().AttrTypes),
	}

	if httpHc := src.GetHttpHealthCheck(); httpHc != nil {
		expectedStatusesElem := []attr.Value{}
		for _, status := range httpHc.ExpectedStatuses {
			statusObj, diagsStatus := int64RangeFromPB(status)
			c.diagnostics.Append(diagsStatus...)
			expectedStatusesElem = append(expectedStatusesElem, statusObj)
		}
		expectedStatuses, _ := types.SetValue(Int64RangeObjectType(), expectedStatusesElem)

		retriableStatusesElem := []attr.Value{}
		for _, status := range httpHc.RetriableStatuses {
			statusObj, diagsStatus := int64RangeFromPB(status)
			c.diagnostics.Append(diagsStatus...)
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
	} else if tcpHc := src.GetTcpHealthCheck(); tcpHc != nil {
		sendPayload, diagsSend := payloadFromPB(tcpHc.Send)
		c.diagnostics.Append(diagsSend...)

		receiveElements := []attr.Value{}
		for _, payload := range tcpHc.Receive {
			payloadObj, diagsPayload := payloadFromPB(payload)
			c.diagnostics.Append(diagsPayload...)
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

func (c *EnterpriseToModelConverter) IdentityProviderAuth0(src *enterprise.Settings) types.Object {
	attrs, err := GetTFObjectTypes[Auth0Options]()
	if err != nil {
		c.diagnostics.AddAttributeError(path.Root("identity_provider_auth0"), err.Error(), err.Error())
		return types.ObjectNull(map[string]attr.Type{})
	}
	if src.GetIdentityProvider() != "auth0" {
		return types.ObjectNull(attrs)
	}
	return idpOptionsFromStruct[Auth0Options](c.diagnostics, src.IdentityProviderOptions)
}

func (c *EnterpriseToModelConverter) IdentityProviderAzure(src *enterprise.Settings) types.Object {
	attrs, err := GetTFObjectTypes[AzureOptions]()
	if err != nil {
		c.diagnostics.AddAttributeError(path.Root("identity_provider_azure"), err.Error(), err.Error())
		return types.ObjectNull(map[string]attr.Type{})
	}
	if src.GetIdentityProvider() != "azure" {
		return types.ObjectNull(attrs)
	}
	return idpOptionsFromStruct[AzureOptions](c.diagnostics, src.IdentityProviderOptions)
}

func (c *EnterpriseToModelConverter) IdentityProviderBlob(src *enterprise.Settings) types.Object {
	attrs, err := GetTFObjectTypes[BlobOptions]()
	if err != nil {
		c.diagnostics.AddAttributeError(path.Root("identity_provider_blob"), err.Error(), err.Error())
		return types.ObjectNull(map[string]attr.Type{})
	}
	if src.GetIdentityProvider() != "blob" {
		return types.ObjectNull(attrs)
	}
	return idpOptionsFromStruct[BlobOptions](c.diagnostics, src.IdentityProviderOptions)
}

func (c *EnterpriseToModelConverter) IdentityProviderCognito(src *enterprise.Settings) types.Object {
	attrs, err := GetTFObjectTypes[CognitoOptions]()
	if err != nil {
		c.diagnostics.AddAttributeError(path.Root("identity_provider_cognito"), err.Error(), err.Error())
		return types.ObjectNull(map[string]attr.Type{})
	}
	if src.GetIdentityProvider() != "cognito" {
		return types.ObjectNull(attrs)
	}
	return idpOptionsFromStruct[CognitoOptions](c.diagnostics, src.IdentityProviderOptions)
}

func (c *EnterpriseToModelConverter) IdentityProviderGitHub(src *enterprise.Settings) types.Object {
	attrs, err := GetTFObjectTypes[GitHubOptions]()
	if err != nil {
		c.diagnostics.AddAttributeError(path.Root("identity_provider_github"), err.Error(), err.Error())
		return types.ObjectNull(map[string]attr.Type{})
	}
	if src.GetIdentityProvider() != "github" {
		return types.ObjectNull(attrs)
	}
	return idpOptionsFromStruct[GitHubOptions](c.diagnostics, src.IdentityProviderOptions)
}

func (c *EnterpriseToModelConverter) IdentityProviderGitLab(src *enterprise.Settings) types.Object {
	attrs, err := GetTFObjectTypes[GitLabOptions]()
	if err != nil {
		c.diagnostics.AddAttributeError(path.Root("identity_provider_gitlab"), err.Error(), err.Error())
		return types.ObjectNull(map[string]attr.Type{})
	}
	if src.GetIdentityProvider() != "gitlab" {
		return types.ObjectNull(attrs)
	}
	return idpOptionsFromStruct[GitLabOptions](c.diagnostics, src.IdentityProviderOptions)
}

func (c *EnterpriseToModelConverter) IdentityProviderGoogle(src *enterprise.Settings) types.Object {
	attrs, err := GetTFObjectTypes[GoogleOptions]()
	if err != nil {
		c.diagnostics.AddAttributeError(path.Root("identity_provider_google"), err.Error(), err.Error())
		return types.ObjectNull(map[string]attr.Type{})
	}
	if src.GetIdentityProvider() != "google" {
		return types.ObjectNull(attrs)
	}
	return idpOptionsFromStruct[GoogleOptions](c.diagnostics, src.IdentityProviderOptions)
}

func (c *EnterpriseToModelConverter) IdentityProviderOkta(src *enterprise.Settings) types.Object {
	attrs, err := GetTFObjectTypes[OktaOptions]()
	if err != nil {
		c.diagnostics.AddAttributeError(path.Root("identity_provider_okta"), err.Error(), err.Error())
		return types.ObjectNull(map[string]attr.Type{})
	}
	if src.GetIdentityProvider() != "okta" {
		return types.ObjectNull(attrs)
	}
	return idpOptionsFromStruct[OktaOptions](c.diagnostics, src.IdentityProviderOptions)
}

func (c *EnterpriseToModelConverter) IdentityProviderOneLogin(src *enterprise.Settings) types.Object {
	attrs, err := GetTFObjectTypes[OneLoginOptions]()
	if err != nil {
		c.diagnostics.AddAttributeError(path.Root("identity_provider_onelogin"), err.Error(), err.Error())
		return types.ObjectNull(map[string]attr.Type{})
	}
	if src.GetIdentityProvider() != "onelogin" {
		return types.ObjectNull(attrs)
	}
	return idpOptionsFromStruct[OneLoginOptions](c.diagnostics, src.IdentityProviderOptions)
}

func (c *EnterpriseToModelConverter) IdentityProviderPing(src *enterprise.Settings) types.Object {
	attrs, err := GetTFObjectTypes[PingOptions]()
	if err != nil {
		c.diagnostics.AddAttributeError(path.Root("identity_provider_ping"), err.Error(), err.Error())
		return types.ObjectNull(map[string]attr.Type{})
	}
	if src.GetIdentityProvider() != "ping" {
		return types.ObjectNull(attrs)
	}
	return idpOptionsFromStruct[PingOptions](c.diagnostics, src.IdentityProviderOptions)
}

func (c *EnterpriseToModelConverter) JWTGroupsFilter(src *enterprise.JwtGroupsFilter) types.Object {
	if src == nil {
		return types.ObjectNull(JWTGroupsFilterSchemaAttributes)
	}

	attrs := make(map[string]attr.Value)
	if src.Groups == nil {
		attrs["groups"] = types.SetNull(types.StringType)
	} else {
		var vals []attr.Value
		for _, v := range src.Groups {
			vals = append(vals, types.StringValue(v))
		}
		attrs["groups"] = types.SetValueMust(types.StringType, vals)
	}

	attrs["infer_from_ppl"] = types.BoolPointerValue(src.InferFromPpl)

	return types.ObjectValueMust(JWTGroupsFilterSchemaAttributes, attrs)
}

func (c *EnterpriseToModelConverter) Namespace(src *enterprise.Namespace) NamespaceModel {
	return NamespaceModel{
		ClusterID: types.StringPointerValue(src.ClusterId),
		ID:        types.StringValue(src.Id),
		Name:      types.StringValue(src.Name),
		ParentID:  types.StringPointerValue(zeroToNil(src.ParentId)),
	}
}

func (c *EnterpriseToModelConverter) NamespacePermission(src *enterprise.NamespacePermission) NamespacePermissionModel {
	return NamespacePermissionModel{
		ID:          types.StringValue(src.Id),
		NamespaceID: types.StringValue(src.NamespaceId),
		Role:        types.StringValue(src.Role),
		SubjectID:   types.StringValue(src.SubjectId),
		SubjectType: types.StringValue(src.SubjectType),
	}
}

func (c *EnterpriseToModelConverter) Policy(src *enterprise.Policy) PolicyModel {
	ppl, err := PolicyLanguageType{}.Parse(types.StringValue(src.Ppl))
	if err != nil {
		c.diagnostics.AddError("error parsing ppl", err.Error())
	}

	return PolicyModel{
		Description: types.StringValue(src.Description),
		Enforced:    types.BoolValue(src.Enforced),
		Explanation: types.StringValue(src.Explanation),
		ID:          types.StringValue(src.Id),
		Name:        types.StringValue(src.Name),
		NamespaceID: types.StringValue(src.NamespaceId),
		PPL:         ppl,
		Rego:        FromStringSliceToList(src.Rego),
		Remediation: types.StringValue(src.Remediation),
	}
}

func (c *EnterpriseToModelConverter) Route(src *enterprise.Route) RouteModel {
	return RouteModel{
		AllowSPDY:                types.BoolPointerValue(src.AllowSpdy),
		AllowWebsockets:          types.BoolPointerValue(src.AllowWebsockets),
		BearerTokenFormat:        FromBearerTokenFormat(src.BearerTokenFormat),
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
		ID:                                types.StringValue(src.Id),
		IdleTimeout:                       c.Duration(src.IdleTimeout),
		IDPAccessTokenAllowedAudiences:    FromStringList(src.IdpAccessTokenAllowedAudiences),
		IDPClientID:                       types.StringPointerValue(src.IdpClientId),
		IDPClientSecret:                   types.StringPointerValue(src.IdpClientSecret),
		JWTGroupsFilter:                   c.JWTGroupsFilter(src.JwtGroupsFilter),
		JWTIssuerFormat:                   FromIssuerFormat(src.JwtIssuerFormat),
		KubernetesServiceAccountToken:     types.StringPointerValue(src.KubernetesServiceAccountToken),
		KubernetesServiceAccountTokenFile: types.StringPointerValue(src.KubernetesServiceAccountTokenFile),
		LoadBalancingPolicy:               OptionalEnumValueFromPB(src.LoadBalancingPolicy, "LOAD_BALANCING_POLICY"),
		LogoURL:                           types.StringPointerValue(src.LogoUrl),
		Name:                              types.StringValue(src.Name),
		NamespaceID:                       types.StringValue(src.NamespaceId),
		PassIdentityHeaders:               types.BoolPointerValue(src.PassIdentityHeaders),
		Path:                              types.StringPointerValue(src.Path),
		Policies:                          FromStringSliceToSet(StringSliceExclude(src.PolicyIds, src.EnforcedPolicyIds)),
		Prefix:                            types.StringPointerValue(src.Prefix),
		PrefixRewrite:                     types.StringPointerValue(src.PrefixRewrite),
		PreserveHostHeader:                types.BoolPointerValue(src.PreserveHostHeader),
		Regex:                             types.StringPointerValue(src.Regex),
		RegexPriorityOrder:                types.Int64PointerValue(src.RegexPriorityOrder),
		RegexRewritePattern:               types.StringPointerValue(src.RegexRewritePattern),
		RegexRewriteSubstitution:          types.StringPointerValue(src.RegexRewriteSubstitution),
		RemoveRequestHeaders:              FromStringSliceToSet(src.RemoveRequestHeaders),
		RewriteResponseHeaders:            rewriteHeadersFromPB(src.RewriteResponseHeaders),
		SetRequestHeaders:                 FromStringMap(src.SetRequestHeaders),
		SetResponseHeaders:                FromStringMap(src.SetResponseHeaders),
		ShowErrorDetails:                  types.BoolValue(src.ShowErrorDetails),
		StatName:                          types.StringValue(src.StatName),
		Timeout:                           c.Duration(src.Timeout),
		TLSClientKeyPairID:                types.StringPointerValue(src.TlsClientKeyPairId),
		TLSCustomCAKeyPairID:              types.StringPointerValue(src.TlsCustomCaKeyPairId),
		TLSDownstreamServerName:           types.StringPointerValue(src.TlsDownstreamServerName),
		TLSSkipVerify:                     types.BoolPointerValue(src.TlsSkipVerify),
		TLSUpstreamAllowRenegotiation:     types.BoolPointerValue(src.TlsUpstreamAllowRenegotiation),
		TLSUpstreamServerName:             types.StringPointerValue(src.TlsUpstreamServerName),
		To:                                FromStringSliceToSet(src.To),
	}
}

func (c *EnterpriseToModelConverter) ServiceAccount(src *enterprise.PomeriumServiceAccount) ServiceAccountModel {
	return ServiceAccountModel{
		Description: types.StringPointerValue(src.Description),
		ExpiresAt:   c.Timestamp(src.ExpiresAt),
		ID:          types.StringValue(src.Id),
		Name:        types.StringValue(strings.TrimSuffix(src.GetUserId(), "@"+src.GetNamespaceId()+".pomerium")),
		NamespaceID: types.StringPointerValue(src.NamespaceId),
		UserID:      types.StringValue(src.UserId),
	}
}

func (c *EnterpriseToModelConverter) Settings(src *enterprise.Settings) SettingsModel {
	return SettingsModel{
		AccessLogFields:               FromStringListToSet(src.AccessLogFields),
		Address:                       types.StringPointerValue(src.Address),
		AuthenticateServiceURL:        types.StringPointerValue(src.AuthenticateServiceUrl),
		AuthorizeLogFields:            FromStringListToSet(src.AuthorizeLogFields),
		AuthorizeServiceURL:           types.StringPointerValue(src.AuthorizeServiceUrl),
		Autocert:                      types.BoolPointerValue(src.Autocert),
		AutocertDir:                   types.StringPointerValue(src.AutocertDir),
		AutocertMustStaple:            types.BoolPointerValue(src.AutocertMustStaple),
		AutocertUseStaging:            types.BoolPointerValue(src.AutocertUseStaging),
		BearerTokenFormat:             FromBearerTokenFormat(src.BearerTokenFormat),
		CacheServiceURL:               types.StringPointerValue(src.CacheServiceUrl),
		CertificateAuthority:          types.StringPointerValue(src.CertificateAuthority),
		CertificateAuthorityFile:      types.StringPointerValue(src.CertificateAuthorityFile),
		CertificateAuthorityKeyPairID: types.StringPointerValue(src.CertificateAuthorityKeyPairId),
		CircuitBreakerThresholds:      c.CircuitBreakerThresholds(src.CircuitBreakerThresholds),
		ClientCA:                      types.StringPointerValue(src.ClientCa),
		ClientCAFile:                  types.StringPointerValue(src.ClientCaFile),
		ClientCAKeyPairID:             types.StringPointerValue(src.ClientCaKeyPairId),
		ClusterID:                     types.StringPointerValue(src.ClusterId),
		CodecType:                     FromCodecType(src.CodecType),
		CookieDomain:                  types.StringPointerValue(src.CookieDomain),
		CookieExpire:                  c.Duration(src.CookieExpire),
		CookieHTTPOnly:                types.BoolPointerValue(src.CookieHttpOnly),
		CookieName:                    types.StringPointerValue(src.CookieName),
		CookieSameSite:                types.StringPointerValue(src.CookieSameSite),
		CookieSecret:                  types.StringPointerValue(src.CookieSecret),
		CookieSecure:                  types.BoolPointerValue(src.CookieSecure),
		DarkmodePrimaryColor:          types.StringPointerValue(src.DarkmodePrimaryColor),
		DarkmodeSecondaryColor:        types.StringPointerValue(src.DarkmodeSecondaryColor),
		DatabrokerServiceURL:          types.StringPointerValue(src.DatabrokerServiceUrl),
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
		ID:                              types.StringValue(src.Id),
		IdentityProviderAuth0:           c.IdentityProviderAuth0(src),
		IdentityProviderAzure:           c.IdentityProviderAzure(src),
		IdentityProviderBlob:            c.IdentityProviderBlob(src),
		IdentityProviderCognito:         c.IdentityProviderCognito(src),
		IdentityProviderGitHub:          c.IdentityProviderGitHub(src),
		IdentityProviderGitLab:          c.IdentityProviderGitLab(src),
		IdentityProviderGoogle:          c.IdentityProviderGoogle(src),
		IdentityProviderOkta:            c.IdentityProviderOkta(src),
		IdentityProviderOneLogin:        c.IdentityProviderOneLogin(src),
		IdentityProviderPing:            c.IdentityProviderPing(src),
		IdentityProviderRefreshInterval: c.Duration(src.IdentityProviderRefreshInterval),
		IdentityProviderRefreshTimeout:  c.Duration(src.IdentityProviderRefreshTimeout),
		IDPAccessTokenAllowedAudiences:  FromStringList(src.IdpAccessTokenAllowedAudiences),
		IdpClientID:                     types.StringPointerValue(src.IdpClientId),
		IdpClientSecret:                 types.StringPointerValue(src.IdpClientSecret),
		IdpProvider:                     types.StringPointerValue(src.IdpProvider),
		IdpProviderURL:                  types.StringPointerValue(src.IdpProviderUrl),
		IdpRefreshDirectoryInterval:     c.Duration(src.IdpRefreshDirectoryInterval),
		IdpRefreshDirectoryTimeout:      c.Duration(src.IdpRefreshDirectoryTimeout),
		IdpServiceAccount:               types.StringPointerValue(src.IdpServiceAccount),
		InsecureServer:                  types.BoolPointerValue(src.InsecureServer),
		InstallationID:                  types.StringPointerValue(src.InstallationId),
		JWTClaimsHeaders:                FromStringMap(src.JwtClaimsHeaders),
		JWTGroupsFilter:                 c.JWTGroupsFilter(src.JwtGroupsFilter),
		JWTIssuerFormat:                 FromIssuerFormat(src.JwtIssuerFormat),
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

func (c *EnterpriseToModelConverter) Timestamp(src *timestamppb.Timestamp) types.String {
	if src == nil || src.AsTime().IsZero() {
		return types.StringNull()
	}

	return types.StringValue(src.AsTime().Format(time.RFC3339))
}
