package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"google.golang.org/protobuf/proto"
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
