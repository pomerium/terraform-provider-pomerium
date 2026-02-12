package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pomerium/enterprise-client-go/pb"
)

type SettingsModel struct {
	AccessLogFields                                   types.Set            `tfsdk:"access_log_fields"`
	Address                                           types.String         `tfsdk:"address"`
	AuthenticateServiceURL                            types.String         `tfsdk:"authenticate_service_url"`
	AuthorizeLogFields                                types.Set            `tfsdk:"authorize_log_fields"`
	AuthorizeServiceURL                               types.String         `tfsdk:"authorize_service_url"`
	Autocert                                          types.Bool           `tfsdk:"autocert"`
	AutocertDir                                       types.String         `tfsdk:"autocert_dir"`
	AutocertMustStaple                                types.Bool           `tfsdk:"autocert_must_staple"`
	AutocertUseStaging                                types.Bool           `tfsdk:"autocert_use_staging"`
	BearerTokenFormat                                 types.String         `tfsdk:"bearer_token_format"`
	CacheServiceURL                                   types.String         `tfsdk:"cache_service_url"`
	CertificateAuthority                              types.String         `tfsdk:"certificate_authority"`
	CertificateAuthorityFile                          types.String         `tfsdk:"certificate_authority_file"`
	CertificateAuthorityKeyPairID                     types.String         `tfsdk:"certificate_authority_key_pair_id"`
	CircuitBreakerThresholds                          types.Object         `tfsdk:"circuit_breaker_thresholds"`
	ClientCA                                          types.String         `tfsdk:"client_ca"`
	ClientCAFile                                      types.String         `tfsdk:"client_ca_file"`
	ClientCAKeyPairID                                 types.String         `tfsdk:"client_ca_key_pair_id"`
	ClusterID                                         types.String         `tfsdk:"cluster_id"`
	CodecType                                         types.String         `tfsdk:"codec_type"`
	CookieDomain                                      types.String         `tfsdk:"cookie_domain"`
	CookieExpire                                      timetypes.GoDuration `tfsdk:"cookie_expire"`
	CookieHTTPOnly                                    types.Bool           `tfsdk:"cookie_http_only"`
	CookieName                                        types.String         `tfsdk:"cookie_name"`
	CookieSameSite                                    types.String         `tfsdk:"cookie_same_site"`
	CookieSecret                                      types.String         `tfsdk:"cookie_secret"`
	CookieSecure                                      types.Bool           `tfsdk:"cookie_secure"`
	DarkmodePrimaryColor                              types.String         `tfsdk:"darkmode_primary_color"`
	DarkmodeSecondaryColor                            types.String         `tfsdk:"darkmode_secondary_color"`
	DatabrokerServiceURL                              types.String         `tfsdk:"databroker_service_url"`
	DefaultUpstreamTimeout                            timetypes.GoDuration `tfsdk:"default_upstream_timeout"`
	DNSFailureRefreshRate                             timetypes.GoDuration `tfsdk:"dns_failure_refresh_rate"`
	DNSLookupFamily                                   types.String         `tfsdk:"dns_lookup_family"`
	DNSQueryTimeout                                   timetypes.GoDuration `tfsdk:"dns_query_timeout"`
	DNSQueryTries                                     types.Int64          `tfsdk:"dns_query_tries"`
	DNSRefreshRate                                    timetypes.GoDuration `tfsdk:"dns_refresh_rate"`
	DNSUDPMaxQueries                                  types.Int64          `tfsdk:"dns_udp_max_queries"`
	DNSUseTCP                                         types.Bool           `tfsdk:"dns_use_tcp"`
	ErrorMessageFirstParagraph                        types.String         `tfsdk:"error_message_first_paragraph"`
	FaviconURL                                        types.String         `tfsdk:"favicon_url"`
	GoogleCloudServerlessAuthenticationServiceAccount types.String         `tfsdk:"google_cloud_serverless_authentication_service_account"`
	GRPCAddress                                       types.String         `tfsdk:"grpc_address"`
	GRPCInsecure                                      types.Bool           `tfsdk:"grpc_insecure"`
	HTTPRedirectAddr                                  types.String         `tfsdk:"http_redirect_addr"`
	ID                                                types.String         `tfsdk:"id"`
	IdentityProviderAuth0                             types.Object         `tfsdk:"identity_provider_auth0"`
	IdentityProviderAzure                             types.Object         `tfsdk:"identity_provider_azure"`
	IdentityProviderBlob                              types.Object         `tfsdk:"identity_provider_blob"`
	IdentityProviderCognito                           types.Object         `tfsdk:"identity_provider_cognito"`
	IdentityProviderGitHub                            types.Object         `tfsdk:"identity_provider_github"`
	IdentityProviderGitLab                            types.Object         `tfsdk:"identity_provider_gitlab"`
	IdentityProviderGoogle                            types.Object         `tfsdk:"identity_provider_google"`
	IdentityProviderOkta                              types.Object         `tfsdk:"identity_provider_okta"`
	IdentityProviderOneLogin                          types.Object         `tfsdk:"identity_provider_onelogin"`
	IdentityProviderPing                              types.Object         `tfsdk:"identity_provider_ping"`
	IdentityProviderRefreshInterval                   timetypes.GoDuration `tfsdk:"identity_provider_refresh_interval"`
	IdentityProviderRefreshTimeout                    timetypes.GoDuration `tfsdk:"identity_provider_refresh_timeout"`
	IDPAccessTokenAllowedAudiences                    types.Set            `tfsdk:"idp_access_token_allowed_audiences"`
	IdpClientID                                       types.String         `tfsdk:"idp_client_id"`
	IdpClientSecret                                   types.String         `tfsdk:"idp_client_secret"`
	IdpProvider                                       types.String         `tfsdk:"idp_provider"`
	IdpProviderURL                                    types.String         `tfsdk:"idp_provider_url"`
	IdpRefreshDirectoryInterval                       timetypes.GoDuration `tfsdk:"idp_refresh_directory_interval"`
	IdpRefreshDirectoryTimeout                        timetypes.GoDuration `tfsdk:"idp_refresh_directory_timeout"`
	IdpServiceAccount                                 types.String         `tfsdk:"idp_service_account"`
	InsecureServer                                    types.Bool           `tfsdk:"insecure_server"`
	InstallationID                                    types.String         `tfsdk:"installation_id"`
	JWTClaimsHeaders                                  types.Map            `tfsdk:"jwt_claims_headers"`
	JWTGroupsFilter                                   types.Object         `tfsdk:"jwt_groups_filter"`
	JWTIssuerFormat                                   types.String         `tfsdk:"jwt_issuer_format"`
	LogLevel                                          types.String         `tfsdk:"log_level"`
	LogoURL                                           types.String         `tfsdk:"logo_url"`
	MetricsAddress                                    types.String         `tfsdk:"metrics_address"`
	OtelAttributeValueLengthLimit                     types.Int64          `tfsdk:"otel_attribute_value_length_limit"`
	OtelBspMaxExportBatchSize                         types.Int64          `tfsdk:"otel_bsp_max_export_batch_size"`
	OtelBspScheduleDelay                              timetypes.GoDuration `tfsdk:"otel_bsp_schedule_delay"`
	OtelExporterOtlpEndpoint                          types.String         `tfsdk:"otel_exporter_otlp_endpoint"`
	OtelExporterOtlpHeaders                           types.Set            `tfsdk:"otel_exporter_otlp_headers"`
	OtelExporterOtlpProtocol                          types.String         `tfsdk:"otel_exporter_otlp_protocol"`
	OtelExporterOtlpTimeout                           timetypes.GoDuration `tfsdk:"otel_exporter_otlp_timeout"`
	OtelExporterOtlpTracesEndpoint                    types.String         `tfsdk:"otel_exporter_otlp_traces_endpoint"`
	OtelExporterOtlpTracesHeaders                     types.Set            `tfsdk:"otel_exporter_otlp_traces_headers"`
	OtelExporterOtlpTracesProtocol                    types.String         `tfsdk:"otel_exporter_otlp_traces_protocol"`
	OtelExporterOtlpTracesTimeout                     timetypes.GoDuration `tfsdk:"otel_exporter_otlp_traces_timeout"`
	OtelLogLevel                                      types.String         `tfsdk:"otel_log_level"`
	OtelResourceAttributes                            types.Set            `tfsdk:"otel_resource_attributes"`
	OtelTracesExporter                                types.String         `tfsdk:"otel_traces_exporter"`
	OtelTracesSamplerArg                              types.Float64        `tfsdk:"otel_traces_sampler_arg"`
	PassIdentityHeaders                               types.Bool           `tfsdk:"pass_identity_headers"`
	PrimaryColor                                      types.String         `tfsdk:"primary_color"`
	ProxyLogLevel                                     types.String         `tfsdk:"proxy_log_level"`
	RequestParams                                     types.Map            `tfsdk:"request_params"`
	Scopes                                            types.Set            `tfsdk:"scopes"`
	SecondaryColor                                    types.String         `tfsdk:"secondary_color"`
	SetResponseHeaders                                types.Map            `tfsdk:"set_response_headers"`
	SkipXFFAppend                                     types.Bool           `tfsdk:"skip_xff_append"`
	SSHAddress                                        types.String         `tfsdk:"ssh_address"`
	SSHHostKeyFiles                                   types.Set            `tfsdk:"ssh_host_key_files"`
	SSHHostKeys                                       types.Set            `tfsdk:"ssh_host_keys"`
	SSHUserCAKey                                      types.String         `tfsdk:"ssh_user_ca_key"`
	SSHUserCAKeyFile                                  types.String         `tfsdk:"ssh_user_ca_key_file"`
	TimeoutIdle                                       timetypes.GoDuration `tfsdk:"timeout_idle"`
	TimeoutRead                                       timetypes.GoDuration `tfsdk:"timeout_read"`
	TimeoutWrite                                      timetypes.GoDuration `tfsdk:"timeout_write"`
}

func ConvertSettingsToPB(
	ctx context.Context,
	src *SettingsModel,
) (*pb.Settings, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	dst := &pb.Settings{}

	ToStringListFromSet(ctx, &dst.AccessLogFields, src.AccessLogFields, &diagnostics)
	dst.Address = src.Address.ValueStringPointer()
	dst.AuthenticateServiceUrl = src.AuthenticateServiceURL.ValueStringPointer()
	ToStringListFromSet(ctx, &dst.AuthorizeLogFields, src.AuthorizeLogFields, &diagnostics)
	dst.AuthorizeServiceUrl = src.AuthorizeServiceURL.ValueStringPointer()
	dst.Autocert = src.Autocert.ValueBoolPointer()
	dst.AutocertDir = src.AutocertDir.ValueStringPointer()
	dst.AutocertMustStaple = src.AutocertMustStaple.ValueBoolPointer()
	dst.AutocertUseStaging = src.AutocertUseStaging.ValueBoolPointer()
	dst.BearerTokenFormat = ToBearerTokenFormat(src.BearerTokenFormat)
	dst.CacheServiceUrl = src.CacheServiceURL.ValueStringPointer()
	dst.CertificateAuthority = src.CertificateAuthority.ValueStringPointer()
	dst.CertificateAuthorityFile = src.CertificateAuthorityFile.ValueStringPointer()
	dst.CertificateAuthorityKeyPairId = src.CertificateAuthorityKeyPairID.ValueStringPointer()
	dst.CircuitBreakerThresholds = NewModelToEnterpriseConverter(&diagnostics).CircuitBreakerThresholds(src.CircuitBreakerThresholds)
	dst.ClientCa = src.ClientCA.ValueStringPointer()
	dst.ClientCaFile = src.ClientCAFile.ValueStringPointer()
	dst.ClientCaKeyPairId = src.ClientCAKeyPairID.ValueStringPointer()
	dst.ClusterId = src.ClusterID.ValueStringPointer()
	dst.CodecType = ToCodecType(src.CodecType)
	dst.CookieDomain = src.CookieDomain.ValueStringPointer()
	ToDuration(&dst.CookieExpire, src.CookieExpire, &diagnostics)
	dst.CookieHttpOnly = src.CookieHTTPOnly.ValueBoolPointer()
	dst.CookieName = src.CookieName.ValueStringPointer()
	dst.CookieSameSite = src.CookieSameSite.ValueStringPointer()
	dst.CookieSecret = src.CookieSecret.ValueStringPointer()
	dst.CookieSecure = src.CookieSecure.ValueBoolPointer()
	dst.DarkmodePrimaryColor = src.DarkmodePrimaryColor.ValueStringPointer()
	dst.DarkmodeSecondaryColor = src.DarkmodeSecondaryColor.ValueStringPointer()
	dst.DatabrokerServiceUrl = src.DatabrokerServiceURL.ValueStringPointer()
	ToDuration(&dst.DefaultUpstreamTimeout, src.DefaultUpstreamTimeout, &diagnostics)
	ToDuration(&dst.DnsFailureRefreshRate, src.DNSFailureRefreshRate, &diagnostics)
	dst.DnsLookupFamily = src.DNSLookupFamily.ValueStringPointer()
	ToDuration(&dst.DnsQueryTimeout, src.DNSQueryTimeout, &diagnostics)
	dst.DnsQueryTries = FromInt64Pointer[uint32](src.DNSQueryTries)
	ToDuration(&dst.DnsRefreshRate, src.DNSRefreshRate, &diagnostics)
	dst.DnsUdpMaxQueries = FromInt64Pointer[uint32](src.DNSUDPMaxQueries)
	dst.DnsUseTcp = src.DNSUseTCP.ValueBoolPointer()
	dst.ErrorMessageFirstParagraph = src.ErrorMessageFirstParagraph.ValueStringPointer()
	dst.FaviconUrl = src.FaviconURL.ValueStringPointer()
	dst.GoogleCloudServerlessAuthenticationServiceAccount = src.GoogleCloudServerlessAuthenticationServiceAccount.ValueStringPointer()
	dst.GrpcAddress = src.GRPCAddress.ValueStringPointer()
	dst.GrpcInsecure = src.GRPCInsecure.ValueBoolPointer()
	dst.HttpRedirectAddr = src.HTTPRedirectAddr.ValueStringPointer()
	dst.Id = src.ID.ValueString()
	IdentityProviderSettingsToPB(ctx, dst, src, &diagnostics)
	ToDuration(&dst.IdentityProviderRefreshInterval, src.IdentityProviderRefreshInterval, &diagnostics)
	ToDuration(&dst.IdentityProviderRefreshTimeout, src.IdentityProviderRefreshTimeout, &diagnostics)
	ToSettingsStringList(ctx, &dst.IdpAccessTokenAllowedAudiences, src.IDPAccessTokenAllowedAudiences, &diagnostics)
	dst.IdpClientId = src.IdpClientID.ValueStringPointer()
	dst.IdpClientSecret = src.IdpClientSecret.ValueStringPointer()
	dst.IdpProvider = src.IdpProvider.ValueStringPointer()
	dst.IdpProviderUrl = src.IdpProviderURL.ValueStringPointer()
	ToDuration(&dst.IdpRefreshDirectoryInterval, src.IdpRefreshDirectoryInterval, &diagnostics)
	ToDuration(&dst.IdpRefreshDirectoryTimeout, src.IdpRefreshDirectoryTimeout, &diagnostics)
	dst.IdpServiceAccount = src.IdpServiceAccount.ValueStringPointer()
	dst.InsecureServer = src.InsecureServer.ValueBoolPointer()
	dst.InstallationId = src.InstallationID.ValueStringPointer()
	ToStringMap(ctx, &dst.JwtClaimsHeaders, src.JWTClaimsHeaders, &diagnostics)
	dst.JwtIssuerFormat = ToIssuerFormat(src.JWTIssuerFormat, &diagnostics)
	dst.LogLevel = src.LogLevel.ValueStringPointer()
	dst.LogoUrl = src.LogoURL.ValueStringPointer()
	dst.MetricsAddress = src.MetricsAddress.ValueStringPointer()
	dst.OriginatorId = OriginatorID
	dst.PassIdentityHeaders = src.PassIdentityHeaders.ValueBoolPointer()
	dst.PrimaryColor = src.PrimaryColor.ValueStringPointer()
	dst.ProxyLogLevel = src.ProxyLogLevel.ValueStringPointer()
	ToStringMap(ctx, &dst.RequestParams, src.RequestParams, &diagnostics)
	ToStringSliceFromSet(ctx, &dst.Scopes, src.Scopes, &diagnostics)
	dst.SecondaryColor = src.SecondaryColor.ValueStringPointer()
	ToStringMap(ctx, &dst.SetResponseHeaders, src.SetResponseHeaders, &diagnostics)
	dst.SkipXffAppend = src.SkipXFFAppend.ValueBoolPointer()
	dst.SshAddress = src.SSHAddress.ValueStringPointer()
	ToSettingsStringList(ctx, &dst.SshHostKeyFiles, src.SSHHostKeyFiles, &diagnostics)
	ToSettingsStringList(ctx, &dst.SshHostKeys, src.SSHHostKeys, &diagnostics)
	dst.SshUserCaKey = src.SSHUserCAKey.ValueStringPointer()
	dst.SshUserCaKeyFile = src.SSHUserCAKeyFile.ValueStringPointer()
	ToDuration(&dst.TimeoutIdle, src.TimeoutIdle, &diagnostics)
	ToDuration(&dst.TimeoutRead, src.TimeoutRead, &diagnostics)
	ToDuration(&dst.TimeoutWrite, src.TimeoutWrite, &diagnostics)
	JWTGroupsFilterToPB(ctx, &dst.JwtGroupsFilter, src.JWTGroupsFilter, &diagnostics)

	dst.OtelTracesExporter = src.OtelTracesExporter.ValueStringPointer()
	dst.OtelTracesSamplerArg = src.OtelTracesSamplerArg.ValueFloat64Pointer()
	ToStringSliceFromSet(ctx, &dst.OtelResourceAttributes, src.OtelResourceAttributes, &diagnostics)
	dst.OtelLogLevel = src.OtelLogLevel.ValueStringPointer()
	dst.OtelAttributeValueLengthLimit = FromInt64Pointer[int32](src.OtelAttributeValueLengthLimit)
	dst.OtelExporterOtlpEndpoint = src.OtelExporterOtlpEndpoint.ValueStringPointer()
	dst.OtelExporterOtlpTracesEndpoint = src.OtelExporterOtlpTracesEndpoint.ValueStringPointer()
	dst.OtelExporterOtlpProtocol = src.OtelExporterOtlpProtocol.ValueStringPointer()
	dst.OtelExporterOtlpTracesProtocol = src.OtelExporterOtlpTracesProtocol.ValueStringPointer()
	ToStringSliceFromSet(ctx, &dst.OtelExporterOtlpHeaders, src.OtelExporterOtlpHeaders, &diagnostics)
	ToStringSliceFromSet(ctx, &dst.OtelExporterOtlpTracesHeaders, src.OtelExporterOtlpTracesHeaders, &diagnostics)
	ToDuration(&dst.OtelExporterOtlpTimeout, src.OtelExporterOtlpTimeout, &diagnostics)
	ToDuration(&dst.OtelExporterOtlpTracesTimeout, src.OtelExporterOtlpTracesTimeout, &diagnostics)
	ToDuration(&dst.OtelBspScheduleDelay, src.OtelBspScheduleDelay, &diagnostics)
	dst.OtelBspMaxExportBatchSize = FromInt64Pointer[int32](src.OtelBspMaxExportBatchSize)

	return dst, diagnostics
}

func ConvertSettingsFromPB(
	dst *SettingsModel,
	src *pb.Settings,
) diag.Diagnostics {
	var diagnostics diag.Diagnostics

	dst.AccessLogFields = FromStringListToSet(src.AccessLogFields)
	dst.Address = types.StringPointerValue(src.Address)
	dst.AuthenticateServiceURL = types.StringPointerValue(src.AuthenticateServiceUrl)
	dst.AuthorizeLogFields = FromStringListToSet(src.AuthorizeLogFields)
	dst.AuthorizeServiceURL = types.StringPointerValue(src.AuthorizeServiceUrl)
	dst.Autocert = types.BoolPointerValue(src.Autocert)
	dst.AutocertDir = types.StringPointerValue(src.AutocertDir)
	dst.AutocertMustStaple = types.BoolPointerValue(src.AutocertMustStaple)
	dst.AutocertUseStaging = types.BoolPointerValue(src.AutocertUseStaging)
	dst.BearerTokenFormat = FromBearerTokenFormat(src.BearerTokenFormat)
	dst.CacheServiceURL = types.StringPointerValue(src.CacheServiceUrl)
	dst.CertificateAuthority = types.StringPointerValue(src.CertificateAuthority)
	dst.CertificateAuthorityFile = types.StringPointerValue(src.CertificateAuthorityFile)
	dst.CertificateAuthorityKeyPairID = types.StringPointerValue(src.CertificateAuthorityKeyPairId)
	dst.CircuitBreakerThresholds = NewEnterpriseToModelConverter(&diagnostics).CircuitBreakerThresholds(src.CircuitBreakerThresholds)
	dst.ClientCA = types.StringPointerValue(src.ClientCa)
	dst.ClientCAFile = types.StringPointerValue(src.ClientCaFile)
	dst.ClientCAKeyPairID = types.StringPointerValue(src.ClientCaKeyPairId)
	dst.ClusterID = types.StringPointerValue(src.ClusterId)
	dst.CodecType = FromCodecType(src.CodecType)
	dst.CookieDomain = types.StringPointerValue(src.CookieDomain)
	dst.CookieExpire = FromDuration(src.CookieExpire)
	dst.CookieHTTPOnly = types.BoolPointerValue(src.CookieHttpOnly)
	dst.CookieName = types.StringPointerValue(src.CookieName)
	dst.CookieSameSite = types.StringPointerValue(src.CookieSameSite)
	dst.CookieSecret = types.StringPointerValue(src.CookieSecret)
	dst.CookieSecure = types.BoolPointerValue(src.CookieSecure)
	dst.DarkmodePrimaryColor = types.StringPointerValue(src.DarkmodePrimaryColor)
	dst.DarkmodeSecondaryColor = types.StringPointerValue(src.DarkmodeSecondaryColor)
	dst.DatabrokerServiceURL = types.StringPointerValue(src.DatabrokerServiceUrl)
	dst.DefaultUpstreamTimeout = FromDuration(src.DefaultUpstreamTimeout)
	dst.DNSFailureRefreshRate = FromDuration(src.DnsFailureRefreshRate)
	dst.DNSLookupFamily = types.StringPointerValue(src.DnsLookupFamily)
	dst.DNSQueryTimeout = FromDuration(src.DnsQueryTimeout)
	dst.DNSQueryTries = Int64PointerValue(src.DnsQueryTries)
	dst.DNSRefreshRate = FromDuration(src.DnsRefreshRate)
	dst.DNSUDPMaxQueries = Int64PointerValue(src.DnsUdpMaxQueries)
	dst.DNSUseTCP = types.BoolPointerValue(src.DnsUseTcp)
	dst.ErrorMessageFirstParagraph = types.StringPointerValue(src.ErrorMessageFirstParagraph)
	dst.FaviconURL = types.StringPointerValue(src.FaviconUrl)
	dst.GoogleCloudServerlessAuthenticationServiceAccount = types.StringPointerValue(src.GoogleCloudServerlessAuthenticationServiceAccount)
	dst.GRPCAddress = types.StringPointerValue(src.GrpcAddress)
	dst.GRPCInsecure = types.BoolPointerValue(src.GrpcInsecure)
	dst.HTTPRedirectAddr = types.StringPointerValue(src.HttpRedirectAddr)
	dst.ID = types.StringValue(src.Id)
	dst.IdentityProviderRefreshInterval = FromDuration(src.IdentityProviderRefreshInterval)
	dst.IdentityProviderRefreshTimeout = FromDuration(src.IdentityProviderRefreshTimeout)
	dst.IDPAccessTokenAllowedAudiences = FromStringList(src.IdpAccessTokenAllowedAudiences)
	dst.IdpClientID = types.StringPointerValue(src.IdpClientId)
	dst.IdpClientSecret = types.StringPointerValue(src.IdpClientSecret)
	dst.IdpProvider = types.StringPointerValue(src.IdpProvider)
	dst.IdpProviderURL = types.StringPointerValue(src.IdpProviderUrl)
	dst.IdpRefreshDirectoryInterval = FromDuration(src.IdpRefreshDirectoryInterval)
	dst.IdpRefreshDirectoryTimeout = FromDuration(src.IdpRefreshDirectoryTimeout)
	dst.IdpServiceAccount = types.StringPointerValue(src.IdpServiceAccount)
	dst.InsecureServer = types.BoolPointerValue(src.InsecureServer)
	dst.InstallationID = types.StringPointerValue(src.InstallationId)
	dst.JWTClaimsHeaders = FromStringMap(src.JwtClaimsHeaders)
	dst.JWTIssuerFormat = FromIssuerFormat(src.JwtIssuerFormat)
	dst.LogLevel = types.StringPointerValue(src.LogLevel)
	dst.LogoURL = types.StringPointerValue(src.LogoUrl)
	dst.MetricsAddress = types.StringPointerValue(src.MetricsAddress)
	dst.PassIdentityHeaders = types.BoolPointerValue(src.PassIdentityHeaders)
	dst.PrimaryColor = types.StringPointerValue(src.PrimaryColor)
	dst.ProxyLogLevel = types.StringPointerValue(src.ProxyLogLevel)
	dst.RequestParams = FromStringMap(src.RequestParams)
	dst.Scopes = FromStringSliceToSet(src.Scopes)
	dst.SecondaryColor = types.StringPointerValue(src.SecondaryColor)
	dst.SetResponseHeaders = FromStringMap(src.SetResponseHeaders)
	dst.SkipXFFAppend = types.BoolPointerValue(src.SkipXffAppend)
	dst.SSHAddress = types.StringPointerValue(src.SshAddress)
	dst.SSHHostKeyFiles = FromStringList(src.SshHostKeyFiles)
	dst.SSHHostKeys = FromStringList(src.SshHostKeys)
	dst.SSHUserCAKey = types.StringPointerValue(src.SshUserCaKey)
	dst.SSHUserCAKeyFile = types.StringPointerValue(src.SshUserCaKeyFile)
	dst.TimeoutIdle = FromDuration(src.TimeoutIdle)
	dst.TimeoutRead = FromDuration(src.TimeoutRead)
	dst.TimeoutWrite = FromDuration(src.TimeoutWrite)
	IdentityProviderSettingsFromPB(dst, src, &diagnostics)
	JWTGroupsFilterFromPB(&dst.JWTGroupsFilter, src.JwtGroupsFilter)

	dst.OtelTracesExporter = types.StringPointerValue(src.OtelTracesExporter)
	dst.OtelTracesSamplerArg = types.Float64PointerValue(src.OtelTracesSamplerArg)
	dst.OtelResourceAttributes = FromStringSliceToSet(src.OtelResourceAttributes)
	dst.OtelLogLevel = types.StringPointerValue(src.OtelLogLevel)
	dst.OtelAttributeValueLengthLimit = Int64PointerValue(src.OtelAttributeValueLengthLimit)
	dst.OtelExporterOtlpEndpoint = types.StringPointerValue(src.OtelExporterOtlpEndpoint)
	dst.OtelExporterOtlpTracesEndpoint = types.StringPointerValue(src.OtelExporterOtlpTracesEndpoint)
	dst.OtelExporterOtlpProtocol = types.StringPointerValue(src.OtelExporterOtlpProtocol)
	dst.OtelExporterOtlpTracesProtocol = types.StringPointerValue(src.OtelExporterOtlpTracesProtocol)
	dst.OtelExporterOtlpHeaders = FromStringSliceToSet(src.OtelExporterOtlpHeaders)
	dst.OtelExporterOtlpTracesHeaders = FromStringSliceToSet(src.OtelExporterOtlpTracesHeaders)
	dst.OtelExporterOtlpTimeout = FromDuration(src.OtelExporterOtlpTimeout)
	dst.OtelExporterOtlpTracesTimeout = FromDuration(src.OtelExporterOtlpTracesTimeout)
	dst.OtelBspScheduleDelay = FromDuration(src.OtelBspScheduleDelay)
	dst.OtelBspMaxExportBatchSize = Int64PointerValue(src.OtelBspMaxExportBatchSize)

	return diagnostics
}
