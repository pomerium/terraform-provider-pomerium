package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/pomerium/enterprise-client-go/pb"
)

type SettingsModel struct {
	AccessLogFields                                   types.List    `tfsdk:"access_log_fields"`
	Address                                           types.String  `tfsdk:"address"`
	AuthenticateCallbackPath                          types.String  `tfsdk:"authenticate_callback_path"`
	AuthenticateServiceURL                            types.String  `tfsdk:"authenticate_service_url"`
	AuthorizeLogFields                                types.List    `tfsdk:"authorize_log_fields"`
	AuthorizeServiceURL                               types.String  `tfsdk:"authorize_service_url"`
	Autocert                                          types.Bool    `tfsdk:"autocert"`
	AutocertDir                                       types.String  `tfsdk:"autocert_dir"`
	AutocertMustStaple                                types.Bool    `tfsdk:"autocert_must_staple"`
	AutocertUseStaging                                types.Bool    `tfsdk:"autocert_use_staging"`
	CacheServiceURL                                   types.String  `tfsdk:"cache_service_url"`
	CertificateAuthority                              types.String  `tfsdk:"certificate_authority"`
	CertificateAuthorityFile                          types.String  `tfsdk:"certificate_authority_file"`
	CertificateAuthorityKeyPairID                     types.String  `tfsdk:"certificate_authority_key_pair_id"`
	ClientCA                                          types.String  `tfsdk:"client_ca"`
	ClientCAFile                                      types.String  `tfsdk:"client_ca_file"`
	ClientCAKeyPairID                                 types.String  `tfsdk:"client_ca_key_pair_id"`
	CookieDomain                                      types.String  `tfsdk:"cookie_domain"`
	CookieExpire                                      types.String  `tfsdk:"cookie_expire"`
	CookieHTTPOnly                                    types.Bool    `tfsdk:"cookie_http_only"`
	CookieName                                        types.String  `tfsdk:"cookie_name"`
	CookieSameSite                                    types.String  `tfsdk:"cookie_same_site"`
	CookieSecret                                      types.String  `tfsdk:"cookie_secret"`
	CookieSecure                                      types.Bool    `tfsdk:"cookie_secure"`
	DarkmodePrimaryColor                              types.String  `tfsdk:"darkmode_primary_color"`
	DarkmodeSecondaryColor                            types.String  `tfsdk:"darkmode_secondary_color"`
	DatabrokerServiceURL                              types.String  `tfsdk:"databroker_service_url"`
	DefaultUpstreamTimeout                            types.String  `tfsdk:"default_upstream_timeout"`
	DNSLookupFamily                                   types.String  `tfsdk:"dns_lookup_family"`
	ErrorMessageFirstParagraph                        types.String  `tfsdk:"error_message_first_paragraph"`
	FaviconURL                                        types.String  `tfsdk:"favicon_url"`
	GoogleCloudServerlessAuthenticationServiceAccount types.String  `tfsdk:"google_cloud_serverless_authentication_service_account"`
	GRPCAddress                                       types.String  `tfsdk:"grpc_address"`
	GRPCInsecure                                      types.Bool    `tfsdk:"grpc_insecure"`
	HTTPRedirectAddr                                  types.String  `tfsdk:"http_redirect_addr"`
	IdentityProvider                                  types.String  `tfsdk:"identity_provider"`
	IdentityProviderOptions                           types.Map     `tfsdk:"identity_provider_options"`
	IdentityProviderRefreshInterval                   types.String  `tfsdk:"identity_provider_refresh_interval"`
	IdentityProviderRefreshTimeout                    types.String  `tfsdk:"identity_provider_refresh_timeout"`
	IdpClientID                                       types.String  `tfsdk:"idp_client_id"`
	IdpClientSecret                                   types.String  `tfsdk:"idp_client_secret"`
	IdpProvider                                       types.String  `tfsdk:"idp_provider"`
	IdpProviderURL                                    types.String  `tfsdk:"idp_provider_url"`
	IdpRefreshDirectoryInterval                       types.String  `tfsdk:"idp_refresh_directory_interval"`
	IdpRefreshDirectoryTimeout                        types.String  `tfsdk:"idp_refresh_directory_timeout"`
	IdpServiceAccount                                 types.String  `tfsdk:"idp_service_account"`
	InsecureServer                                    types.Bool    `tfsdk:"insecure_server"`
	InstallationID                                    types.String  `tfsdk:"installation_id"`
	JWTClaimsHeaders                                  types.Map     `tfsdk:"jwt_claims_headers"`
	LogLevel                                          types.String  `tfsdk:"log_level"`
	LogoURL                                           types.String  `tfsdk:"logo_url"`
	MetricsAddress                                    types.String  `tfsdk:"metrics_address"`
	PassIdentityHeaders                               types.Bool    `tfsdk:"pass_identity_headers"`
	PrimaryColor                                      types.String  `tfsdk:"primary_color"`
	ProxyLogLevel                                     types.String  `tfsdk:"proxy_log_level"`
	RequestParams                                     types.Map     `tfsdk:"request_params"`
	Scopes                                            types.List    `tfsdk:"scopes"`
	SecondaryColor                                    types.String  `tfsdk:"secondary_color"`
	Services                                          types.String  `tfsdk:"services"`
	SetResponseHeaders                                types.Map     `tfsdk:"set_response_headers"`
	SharedSecret                                      types.String  `tfsdk:"shared_secret"`
	SkipXFFAppend                                     types.Bool    `tfsdk:"skip_xff_append"`
	TimeoutIdle                                       types.String  `tfsdk:"timeout_idle"`
	TimeoutRead                                       types.String  `tfsdk:"timeout_read"`
	TimeoutWrite                                      types.String  `tfsdk:"timeout_write"`
	TracingDatadogAddress                             types.String  `tfsdk:"tracing_datadog_address"`
	TracingJaegerAgentEndpoint                        types.String  `tfsdk:"tracing_jaeger_agent_endpoint"`
	TracingJaegerCollectorEndpoint                    types.String  `tfsdk:"tracing_jaeger_collector_endpoint"`
	TracingProvider                                   types.String  `tfsdk:"tracing_provider"`
	TracingSampleRate                                 types.Float64 `tfsdk:"tracing_sample_rate"`
	TracingZipkinEndpoint                             types.String  `tfsdk:"tracing_zipkin_endpoint"`
}

func ConvertSettingsToPB(
	ctx context.Context,
	src *SettingsModel,
) (*pb.Settings, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	pbSettings := &pb.Settings{}

	ToStringList(ctx, &pbSettings.AccessLogFields, src.AccessLogFields, &diagnostics)
	pbSettings.Address = StringP(src.Address)
	pbSettings.AuthenticateCallbackPath = StringP(src.AuthenticateCallbackPath)
	pbSettings.AuthenticateServiceUrl = StringP(src.AuthenticateServiceURL)
	ToStringList(ctx, &pbSettings.AuthorizeLogFields, src.AuthorizeLogFields, &diagnostics)
	pbSettings.AuthorizeServiceUrl = StringP(src.AuthorizeServiceURL)
	pbSettings.Autocert = BoolP(src.Autocert)
	pbSettings.AutocertDir = StringP(src.AutocertDir)
	pbSettings.AutocertMustStaple = BoolP(src.AutocertMustStaple)
	pbSettings.AutocertUseStaging = BoolP(src.AutocertUseStaging)
	pbSettings.CacheServiceUrl = StringP(src.CacheServiceURL)
	pbSettings.CertificateAuthority = StringP(src.CertificateAuthority)
	pbSettings.CertificateAuthorityFile = StringP(src.CertificateAuthorityFile)
	pbSettings.CertificateAuthorityKeyPairId = StringP(src.CertificateAuthorityKeyPairID)
	pbSettings.ClientCa = StringP(src.ClientCA)
	pbSettings.ClientCaFile = StringP(src.ClientCAFile)
	pbSettings.ClientCaKeyPairId = StringP(src.ClientCAKeyPairID)
	pbSettings.CookieDomain = StringP(src.CookieDomain)
	ToDurationP(&pbSettings.CookieExpire, src.CookieExpire, "cookie_expire", &diagnostics)
	pbSettings.CookieHttpOnly = BoolP(src.CookieHTTPOnly)
	pbSettings.CookieName = StringP(src.CookieName)
	pbSettings.CookieSameSite = StringP(src.CookieSameSite)
	pbSettings.CookieSecret = StringP(src.CookieSecret)
	pbSettings.CookieSecure = BoolP(src.CookieSecure)
	pbSettings.DarkmodePrimaryColor = StringP(src.DarkmodePrimaryColor)
	pbSettings.DarkmodeSecondaryColor = StringP(src.DarkmodeSecondaryColor)
	pbSettings.DatabrokerServiceUrl = StringP(src.DatabrokerServiceURL)
	ToDurationP(&pbSettings.DefaultUpstreamTimeout, src.DefaultUpstreamTimeout, "default_upstream_timeout", &diagnostics)
	pbSettings.DnsLookupFamily = StringP(src.DNSLookupFamily)
	pbSettings.ErrorMessageFirstParagraph = StringP(src.ErrorMessageFirstParagraph)
	pbSettings.FaviconUrl = StringP(src.FaviconURL)
	pbSettings.GoogleCloudServerlessAuthenticationServiceAccount = StringP(src.GoogleCloudServerlessAuthenticationServiceAccount)
	pbSettings.GrpcAddress = StringP(src.GRPCAddress)
	pbSettings.GrpcInsecure = BoolP(src.GRPCInsecure)
	pbSettings.HttpRedirectAddr = StringP(src.HTTPRedirectAddr)
	pbSettings.IdentityProvider = StringP(src.IdentityProvider)
	ToDurationP(&pbSettings.IdentityProviderRefreshInterval, src.IdentityProviderRefreshInterval, "identity_provider_refresh_interval", &diagnostics)
	ToDurationP(&pbSettings.IdentityProviderRefreshTimeout, src.IdentityProviderRefreshTimeout, "identity_provider_refresh_timeout", &diagnostics)
	pbSettings.IdpClientId = StringP(src.IdpClientID)
	pbSettings.IdpClientSecret = StringP(src.IdpClientSecret)
	pbSettings.IdpProvider = StringP(src.IdpProvider)
	pbSettings.IdpProviderUrl = StringP(src.IdpProviderURL)
	ToDurationP(&pbSettings.IdpRefreshDirectoryInterval, src.IdpRefreshDirectoryInterval, "idp_refresh_directory_interval", &diagnostics)
	ToDurationP(&pbSettings.IdpRefreshDirectoryTimeout, src.IdpRefreshDirectoryTimeout, "idp_refresh_directory_timeout", &diagnostics)
	pbSettings.IdpServiceAccount = StringP(src.IdpServiceAccount)
	pbSettings.InsecureServer = BoolP(src.InsecureServer)
	pbSettings.InstallationId = StringP(src.InstallationID)
	ToStringMap(ctx, &pbSettings.JwtClaimsHeaders, src.JWTClaimsHeaders, &diagnostics)
	pbSettings.LogLevel = StringP(src.LogLevel)
	pbSettings.LogoUrl = StringP(src.LogoURL)
	pbSettings.MetricsAddress = StringP(src.MetricsAddress)
	pbSettings.PassIdentityHeaders = BoolP(src.PassIdentityHeaders)
	pbSettings.PrimaryColor = StringP(src.PrimaryColor)
	pbSettings.ProxyLogLevel = StringP(src.ProxyLogLevel)
	ToStringMap(ctx, &pbSettings.RequestParams, src.RequestParams, &diagnostics)
	ToStringSlice(ctx, &pbSettings.Scopes, src.Scopes, &diagnostics)
	pbSettings.SecondaryColor = StringP(src.SecondaryColor)
	pbSettings.Services = StringP(src.Services)
	ToStringMap(ctx, &pbSettings.SetResponseHeaders, src.SetResponseHeaders, &diagnostics)
	pbSettings.SharedSecret = StringP(src.SharedSecret)
	pbSettings.SkipXffAppend = BoolP(src.SkipXFFAppend)
	ToDurationP(&pbSettings.TimeoutIdle, src.TimeoutIdle, "timeout_idle", &diagnostics)
	ToDurationP(&pbSettings.TimeoutRead, src.TimeoutRead, "timeout_read", &diagnostics)
	ToDurationP(&pbSettings.TimeoutWrite, src.TimeoutWrite, "timeout_write", &diagnostics)
	pbSettings.TracingDatadogAddress = StringP(src.TracingDatadogAddress)
	pbSettings.TracingJaegerAgentEndpoint = StringP(src.TracingJaegerAgentEndpoint)
	pbSettings.TracingJaegerCollectorEndpoint = StringP(src.TracingJaegerCollectorEndpoint)
	pbSettings.TracingProvider = StringP(src.TracingProvider)
	pbSettings.TracingSampleRate = Float64P(src.TracingSampleRate)
	pbSettings.TracingZipkinEndpoint = StringP(src.TracingZipkinEndpoint)

	return pbSettings, diagnostics
}

func ConvertSettingsFromPB(
	dst *SettingsModel,
	src *pb.Settings,
) diag.Diagnostics {
	var diagnostics diag.Diagnostics

	dst.AccessLogFields = FromStringList(src.AccessLogFields)
	dst.Address = types.StringPointerValue(src.Address)
	dst.AuthenticateCallbackPath = types.StringPointerValue(src.AuthenticateCallbackPath)
	dst.AuthenticateServiceURL = types.StringPointerValue(src.AuthenticateServiceUrl)
	dst.AuthorizeLogFields = FromStringList(src.AuthorizeLogFields)
	dst.AuthorizeServiceURL = types.StringPointerValue(src.AuthorizeServiceUrl)
	dst.Autocert = types.BoolPointerValue(src.Autocert)
	dst.AutocertDir = types.StringPointerValue(src.AutocertDir)
	dst.AutocertMustStaple = types.BoolPointerValue(src.AutocertMustStaple)
	dst.AutocertUseStaging = types.BoolPointerValue(src.AutocertUseStaging)
	dst.CacheServiceURL = types.StringPointerValue(src.CacheServiceUrl)
	dst.CertificateAuthority = types.StringPointerValue(src.CertificateAuthority)
	dst.CertificateAuthorityFile = types.StringPointerValue(src.CertificateAuthorityFile)
	dst.CertificateAuthorityKeyPairID = types.StringPointerValue(src.CertificateAuthorityKeyPairId)
	dst.ClientCA = types.StringPointerValue(src.ClientCa)
	dst.ClientCAFile = types.StringPointerValue(src.ClientCaFile)
	dst.ClientCAKeyPairID = types.StringPointerValue(src.ClientCaKeyPairId)
	dst.CookieDomain = types.StringPointerValue(src.CookieDomain)
	dst.CookieExpire = FromDurationP(src.CookieExpire)
	dst.CookieHTTPOnly = types.BoolPointerValue(src.CookieHttpOnly)
	dst.CookieName = types.StringPointerValue(src.CookieName)
	dst.CookieSameSite = types.StringPointerValue(src.CookieSameSite)
	dst.CookieSecret = types.StringPointerValue(src.CookieSecret)
	dst.CookieSecure = types.BoolPointerValue(src.CookieSecure)
	dst.DarkmodePrimaryColor = types.StringPointerValue(src.DarkmodePrimaryColor)
	dst.DarkmodeSecondaryColor = types.StringPointerValue(src.DarkmodeSecondaryColor)
	dst.DatabrokerServiceURL = types.StringPointerValue(src.DatabrokerServiceUrl)
	dst.DefaultUpstreamTimeout = FromDurationP(src.DefaultUpstreamTimeout)
	dst.DNSLookupFamily = types.StringPointerValue(src.DnsLookupFamily)
	dst.ErrorMessageFirstParagraph = types.StringPointerValue(src.ErrorMessageFirstParagraph)
	dst.FaviconURL = types.StringPointerValue(src.FaviconUrl)
	dst.GoogleCloudServerlessAuthenticationServiceAccount = types.StringPointerValue(src.GoogleCloudServerlessAuthenticationServiceAccount)
	dst.GRPCAddress = types.StringPointerValue(src.GrpcAddress)
	dst.GRPCInsecure = types.BoolPointerValue(src.GrpcInsecure)
	dst.HTTPRedirectAddr = types.StringPointerValue(src.HttpRedirectAddr)
	dst.IdentityProvider = types.StringPointerValue(src.IdentityProvider)
	dst.IdentityProviderRefreshInterval = FromDurationP(src.IdentityProviderRefreshInterval)
	dst.IdentityProviderRefreshTimeout = FromDurationP(src.IdentityProviderRefreshTimeout)
	dst.IdpClientID = types.StringPointerValue(src.IdpClientId)
	dst.IdpClientSecret = types.StringPointerValue(src.IdpClientSecret)
	dst.IdpProvider = types.StringPointerValue(src.IdpProvider)
	dst.IdpProviderURL = types.StringPointerValue(src.IdpProviderUrl)
	dst.IdpRefreshDirectoryInterval = FromDurationP(src.IdpRefreshDirectoryInterval)
	dst.IdpRefreshDirectoryTimeout = FromDurationP(src.IdpRefreshDirectoryTimeout)
	dst.IdpServiceAccount = types.StringPointerValue(src.IdpServiceAccount)
	dst.InsecureServer = types.BoolPointerValue(src.InsecureServer)
	dst.InstallationID = types.StringPointerValue(src.InstallationId)
	dst.JWTClaimsHeaders = FromStringMap(src.JwtClaimsHeaders)
	dst.LogLevel = types.StringPointerValue(src.LogLevel)
	dst.LogoURL = types.StringPointerValue(src.LogoUrl)
	dst.MetricsAddress = types.StringPointerValue(src.MetricsAddress)
	dst.PassIdentityHeaders = types.BoolPointerValue(src.PassIdentityHeaders)
	dst.PrimaryColor = types.StringPointerValue(src.PrimaryColor)
	dst.ProxyLogLevel = types.StringPointerValue(src.ProxyLogLevel)
	dst.RequestParams = FromStringMap(src.RequestParams)
	dst.Scopes = FromStringSlice(src.Scopes)
	dst.SecondaryColor = types.StringPointerValue(src.SecondaryColor)
	dst.Services = types.StringPointerValue(src.Services)
	dst.SetResponseHeaders = FromStringMap(src.SetResponseHeaders)
	dst.SharedSecret = types.StringPointerValue(src.SharedSecret)
	dst.SkipXFFAppend = types.BoolPointerValue(src.SkipXffAppend)
	dst.TimeoutIdle = FromDurationP(src.TimeoutIdle)
	dst.TimeoutRead = FromDurationP(src.TimeoutRead)
	dst.TimeoutWrite = FromDurationP(src.TimeoutWrite)
	dst.TracingDatadogAddress = types.StringPointerValue(src.TracingDatadogAddress)
	dst.TracingJaegerAgentEndpoint = types.StringPointerValue(src.TracingJaegerAgentEndpoint)
	dst.TracingJaegerCollectorEndpoint = types.StringPointerValue(src.TracingJaegerCollectorEndpoint)
	dst.TracingProvider = types.StringPointerValue(src.TracingProvider)
	dst.TracingSampleRate = types.Float64PointerValue(src.TracingSampleRate)
	dst.TracingZipkinEndpoint = types.StringPointerValue(src.TracingZipkinEndpoint)

	return diagnostics
}
