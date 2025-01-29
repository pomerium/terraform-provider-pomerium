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
	AuthenticateCallbackPath                          types.String         `tfsdk:"authenticate_callback_path"`
	AuthenticateServiceURL                            types.String         `tfsdk:"authenticate_service_url"`
	AuthorizeLogFields                                types.Set            `tfsdk:"authorize_log_fields"`
	AuthorizeServiceURL                               types.String         `tfsdk:"authorize_service_url"`
	Autocert                                          types.Bool           `tfsdk:"autocert"`
	AutocertDir                                       types.String         `tfsdk:"autocert_dir"`
	AutocertMustStaple                                types.Bool           `tfsdk:"autocert_must_staple"`
	AutocertUseStaging                                types.Bool           `tfsdk:"autocert_use_staging"`
	CacheServiceURL                                   types.String         `tfsdk:"cache_service_url"`
	CertificateAuthority                              types.String         `tfsdk:"certificate_authority"`
	CertificateAuthorityFile                          types.String         `tfsdk:"certificate_authority_file"`
	CertificateAuthorityKeyPairID                     types.String         `tfsdk:"certificate_authority_key_pair_id"`
	ClientCA                                          types.String         `tfsdk:"client_ca"`
	ClientCAFile                                      types.String         `tfsdk:"client_ca_file"`
	ClientCAKeyPairID                                 types.String         `tfsdk:"client_ca_key_pair_id"`
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
	DNSLookupFamily                                   types.String         `tfsdk:"dns_lookup_family"`
	ErrorMessageFirstParagraph                        types.String         `tfsdk:"error_message_first_paragraph"`
	FaviconURL                                        types.String         `tfsdk:"favicon_url"`
	GoogleCloudServerlessAuthenticationServiceAccount types.String         `tfsdk:"google_cloud_serverless_authentication_service_account"`
	GRPCAddress                                       types.String         `tfsdk:"grpc_address"`
	GRPCInsecure                                      types.Bool           `tfsdk:"grpc_insecure"`
	HTTPRedirectAddr                                  types.String         `tfsdk:"http_redirect_addr"`
	IdentityProviderAuth0                             types.Object         `tfsdk:"identity_provider_auth0"`
	IdentityProviderAzure                             types.Object         `tfsdk:"identity_provider_azure"`
	IdentityProviderCognito                           types.Object         `tfsdk:"identity_provider_cognito"`
	IdentityProviderGitHub                            types.Object         `tfsdk:"identity_provider_github"`
	IdentityProviderGitLab                            types.Object         `tfsdk:"identity_provider_gitlab"`
	IdentityProviderGoogle                            types.Object         `tfsdk:"identity_provider_google"`
	IdentityProviderOkta                              types.Object         `tfsdk:"identity_provider_okta"`
	IdentityProviderOneLogin                          types.Object         `tfsdk:"identity_provider_onelogin"`
	IdentityProviderPing                              types.Object         `tfsdk:"identity_provider_ping"`
	IdentityProviderRefreshInterval                   timetypes.GoDuration `tfsdk:"identity_provider_refresh_interval"`
	IdentityProviderRefreshTimeout                    timetypes.GoDuration `tfsdk:"identity_provider_refresh_timeout"`
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
	LogLevel                                          types.String         `tfsdk:"log_level"`
	LogoURL                                           types.String         `tfsdk:"logo_url"`
	MetricsAddress                                    types.String         `tfsdk:"metrics_address"`
	PassIdentityHeaders                               types.Bool           `tfsdk:"pass_identity_headers"`
	PrimaryColor                                      types.String         `tfsdk:"primary_color"`
	ProxyLogLevel                                     types.String         `tfsdk:"proxy_log_level"`
	RequestParams                                     types.Map            `tfsdk:"request_params"`
	Scopes                                            types.Set            `tfsdk:"scopes"`
	SecondaryColor                                    types.String         `tfsdk:"secondary_color"`
	SetResponseHeaders                                types.Map            `tfsdk:"set_response_headers"`
	SkipXFFAppend                                     types.Bool           `tfsdk:"skip_xff_append"`
	TimeoutIdle                                       timetypes.GoDuration `tfsdk:"timeout_idle"`
	TimeoutRead                                       timetypes.GoDuration `tfsdk:"timeout_read"`
	TimeoutWrite                                      timetypes.GoDuration `tfsdk:"timeout_write"`
	JWTGroupsFilter                                   types.Object         `tfsdk:"jwt_groups_filter"`
}

func ConvertSettingsToPB(
	ctx context.Context,
	src *SettingsModel,
) (*pb.Settings, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	pbSettings := &pb.Settings{}

	ToStringListFromSet(ctx, &pbSettings.AccessLogFields, src.AccessLogFields, &diagnostics)
	pbSettings.Address = src.Address.ValueStringPointer()
	pbSettings.AuthenticateCallbackPath = src.AuthenticateCallbackPath.ValueStringPointer()
	pbSettings.AuthenticateServiceUrl = src.AuthenticateServiceURL.ValueStringPointer()
	ToStringListFromSet(ctx, &pbSettings.AuthorizeLogFields, src.AuthorizeLogFields, &diagnostics)
	pbSettings.AuthorizeServiceUrl = src.AuthorizeServiceURL.ValueStringPointer()
	pbSettings.Autocert = src.Autocert.ValueBoolPointer()
	pbSettings.AutocertDir = src.AutocertDir.ValueStringPointer()
	pbSettings.AutocertMustStaple = src.AutocertMustStaple.ValueBoolPointer()
	pbSettings.AutocertUseStaging = src.AutocertUseStaging.ValueBoolPointer()
	pbSettings.CacheServiceUrl = src.CacheServiceURL.ValueStringPointer()
	pbSettings.CertificateAuthority = src.CertificateAuthority.ValueStringPointer()
	pbSettings.CertificateAuthorityFile = src.CertificateAuthorityFile.ValueStringPointer()
	pbSettings.CertificateAuthorityKeyPairId = src.CertificateAuthorityKeyPairID.ValueStringPointer()
	pbSettings.ClientCa = src.ClientCA.ValueStringPointer()
	pbSettings.ClientCaFile = src.ClientCAFile.ValueStringPointer()
	pbSettings.ClientCaKeyPairId = src.ClientCAKeyPairID.ValueStringPointer()
	pbSettings.CookieDomain = src.CookieDomain.ValueStringPointer()
	ToDuration(&pbSettings.CookieExpire, src.CookieExpire, &diagnostics)
	pbSettings.CookieHttpOnly = src.CookieHTTPOnly.ValueBoolPointer()
	pbSettings.CookieName = src.CookieName.ValueStringPointer()
	pbSettings.CookieSameSite = src.CookieSameSite.ValueStringPointer()
	pbSettings.CookieSecret = src.CookieSecret.ValueStringPointer()
	pbSettings.CookieSecure = src.CookieSecure.ValueBoolPointer()
	pbSettings.DarkmodePrimaryColor = src.DarkmodePrimaryColor.ValueStringPointer()
	pbSettings.DarkmodeSecondaryColor = src.DarkmodeSecondaryColor.ValueStringPointer()
	pbSettings.DatabrokerServiceUrl = src.DatabrokerServiceURL.ValueStringPointer()
	ToDuration(&pbSettings.DefaultUpstreamTimeout, src.DefaultUpstreamTimeout, &diagnostics)
	pbSettings.DnsLookupFamily = src.DNSLookupFamily.ValueStringPointer()
	pbSettings.ErrorMessageFirstParagraph = src.ErrorMessageFirstParagraph.ValueStringPointer()
	pbSettings.FaviconUrl = src.FaviconURL.ValueStringPointer()
	pbSettings.GoogleCloudServerlessAuthenticationServiceAccount = src.GoogleCloudServerlessAuthenticationServiceAccount.ValueStringPointer()
	pbSettings.GrpcAddress = src.GRPCAddress.ValueStringPointer()
	pbSettings.GrpcInsecure = src.GRPCInsecure.ValueBoolPointer()
	pbSettings.HttpRedirectAddr = src.HTTPRedirectAddr.ValueStringPointer()
	IdentityProviderSettingsToPB(ctx, pbSettings, src, &diagnostics)
	ToDuration(&pbSettings.IdentityProviderRefreshInterval, src.IdentityProviderRefreshInterval, &diagnostics)
	ToDuration(&pbSettings.IdentityProviderRefreshTimeout, src.IdentityProviderRefreshTimeout, &diagnostics)
	pbSettings.IdpClientId = src.IdpClientID.ValueStringPointer()
	pbSettings.IdpClientSecret = src.IdpClientSecret.ValueStringPointer()
	pbSettings.IdpProvider = src.IdpProvider.ValueStringPointer()
	pbSettings.IdpProviderUrl = src.IdpProviderURL.ValueStringPointer()
	ToDuration(&pbSettings.IdpRefreshDirectoryInterval, src.IdpRefreshDirectoryInterval, &diagnostics)
	ToDuration(&pbSettings.IdpRefreshDirectoryTimeout, src.IdpRefreshDirectoryTimeout, &diagnostics)
	pbSettings.IdpServiceAccount = src.IdpServiceAccount.ValueStringPointer()
	pbSettings.InsecureServer = src.InsecureServer.ValueBoolPointer()
	pbSettings.InstallationId = src.InstallationID.ValueStringPointer()
	ToStringMap(ctx, &pbSettings.JwtClaimsHeaders, src.JWTClaimsHeaders, &diagnostics)
	pbSettings.LogLevel = src.LogLevel.ValueStringPointer()
	pbSettings.LogoUrl = src.LogoURL.ValueStringPointer()
	pbSettings.MetricsAddress = src.MetricsAddress.ValueStringPointer()
	pbSettings.PassIdentityHeaders = src.PassIdentityHeaders.ValueBoolPointer()
	pbSettings.PrimaryColor = src.PrimaryColor.ValueStringPointer()
	pbSettings.ProxyLogLevel = src.ProxyLogLevel.ValueStringPointer()
	ToStringMap(ctx, &pbSettings.RequestParams, src.RequestParams, &diagnostics)
	ToStringSliceFromSet(ctx, &pbSettings.Scopes, src.Scopes, &diagnostics)
	pbSettings.SecondaryColor = src.SecondaryColor.ValueStringPointer()
	ToStringMap(ctx, &pbSettings.SetResponseHeaders, src.SetResponseHeaders, &diagnostics)
	pbSettings.SkipXffAppend = src.SkipXFFAppend.ValueBoolPointer()
	ToDuration(&pbSettings.TimeoutIdle, src.TimeoutIdle, &diagnostics)
	ToDuration(&pbSettings.TimeoutRead, src.TimeoutRead, &diagnostics)
	ToDuration(&pbSettings.TimeoutWrite, src.TimeoutWrite, &diagnostics)
	JWTGroupsFilterToPB(ctx, &pbSettings.JwtGroupsFilter, src.JWTGroupsFilter, &diagnostics)

	return pbSettings, diagnostics
}

func ConvertSettingsFromPB(
	dst *SettingsModel,
	src *pb.Settings,
) diag.Diagnostics {
	var diagnostics diag.Diagnostics

	dst.AccessLogFields = FromStringListToSet(src.AccessLogFields)
	dst.Address = types.StringPointerValue(src.Address)
	dst.AuthenticateCallbackPath = types.StringPointerValue(src.AuthenticateCallbackPath)
	dst.AuthenticateServiceURL = types.StringPointerValue(src.AuthenticateServiceUrl)
	dst.AuthorizeLogFields = FromStringListToSet(src.AuthorizeLogFields)
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
	dst.DNSLookupFamily = types.StringPointerValue(src.DnsLookupFamily)
	dst.ErrorMessageFirstParagraph = types.StringPointerValue(src.ErrorMessageFirstParagraph)
	dst.FaviconURL = types.StringPointerValue(src.FaviconUrl)
	dst.GoogleCloudServerlessAuthenticationServiceAccount = types.StringPointerValue(src.GoogleCloudServerlessAuthenticationServiceAccount)
	dst.GRPCAddress = types.StringPointerValue(src.GrpcAddress)
	dst.GRPCInsecure = types.BoolPointerValue(src.GrpcInsecure)
	dst.HTTPRedirectAddr = types.StringPointerValue(src.HttpRedirectAddr)
	IdentityProviderSettingsFromPB(dst, src, &diagnostics)
	dst.IdentityProviderRefreshInterval = FromDuration(src.IdentityProviderRefreshInterval)
	dst.IdentityProviderRefreshTimeout = FromDuration(src.IdentityProviderRefreshTimeout)
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
	dst.TimeoutIdle = FromDuration(src.TimeoutIdle)
	dst.TimeoutRead = FromDuration(src.TimeoutRead)
	dst.TimeoutWrite = FromDuration(src.TimeoutWrite)
	JWTGroupsFilterFromPB(&dst.JWTGroupsFilter, src.JwtGroupsFilter)

	return diagnostics
}
