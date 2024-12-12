package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/pomerium/enterprise-client-go/pb"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
)

type SettingsModel struct {
	InstallationID                                    types.String  `tfsdk:"installation_id"`
	LogLevel                                          types.String  `tfsdk:"log_level"`
	ProxyLogLevel                                     types.String  `tfsdk:"proxy_log_level"`
	SharedSecret                                      types.String  `tfsdk:"shared_secret"`
	Services                                          types.String  `tfsdk:"services"`
	Address                                           types.String  `tfsdk:"address"`
	InsecureServer                                    types.Bool    `tfsdk:"insecure_server"`
	DNSLookupFamily                                   types.String  `tfsdk:"dns_lookup_family"`
	HTTPRedirectAddr                                  types.String  `tfsdk:"http_redirect_addr"`
	TimeoutRead                                       types.String  `tfsdk:"timeout_read"`
	TimeoutWrite                                      types.String  `tfsdk:"timeout_write"`
	TimeoutIdle                                       types.String  `tfsdk:"timeout_idle"`
	AuthenticateServiceURL                            types.String  `tfsdk:"authenticate_service_url"`
	AuthenticateCallbackPath                          types.String  `tfsdk:"authenticate_callback_path"`
	CookieName                                        types.String  `tfsdk:"cookie_name"`
	CookieSecret                                      types.String  `tfsdk:"cookie_secret"`
	CookieDomain                                      types.String  `tfsdk:"cookie_domain"`
	CookieSecure                                      types.Bool    `tfsdk:"cookie_secure"`
	CookieHTTPOnly                                    types.Bool    `tfsdk:"cookie_http_only"`
	CookieSameSite                                    types.String  `tfsdk:"cookie_same_site"`
	CookieExpire                                      types.String  `tfsdk:"cookie_expire"`
	IdpClientID                                       types.String  `tfsdk:"idp_client_id"`
	IdpClientSecret                                   types.String  `tfsdk:"idp_client_secret"`
	IdpProvider                                       types.String  `tfsdk:"idp_provider"`
	IdpProviderURL                                    types.String  `tfsdk:"idp_provider_url"`
	Scopes                                            types.List    `tfsdk:"scopes"`
	IdpServiceAccount                                 types.String  `tfsdk:"idp_service_account"`
	IdpRefreshDirectoryTimeout                        types.String  `tfsdk:"idp_refresh_directory_timeout"`
	IdpRefreshDirectoryInterval                       types.String  `tfsdk:"idp_refresh_directory_interval"`
	RequestParams                                     types.Map     `tfsdk:"request_params"`
	AuthorizeServiceURL                               types.String  `tfsdk:"authorize_service_url"`
	CertificateAuthority                              types.String  `tfsdk:"certificate_authority"`
	CertificateAuthorityFile                          types.String  `tfsdk:"certificate_authority_file"`
	CertificateAuthorityKeyPairID                     types.String  `tfsdk:"certificate_authority_key_pair_id"`
	SetResponseHeaders                                types.Map     `tfsdk:"set_response_headers"`
	JWTClaimsHeaders                                  types.Map     `tfsdk:"jwt_claims_headers"`
	DefaultUpstreamTimeout                            types.String  `tfsdk:"default_upstream_timeout"`
	MetricsAddress                                    types.String  `tfsdk:"metrics_address"`
	TracingProvider                                   types.String  `tfsdk:"tracing_provider"`
	TracingSampleRate                                 types.Float64 `tfsdk:"tracing_sample_rate"`
	TracingDatadogAddress                             types.String  `tfsdk:"tracing_datadog_address"`
	TracingJaegerCollectorEndpoint                    types.String  `tfsdk:"tracing_jaeger_collector_endpoint"`
	TracingJaegerAgentEndpoint                        types.String  `tfsdk:"tracing_jaeger_agent_endpoint"`
	TracingZipkinEndpoint                             types.String  `tfsdk:"tracing_zipkin_endpoint"`
	GRPCAddress                                       types.String  `tfsdk:"grpc_address"`
	GRPCInsecure                                      types.Bool    `tfsdk:"grpc_insecure"`
	CacheServiceURL                                   types.String  `tfsdk:"cache_service_url"`
	DatabrokerServiceURL                              types.String  `tfsdk:"databroker_service_url"`
	ClientCA                                          types.String  `tfsdk:"client_ca"`
	ClientCAFile                                      types.String  `tfsdk:"client_ca_file"`
	ClientCAKeyPairID                                 types.String  `tfsdk:"client_ca_key_pair_id"`
	GoogleCloudServerlessAuthenticationServiceAccount types.String  `tfsdk:"google_cloud_serverless_authentication_service_account"`
	Autocert                                          types.Bool    `tfsdk:"autocert"`
	AutocertUseStaging                                types.Bool    `tfsdk:"autocert_use_staging"`
	AutocertMustStaple                                types.Bool    `tfsdk:"autocert_must_staple"`
	AutocertDir                                       types.String  `tfsdk:"autocert_dir"`
	SkipXFFAppend                                     types.Bool    `tfsdk:"skip_xff_append"`
	PrimaryColor                                      types.String  `tfsdk:"primary_color"`
	SecondaryColor                                    types.String  `tfsdk:"secondary_color"`
	DarkmodePrimaryColor                              types.String  `tfsdk:"darkmode_primary_color"`
	DarkmodeSecondaryColor                            types.String  `tfsdk:"darkmode_secondary_color"`
	LogoURL                                           types.String  `tfsdk:"logo_url"`
	FaviconURL                                        types.String  `tfsdk:"favicon_url"`
	ErrorMessageFirstParagraph                        types.String  `tfsdk:"error_message_first_paragraph"`
	IdentityProvider                                  types.String  `tfsdk:"identity_provider"`
	IdentityProviderOptions                           types.Map     `tfsdk:"identity_provider_options"`
	IdentityProviderRefreshInterval                   types.String  `tfsdk:"identity_provider_refresh_interval"`
	IdentityProviderRefreshTimeout                    types.String  `tfsdk:"identity_provider_refresh_timeout"`
	AccessLogFields                                   types.List    `tfsdk:"access_log_fields"`
	AuthorizeLogFields                                types.List    `tfsdk:"authorize_log_fields"`
	PassIdentityHeaders                               types.Bool    `tfsdk:"pass_identity_headers"`
}

func ConvertSettingsToPB(
	ctx context.Context,
	src *SettingsModel,
) (*pb.Settings, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	pbSettings := &pb.Settings{}

	if src.InstallationID.IsNull() {
		diagnostics.AddError("installation_id", "installation_id is required")
	}

	// Convert simple fields
	pbSettings.InstallationId = OptionalString(src.InstallationID)
	pbSettings.LogLevel = OptionalString(src.LogLevel)
	pbSettings.ProxyLogLevel = OptionalString(src.ProxyLogLevel)
	pbSettings.SharedSecret = OptionalString(src.SharedSecret)
	pbSettings.Services = OptionalString(src.Services)
	pbSettings.Address = OptionalString(src.Address)
	pbSettings.InsecureServer = OptionalBool(src.InsecureServer)
	pbSettings.TracingSampleRate = OptionalFloat64(src.TracingSampleRate)

	// Handle map fields
	if !src.RequestParams.IsNull() {
		params := make(map[string]string)
		diagnostics.Append(src.RequestParams.ElementsAs(ctx, &params, false)...)
		pbSettings.RequestParams = params
	}

	// Handle list fields
	if !src.Scopes.IsNull() {
		var scopes []string
		diagnostics.Append(src.Scopes.ElementsAs(ctx, &scopes, false)...)
		pbSettings.Scopes = scopes
	}

	// Handle duration fields
	if !src.TimeoutRead.IsNull() {
		if d, err := time.ParseDuration(src.TimeoutRead.ValueString()); err == nil {
			pbSettings.TimeoutRead = durationpb.New(d)
		} else {
			diagnostics.AddError("invalid timeout_read", err.Error())
		}
	}
	if !src.TimeoutWrite.IsNull() {
		if d, err := time.ParseDuration(src.TimeoutWrite.ValueString()); err == nil {
			pbSettings.TimeoutWrite = durationpb.New(d)
		} else {
			diagnostics.AddError("invalid timeout_write", err.Error())
		}
	}
	if !src.TimeoutIdle.IsNull() {
		if d, err := time.ParseDuration(src.TimeoutIdle.ValueString()); err == nil {
			pbSettings.TimeoutIdle = durationpb.New(d)
		} else {
			diagnostics.AddError("invalid timeout_idle", err.Error())
		}
	}
	if !src.CookieExpire.IsNull() {
		if d, err := time.ParseDuration(src.CookieExpire.ValueString()); err == nil {
			pbSettings.CookieExpire = durationpb.New(d)
		} else {
			diagnostics.AddError("invalid cookie_expire", err.Error())
		}
	}
	// Complete remaining duration fields
	if !src.IdpRefreshDirectoryTimeout.IsNull() {
		if d, err := time.ParseDuration(src.IdpRefreshDirectoryTimeout.ValueString()); err == nil {
			pbSettings.IdpRefreshDirectoryTimeout = durationpb.New(d)
		} else {
			diagnostics.AddError("invalid idp_refresh_directory_timeout", err.Error())
		}
	}
	if !src.IdpRefreshDirectoryInterval.IsNull() {
		if d, err := time.ParseDuration(src.IdpRefreshDirectoryInterval.ValueString()); err == nil {
			pbSettings.IdpRefreshDirectoryInterval = durationpb.New(d)
		} else {
			diagnostics.AddError("invalid idp_refresh_directory_interval", err.Error())
		}
	}
	if !src.DefaultUpstreamTimeout.IsNull() {
		if d, err := time.ParseDuration(src.DefaultUpstreamTimeout.ValueString()); err == nil {
			pbSettings.DefaultUpstreamTimeout = durationpb.New(d)
		} else {
			diagnostics.AddError("invalid default_upstream_timeout", err.Error())
		}
	}
	if !src.IdentityProviderRefreshInterval.IsNull() {
		if d, err := time.ParseDuration(src.IdentityProviderRefreshInterval.ValueString()); err == nil {
			pbSettings.IdentityProviderRefreshInterval = durationpb.New(d)
		} else {
			diagnostics.AddError("invalid identity_provider_refresh_interval", err.Error())
		}
	}
	if !src.IdentityProviderRefreshTimeout.IsNull() {
		if d, err := time.ParseDuration(src.IdentityProviderRefreshTimeout.ValueString()); err == nil {
			pbSettings.IdentityProviderRefreshTimeout = durationpb.New(d)
		} else {
			diagnostics.AddError("invalid identity_provider_refresh_timeout", err.Error())
		}
	}

	// Handle identity provider options
	if !src.IdentityProviderOptions.IsNull() {
		var options map[string]interface{}
		diagnostics.Append(src.IdentityProviderOptions.ElementsAs(ctx, &options, false)...)
		if s, err := structpb.NewStruct(options); err == nil {
			pbSettings.IdentityProviderOptions = s
		} else {
			diagnostics.AddError("invalid identity_provider_options", err.Error())
		}
	}

	// Handle StringList fields
	if !src.AccessLogFields.IsNull() {
		var fields []string
		diagnostics.Append(src.AccessLogFields.ElementsAs(ctx, &fields, false)...)
		if !diagnostics.HasError() {
			pbSettings.AccessLogFields = &pb.Settings_StringList{Values: fields}
		}
	}
	// ... similar for authorize_log_fields

	// Handle remaining map fields
	if !src.SetResponseHeaders.IsNull() {
		headers := make(map[string]string)
		diagnostics.Append(src.SetResponseHeaders.ElementsAs(ctx, &headers, false)...)
		pbSettings.SetResponseHeaders = headers
	}
	if !src.JWTClaimsHeaders.IsNull() {
		headers := make(map[string]string)
		diagnostics.Append(src.JWTClaimsHeaders.ElementsAs(ctx, &headers, false)...)
		pbSettings.JwtClaimsHeaders = headers
	}

	// Handle remaining simple fields
	pbSettings.DnsLookupFamily = OptionalString(src.DNSLookupFamily)
	pbSettings.HttpRedirectAddr = OptionalString(src.HTTPRedirectAddr)
	pbSettings.AuthenticateServiceUrl = OptionalString(src.AuthenticateServiceURL)
	pbSettings.AuthenticateCallbackPath = OptionalString(src.AuthenticateCallbackPath)
	pbSettings.CookieName = OptionalString(src.CookieName)
	pbSettings.CookieSecret = OptionalString(src.CookieSecret)
	pbSettings.CookieDomain = OptionalString(src.CookieDomain)
	pbSettings.CookieSecure = OptionalBool(src.CookieSecure)
	pbSettings.CookieHttpOnly = OptionalBool(src.CookieHTTPOnly)
	pbSettings.CookieSameSite = OptionalString(src.CookieSameSite)
	// ... and so on for all remaining string/bool fields

	// Handle AuthorizeLogFields
	if !src.AuthorizeLogFields.IsNull() {
		var fields []string
		diagnostics.Append(src.AuthorizeLogFields.ElementsAs(ctx, &fields, false)...)
		if !diagnostics.HasError() {
			pbSettings.AuthorizeLogFields = &pb.Settings_StringList{Values: fields}
		}
	}

	// Add missing string fields
	pbSettings.IdpClientId = OptionalString(src.IdpClientID)
	pbSettings.IdpClientSecret = OptionalString(src.IdpClientSecret)
	pbSettings.IdpProvider = OptionalString(src.IdpProvider)
	pbSettings.IdpProviderUrl = OptionalString(src.IdpProviderURL)
	pbSettings.IdpServiceAccount = OptionalString(src.IdpServiceAccount)
	pbSettings.AuthorizeServiceUrl = OptionalString(src.AuthorizeServiceURL)
	pbSettings.CertificateAuthority = OptionalString(src.CertificateAuthority)
	pbSettings.CertificateAuthorityFile = OptionalString(src.CertificateAuthorityFile)
	pbSettings.CertificateAuthorityKeyPairId = OptionalString(src.CertificateAuthorityKeyPairID)
	pbSettings.MetricsAddress = OptionalString(src.MetricsAddress)
	pbSettings.TracingProvider = OptionalString(src.TracingProvider)
	pbSettings.TracingDatadogAddress = OptionalString(src.TracingDatadogAddress)
	pbSettings.TracingJaegerCollectorEndpoint = OptionalString(src.TracingJaegerCollectorEndpoint)
	pbSettings.TracingJaegerAgentEndpoint = OptionalString(src.TracingJaegerAgentEndpoint)
	pbSettings.TracingZipkinEndpoint = OptionalString(src.TracingZipkinEndpoint)
	pbSettings.GrpcAddress = OptionalString(src.GRPCAddress)
	pbSettings.CacheServiceUrl = OptionalString(src.CacheServiceURL)
	pbSettings.DatabrokerServiceUrl = OptionalString(src.DatabrokerServiceURL)
	pbSettings.ClientCa = OptionalString(src.ClientCA)
	pbSettings.ClientCaFile = OptionalString(src.ClientCAFile)
	pbSettings.ClientCaKeyPairId = OptionalString(src.ClientCAKeyPairID)
	pbSettings.GoogleCloudServerlessAuthenticationServiceAccount = OptionalString(src.GoogleCloudServerlessAuthenticationServiceAccount)
	pbSettings.AutocertDir = OptionalString(src.AutocertDir)
	pbSettings.PrimaryColor = OptionalString(src.PrimaryColor)
	pbSettings.SecondaryColor = OptionalString(src.SecondaryColor)
	pbSettings.DarkmodePrimaryColor = OptionalString(src.DarkmodePrimaryColor)
	pbSettings.DarkmodeSecondaryColor = OptionalString(src.DarkmodeSecondaryColor)
	pbSettings.LogoUrl = OptionalString(src.LogoURL)
	pbSettings.FaviconUrl = OptionalString(src.FaviconURL)
	pbSettings.ErrorMessageFirstParagraph = OptionalString(src.ErrorMessageFirstParagraph)
	pbSettings.IdentityProvider = OptionalString(src.IdentityProvider)

	// Add missing bool fields
	pbSettings.GrpcInsecure = OptionalBool(src.GRPCInsecure)
	pbSettings.Autocert = OptionalBool(src.Autocert)
	pbSettings.AutocertUseStaging = OptionalBool(src.AutocertUseStaging)
	pbSettings.AutocertMustStaple = OptionalBool(src.AutocertMustStaple)
	pbSettings.SkipXffAppend = OptionalBool(src.SkipXFFAppend)
	pbSettings.PassIdentityHeaders = OptionalBool(src.PassIdentityHeaders)

	return pbSettings, diagnostics
}

func ConvertSettingsFromPB(
	dst *SettingsModel,
	src *pb.Settings,
) diag.Diagnostics {
	var diagnostics diag.Diagnostics

	// Convert simple fields
	if src.InstallationId != nil {
		dst.InstallationID = types.StringValue(*src.InstallationId)
	}
	if src.LogLevel != nil {
		dst.LogLevel = types.StringValue(*src.LogLevel)
	}
	if src.ProxyLogLevel != nil {
		dst.ProxyLogLevel = types.StringValue(*src.ProxyLogLevel)
	}
	if src.SharedSecret != nil {
		dst.SharedSecret = types.StringValue(*src.SharedSecret)
	}
	if src.Services != nil {
		dst.Services = types.StringValue(*src.Services)
	}
	if src.Address != nil {
		dst.Address = types.StringValue(*src.Address)
	}
	if src.InsecureServer != nil {
		dst.InsecureServer = types.BoolValue(*src.InsecureServer)
	}
	if src.TracingSampleRate != nil {
		dst.TracingSampleRate = types.Float64Value(*src.TracingSampleRate)
	}
	// ... convert remaining fields

	// Handle map fields
	if src.RequestParams != nil {
		elements := make(map[string]attr.Value)
		for k, v := range src.RequestParams {
			elements[k] = types.StringValue(v)
		}
		dst.RequestParams = types.MapValueMust(types.StringType, elements)
	}

	// Handle list fields
	if len(src.Scopes) > 0 {
		scopeList := make([]attr.Value, len(src.Scopes))
		for i, scope := range src.Scopes {
			scopeList[i] = types.StringValue(scope)
		}
		dst.Scopes = types.ListValueMust(types.StringType, scopeList)
	}

	// Handle duration fields
	if src.TimeoutRead != nil {
		dst.TimeoutRead = types.StringValue(src.TimeoutRead.AsDuration().String())
	}
	if src.TimeoutWrite != nil {
		dst.TimeoutWrite = types.StringValue(src.TimeoutWrite.AsDuration().String())
	}
	if src.TimeoutIdle != nil {
		dst.TimeoutIdle = types.StringValue(src.TimeoutIdle.AsDuration().String())
	}
	if src.CookieExpire != nil {
		dst.CookieExpire = types.StringValue(src.CookieExpire.AsDuration().String())
	}
	// Complete remaining duration fields
	if src.IdpRefreshDirectoryTimeout != nil {
		dst.IdpRefreshDirectoryTimeout = types.StringValue(src.IdpRefreshDirectoryTimeout.AsDuration().String())
	}
	if src.IdpRefreshDirectoryInterval != nil {
		dst.IdpRefreshDirectoryInterval = types.StringValue(src.IdpRefreshDirectoryInterval.AsDuration().String())
	}
	if src.DefaultUpstreamTimeout != nil {
		dst.DefaultUpstreamTimeout = types.StringValue(src.DefaultUpstreamTimeout.AsDuration().String())
	}
	if src.IdentityProviderRefreshInterval != nil {
		dst.IdentityProviderRefreshInterval = types.StringValue(src.IdentityProviderRefreshInterval.AsDuration().String())
	}
	if src.IdentityProviderRefreshTimeout != nil {
		dst.IdentityProviderRefreshTimeout = types.StringValue(src.IdentityProviderRefreshTimeout.AsDuration().String())
	}

	// Handle identity provider options
	if src.IdentityProviderOptions != nil {
		elements := make(map[string]attr.Value)
		for k, v := range src.IdentityProviderOptions.AsMap() {
			elements[k] = types.StringValue(fmt.Sprint(v))
		}
		dst.IdentityProviderOptions = types.MapValueMust(types.StringType, elements)
	}

	// Handle StringList fields
	if src.AccessLogFields != nil {
		fields := make([]attr.Value, len(src.AccessLogFields.Values))
		for i, v := range src.AccessLogFields.Values {
			fields[i] = types.StringValue(v)
		}
		dst.AccessLogFields = types.ListValueMust(types.StringType, fields)
	}
	// ... similar for authorize_log_fields

	// Handle remaining map fields
	if src.SetResponseHeaders != nil {
		elements := make(map[string]attr.Value)
		for k, v := range src.SetResponseHeaders {
			elements[k] = types.StringValue(v)
		}
		dst.SetResponseHeaders = types.MapValueMust(types.StringType, elements)
	}
	if src.JwtClaimsHeaders != nil {
		elements := make(map[string]attr.Value)
		for k, v := range src.JwtClaimsHeaders {
			elements[k] = types.StringValue(v)
		}
		dst.JWTClaimsHeaders = types.MapValueMust(types.StringType, elements)
	}

	// Handle remaining simple fields
	if src.DnsLookupFamily != nil {
		dst.DNSLookupFamily = types.StringValue(*src.DnsLookupFamily)
	}
	if src.HttpRedirectAddr != nil {
		dst.HTTPRedirectAddr = types.StringValue(*src.HttpRedirectAddr)
	}
	if src.AuthenticateServiceUrl != nil {
		dst.AuthenticateServiceURL = types.StringValue(*src.AuthenticateServiceUrl)
	}
	if src.AuthenticateCallbackPath != nil {
		dst.AuthenticateCallbackPath = types.StringValue(*src.AuthenticateCallbackPath)
	}
	if src.CookieName != nil {
		dst.CookieName = types.StringValue(*src.CookieName)
	}
	if src.CookieSecret != nil {
		dst.CookieSecret = types.StringValue(*src.CookieSecret)
	}
	if src.CookieDomain != nil {
		dst.CookieDomain = types.StringValue(*src.CookieDomain)
	}
	if src.CookieSecure != nil {
		dst.CookieSecure = types.BoolValue(*src.CookieSecure)
	}
	if src.CookieHttpOnly != nil {
		dst.CookieHTTPOnly = types.BoolValue(*src.CookieHttpOnly)
	}
	if src.CookieSameSite != nil {
		dst.CookieSameSite = types.StringValue(*src.CookieSameSite)
	}

	// Handle AuthorizeLogFields
	if src.AuthorizeLogFields != nil {
		fields := make([]attr.Value, len(src.AuthorizeLogFields.Values))
		for i, v := range src.AuthorizeLogFields.Values {
			fields[i] = types.StringValue(v)
		}
		dst.AuthorizeLogFields = types.ListValueMust(types.StringType, fields)
	}

	// Add corresponding fields for FromPB conversion
	if src.IdpClientId != nil {
		dst.IdpClientID = types.StringValue(*src.IdpClientId)
	}
	if src.IdpClientSecret != nil {
		dst.IdpClientSecret = types.StringValue(*src.IdpClientSecret)
	}
	if src.IdpProvider != nil {
		dst.IdpProvider = types.StringValue(*src.IdpProvider)
	}
	if src.IdpProviderUrl != nil {
		dst.IdpProviderURL = types.StringValue(*src.IdpProviderUrl)
	}
	if src.IdpServiceAccount != nil {
		dst.IdpServiceAccount = types.StringValue(*src.IdpServiceAccount)
	}
	if src.AuthorizeServiceUrl != nil {
		dst.AuthorizeServiceURL = types.StringValue(*src.AuthorizeServiceUrl)
	}
	if src.CertificateAuthority != nil {
		dst.CertificateAuthority = types.StringValue(*src.CertificateAuthority)
	}
	if src.CertificateAuthorityFile != nil {
		dst.CertificateAuthorityFile = types.StringValue(*src.CertificateAuthorityFile)
	}
	if src.CertificateAuthorityKeyPairId != nil {
		dst.CertificateAuthorityKeyPairID = types.StringValue(*src.CertificateAuthorityKeyPairId)
	}
	if src.MetricsAddress != nil {
		dst.MetricsAddress = types.StringValue(*src.MetricsAddress)
	}
	if src.TracingProvider != nil {
		dst.TracingProvider = types.StringValue(*src.TracingProvider)
	}
	if src.TracingDatadogAddress != nil {
		dst.TracingDatadogAddress = types.StringValue(*src.TracingDatadogAddress)
	}
	if src.TracingJaegerCollectorEndpoint != nil {
		dst.TracingJaegerCollectorEndpoint = types.StringValue(*src.TracingJaegerCollectorEndpoint)
	}
	if src.TracingJaegerAgentEndpoint != nil {
		dst.TracingJaegerAgentEndpoint = types.StringValue(*src.TracingJaegerAgentEndpoint)
	}
	if src.TracingZipkinEndpoint != nil {
		dst.TracingZipkinEndpoint = types.StringValue(*src.TracingZipkinEndpoint)
	}
	if src.GrpcAddress != nil {
		dst.GRPCAddress = types.StringValue(*src.GrpcAddress)
	}
	if src.CacheServiceUrl != nil {
		dst.CacheServiceURL = types.StringValue(*src.CacheServiceUrl)
	}
	if src.DatabrokerServiceUrl != nil {
		dst.DatabrokerServiceURL = types.StringValue(*src.DatabrokerServiceUrl)
	}
	if src.ClientCa != nil {
		dst.ClientCA = types.StringValue(*src.ClientCa)
	}
	if src.ClientCaFile != nil {
		dst.ClientCAFile = types.StringValue(*src.ClientCaFile)
	}
	if src.ClientCaKeyPairId != nil {
		dst.ClientCAKeyPairID = types.StringValue(*src.ClientCaKeyPairId)
	}
	if src.GoogleCloudServerlessAuthenticationServiceAccount != nil {
		dst.GoogleCloudServerlessAuthenticationServiceAccount = types.StringValue(*src.GoogleCloudServerlessAuthenticationServiceAccount)
	}
	if src.AutocertDir != nil {
		dst.AutocertDir = types.StringValue(*src.AutocertDir)
	}
	if src.PrimaryColor != nil {
		dst.PrimaryColor = types.StringValue(*src.PrimaryColor)
	}
	if src.SecondaryColor != nil {
		dst.SecondaryColor = types.StringValue(*src.SecondaryColor)
	}
	if src.DarkmodePrimaryColor != nil {
		dst.DarkmodePrimaryColor = types.StringValue(*src.DarkmodePrimaryColor)
	}
	if src.DarkmodeSecondaryColor != nil {
		dst.DarkmodeSecondaryColor = types.StringValue(*src.DarkmodeSecondaryColor)
	}
	if src.LogoUrl != nil {
		dst.LogoURL = types.StringValue(*src.LogoUrl)
	}
	if src.FaviconUrl != nil {
		dst.FaviconURL = types.StringValue(*src.FaviconUrl)
	}
	if src.ErrorMessageFirstParagraph != nil {
		dst.ErrorMessageFirstParagraph = types.StringValue(*src.ErrorMessageFirstParagraph)
	}
	if src.IdentityProvider != nil {
		dst.IdentityProvider = types.StringValue(*src.IdentityProvider)
	}

	// Add bool fields
	if src.GrpcInsecure != nil {
		dst.GRPCInsecure = types.BoolValue(*src.GrpcInsecure)
	}
	if src.Autocert != nil {
		dst.Autocert = types.BoolValue(*src.Autocert)
	}
	if src.AutocertUseStaging != nil {
		dst.AutocertUseStaging = types.BoolValue(*src.AutocertUseStaging)
	}
	if src.AutocertMustStaple != nil {
		dst.AutocertMustStaple = types.BoolValue(*src.AutocertMustStaple)
	}
	if src.SkipXffAppend != nil {
		dst.SkipXFFAppend = types.BoolValue(*src.SkipXffAppend)
	}
	if src.PassIdentityHeaders != nil {
		dst.PassIdentityHeaders = types.BoolValue(*src.PassIdentityHeaders)
	}

	return diagnostics
}

// mergeSettings merges new settings into current settings, only overwriting fields that are explicitly set
func mergeSettings(current *pb.Settings, new *pb.Settings) *pb.Settings {
	if current == nil {
		return new
	}
	if new == nil {
		return current
	}

	merged := proto.Clone(current).(*pb.Settings)

	// Only overwrite fields that are explicitly set in new settings
	if new.InstallationId != nil {
		merged.InstallationId = new.InstallationId
	}
	if new.LogLevel != nil {
		merged.LogLevel = new.LogLevel
	}
	if new.ProxyLogLevel != nil {
		merged.ProxyLogLevel = new.ProxyLogLevel
	}
	if new.SharedSecret != nil {
		merged.SharedSecret = new.SharedSecret
	}
	if new.Services != nil {
		merged.Services = new.Services
	}
	if new.Address != nil {
		merged.Address = new.Address
	}
	if new.InsecureServer != nil {
		merged.InsecureServer = new.InsecureServer
	}
	if new.TracingSampleRate != nil {
		merged.TracingSampleRate = new.TracingSampleRate
	}

	// Add duration fields
	if new.TimeoutRead != nil {
		merged.TimeoutRead = new.TimeoutRead
	}
	if new.TimeoutWrite != nil {
		merged.TimeoutWrite = new.TimeoutWrite
	}
	if new.TimeoutIdle != nil {
		merged.TimeoutIdle = new.TimeoutIdle
	}
	if new.CookieExpire != nil {
		merged.CookieExpire = new.CookieExpire
	}
	// Complete remaining duration fields
	if new.IdpRefreshDirectoryTimeout != nil {
		merged.IdpRefreshDirectoryTimeout = new.IdpRefreshDirectoryTimeout
	}
	if new.IdpRefreshDirectoryInterval != nil {
		merged.IdpRefreshDirectoryInterval = new.IdpRefreshDirectoryInterval
	}
	if new.DefaultUpstreamTimeout != nil {
		merged.DefaultUpstreamTimeout = new.DefaultUpstreamTimeout
	}
	if new.IdentityProviderRefreshInterval != nil {
		merged.IdentityProviderRefreshInterval = new.IdentityProviderRefreshInterval
	}
	if new.IdentityProviderRefreshTimeout != nil {
		merged.IdentityProviderRefreshTimeout = new.IdentityProviderRefreshTimeout
	}

	// Add struct fields
	if new.IdentityProviderOptions != nil {
		merged.IdentityProviderOptions = new.IdentityProviderOptions
	}

	// Add StringList fields
	if new.AccessLogFields != nil {
		merged.AccessLogFields = new.AccessLogFields
	}
	if new.AuthorizeLogFields != nil {
		merged.AuthorizeLogFields = new.AuthorizeLogFields
	}

	// Handle remaining map fields
	if new.SetResponseHeaders != nil {
		merged.SetResponseHeaders = new.SetResponseHeaders
	}
	if new.JwtClaimsHeaders != nil {
		merged.JwtClaimsHeaders = new.JwtClaimsHeaders
	}

	// Add remaining simple fields
	if new.DnsLookupFamily != nil {
		merged.DnsLookupFamily = new.DnsLookupFamily
	}
	if new.HttpRedirectAddr != nil {
		merged.HttpRedirectAddr = new.HttpRedirectAddr
	}
	if new.AuthenticateServiceUrl != nil {
		merged.AuthenticateServiceUrl = new.AuthenticateServiceUrl
	}
	if new.AuthenticateCallbackPath != nil {
		merged.AuthenticateCallbackPath = new.AuthenticateCallbackPath
	}
	if new.CookieName != nil {
		merged.CookieName = new.CookieName
	}
	if new.CookieSecret != nil {
		merged.CookieSecret = new.CookieSecret
	}
	if new.CookieDomain != nil {
		merged.CookieDomain = new.CookieDomain
	}
	if new.CookieSecure != nil {
		merged.CookieSecure = new.CookieSecure
	}
	if new.CookieHttpOnly != nil {
		merged.CookieHttpOnly = new.CookieHttpOnly
	}
	if new.CookieSameSite != nil {
		merged.CookieSameSite = new.CookieSameSite
	}

	// Add missing string fields
	if new.IdpClientId != nil {
		merged.IdpClientId = new.IdpClientId
	}
	if new.IdpClientSecret != nil {
		merged.IdpClientSecret = new.IdpClientSecret
	}
	if new.IdpProvider != nil {
		merged.IdpProvider = new.IdpProvider
	}
	if new.IdpProviderUrl != nil {
		merged.IdpProviderUrl = new.IdpProviderUrl
	}
	if new.IdpServiceAccount != nil {
		merged.IdpServiceAccount = new.IdpServiceAccount
	}
	if new.AuthorizeServiceUrl != nil {
		merged.AuthorizeServiceUrl = new.AuthorizeServiceUrl
	}
	if new.CertificateAuthority != nil {
		merged.CertificateAuthority = new.CertificateAuthority
	}
	if new.CertificateAuthorityFile != nil {
		merged.CertificateAuthorityFile = new.CertificateAuthorityFile
	}
	if new.CertificateAuthorityKeyPairId != nil {
		merged.CertificateAuthorityKeyPairId = new.CertificateAuthorityKeyPairId
	}
	if new.MetricsAddress != nil {
		merged.MetricsAddress = new.MetricsAddress
	}
	if new.TracingProvider != nil {
		merged.TracingProvider = new.TracingProvider
	}
	if new.TracingDatadogAddress != nil {
		merged.TracingDatadogAddress = new.TracingDatadogAddress
	}
	if new.TracingJaegerCollectorEndpoint != nil {
		merged.TracingJaegerCollectorEndpoint = new.TracingJaegerCollectorEndpoint
	}
	if new.TracingJaegerAgentEndpoint != nil {
		merged.TracingJaegerAgentEndpoint = new.TracingJaegerAgentEndpoint
	}
	if new.TracingZipkinEndpoint != nil {
		merged.TracingZipkinEndpoint = new.TracingZipkinEndpoint
	}
	if new.GrpcAddress != nil {
		merged.GrpcAddress = new.GrpcAddress
	}
	if new.CacheServiceUrl != nil {
		merged.CacheServiceUrl = new.CacheServiceUrl
	}
	if new.DatabrokerServiceUrl != nil {
		merged.DatabrokerServiceUrl = new.DatabrokerServiceUrl
	}
	if new.ClientCa != nil {
		merged.ClientCa = new.ClientCa
	}
	if new.ClientCaFile != nil {
		merged.ClientCaFile = new.ClientCaFile
	}
	if new.ClientCaKeyPairId != nil {
		merged.ClientCaKeyPairId = new.ClientCaKeyPairId
	}
	if new.GoogleCloudServerlessAuthenticationServiceAccount != nil {
		merged.GoogleCloudServerlessAuthenticationServiceAccount = new.GoogleCloudServerlessAuthenticationServiceAccount
	}
	if new.AutocertDir != nil {
		merged.AutocertDir = new.AutocertDir
	}
	if new.PrimaryColor != nil {
		merged.PrimaryColor = new.PrimaryColor
	}
	if new.SecondaryColor != nil {
		merged.SecondaryColor = new.SecondaryColor
	}
	if new.DarkmodePrimaryColor != nil {
		merged.DarkmodePrimaryColor = new.DarkmodePrimaryColor
	}
	if new.DarkmodeSecondaryColor != nil {
		merged.DarkmodeSecondaryColor = new.DarkmodeSecondaryColor
	}
	if new.LogoUrl != nil {
		merged.LogoUrl = new.LogoUrl
	}
	if new.FaviconUrl != nil {
		merged.FaviconUrl = new.FaviconUrl
	}
	if new.ErrorMessageFirstParagraph != nil {
		merged.ErrorMessageFirstParagraph = new.ErrorMessageFirstParagraph
	}
	if new.IdentityProvider != nil {
		merged.IdentityProvider = new.IdentityProvider
	}

	// Add missing bool fields
	if new.GrpcInsecure != nil {
		merged.GrpcInsecure = new.GrpcInsecure
	}
	if new.Autocert != nil {
		merged.Autocert = new.Autocert
	}
	if new.AutocertUseStaging != nil {
		merged.AutocertUseStaging = new.AutocertUseStaging
	}
	if new.AutocertMustStaple != nil {
		merged.AutocertMustStaple = new.AutocertMustStaple
	}
	if new.SkipXffAppend != nil {
		merged.SkipXffAppend = new.SkipXffAppend
	}
	if new.PassIdentityHeaders != nil {
		merged.PassIdentityHeaders = new.PassIdentityHeaders
	}

	return merged
}
