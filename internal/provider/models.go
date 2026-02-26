package provider

import (
	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const (
	OriginatorID = "terraform"

	RecordTypeCluster             = "pomerium.io/TerraformCluster"
	RecordTypeExternalDataSource  = "pomerium.io/TerraformExternalDataSource"
	RecordTypeNamespace           = "pomerium.io/TerraformNamespace"
	RecordTypeNamespacePermission = "pomerium.io/TerraformNamespacePermission"
)

type ClusterModel struct {
	CertificateAuthorityB64  types.String `tfsdk:"certificate_authority_b64"`
	CertificateAuthorityFile types.String `tfsdk:"certificate_authority_file"`
	DatabrokerServiceURL     types.String `tfsdk:"databroker_service_url"`
	Domain                   types.String `tfsdk:"domain"`
	Flavor                   types.String `tfsdk:"flavor"`
	FQDN                     types.String `tfsdk:"fqdn"`
	ID                       types.String `tfsdk:"id"`
	InsecureSkipVerify       types.Bool   `tfsdk:"insecure_skip_verify"`
	ManualOverrideIPAddress  types.String `tfsdk:"manual_override_ip_address"`
	Name                     types.String `tfsdk:"name"`
	NamespaceID              types.String `tfsdk:"namespace_id"`
	OverrideCertificateName  types.String `tfsdk:"override_certificate_name"`
	ParentNamespaceID        types.String `tfsdk:"parent_namespace_id"`
	SharedSecretB64          types.String `tfsdk:"shared_secret_b64"`
}

type ExternalDataSourceModel struct {
	AllowInsecureTLS types.Bool           `tfsdk:"allow_insecure_tls"`
	ClientTLSKeyID   types.String         `tfsdk:"client_tls_key_id"`
	ClusterID        types.String         `tfsdk:"cluster_id"`
	ForeignKey       types.String         `tfsdk:"foreign_key"`
	Headers          types.Map            `tfsdk:"headers"`
	ID               types.String         `tfsdk:"id"`
	PollingMaxDelay  timetypes.GoDuration `tfsdk:"polling_max_delay"`
	PollingMinDelay  timetypes.GoDuration `tfsdk:"polling_min_delay"`
	RecordType       types.String         `tfsdk:"record_type"`
	URL              types.String         `tfsdk:"url"`
}

type KeyPairModel struct {
	Certificate types.String `tfsdk:"certificate"`
	ID          types.String `tfsdk:"id"`
	Key         types.String `tfsdk:"key"`
	Name        types.String `tfsdk:"name"`
	NamespaceID types.String `tfsdk:"namespace_id"`
}

type NamespaceModel struct {
	ClusterID types.String `tfsdk:"cluster_id"`
	ID        types.String `tfsdk:"id"`
	Name      types.String `tfsdk:"name"`
	ParentID  types.String `tfsdk:"parent_id"`
}

type NamespacePermissionModel struct {
	ID          types.String `tfsdk:"id"`
	NamespaceID types.String `tfsdk:"namespace_id"`
	Role        types.String `tfsdk:"role"`
	SubjectID   types.String `tfsdk:"subject_id"`
	SubjectType types.String `tfsdk:"subject_type"`
}

type PolicyModel struct {
	Description types.String   `tfsdk:"description"`
	Enforced    types.Bool     `tfsdk:"enforced"`
	Explanation types.String   `tfsdk:"explanation"`
	ID          types.String   `tfsdk:"id"`
	Name        types.String   `tfsdk:"name"`
	NamespaceID types.String   `tfsdk:"namespace_id"`
	PPL         PolicyLanguage `tfsdk:"ppl"`
	Rego        types.List     `tfsdk:"rego"`
	Remediation types.String   `tfsdk:"remediation"`
}

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
	HealthyPanicThreshold                     types.Int32          `tfsdk:"healthy_panic_threshold"`
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

type ServiceAccountModel struct {
	Description types.String `tfsdk:"description"`
	ExpiresAt   types.String `tfsdk:"expires_at"`
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	NamespaceID types.String `tfsdk:"namespace_id"`
	UserID      types.String `tfsdk:"user_id"`
}

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
