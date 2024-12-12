package provider

import (
	_ "embed"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

//go:embed help/settings.md
var settingsResourceHelp string

var SettingsResourceSchema = schema.Schema{
	MarkdownDescription: settingsResourceHelp,

	Attributes: map[string]schema.Attribute{
		"installation_id": schema.StringAttribute{
			Optional:    true,
			Description: "Installation ID",
		},
		"log_level": schema.StringAttribute{
			Optional:    true,
			Description: "Log level",
		},
		"proxy_log_level": schema.StringAttribute{
			Optional:    true,
			Description: "Proxy log level",
		},
		"shared_secret": schema.StringAttribute{
			Optional:    true,
			Description: "Shared secret",
			Sensitive:   true,
		},
		"services": schema.StringAttribute{
			Optional:    true,
			Description: "Services",
		},
		"address": schema.StringAttribute{
			Optional:    true,
			Description: "Address",
		},
		"insecure_server": schema.BoolAttribute{
			Optional:    true,
			Description: "Insecure server",
		},
		"dns_lookup_family": schema.StringAttribute{
			Optional:    true,
			Description: "DNS lookup family",
		},
		"http_redirect_addr": schema.StringAttribute{
			Optional:    true,
			Description: "HTTP redirect address",
		},
		"timeout_read": schema.StringAttribute{
			Optional:    true,
			Description: "Timeout read",
		},
		"timeout_write": schema.StringAttribute{
			Optional:    true,
			Description: "Timeout write",
		},
		"timeout_idle": schema.StringAttribute{
			Optional:    true,
			Description: "Timeout idle",
		},
		"authenticate_service_url": schema.StringAttribute{
			Optional:    true,
			Description: "Authenticate service URL",
		},
		"authenticate_callback_path": schema.StringAttribute{
			Optional:    true,
			Description: "Authenticate callback path",
		},
		"cookie_name": schema.StringAttribute{
			Optional:    true,
			Description: "Cookie name",
		},
		"cookie_secret": schema.StringAttribute{
			Optional:    true,
			Description: "Cookie secret",
			Sensitive:   true,
		},
		"cookie_domain": schema.StringAttribute{
			Optional:    true,
			Description: "Cookie domain",
		},
		"cookie_secure": schema.BoolAttribute{
			Optional:    true,
			Description: "Cookie secure",
		},
		"cookie_http_only": schema.BoolAttribute{
			Optional:    true,
			Description: "Cookie HTTP only",
		},
		"cookie_same_site": schema.StringAttribute{
			Optional:    true,
			Description: "Cookie same site",
		},
		"cookie_expire": schema.StringAttribute{
			Optional:    true,
			Description: "Cookie expire",
		},
		"idp_client_id": schema.StringAttribute{
			Optional:    true,
			Description: "IDP client ID",
		},
		"idp_client_secret": schema.StringAttribute{
			Optional:    true,
			Description: "IDP client secret",
			Sensitive:   true,
		},
		"idp_provider": schema.StringAttribute{
			Optional:    true,
			Description: "IDP provider",
		},
		"idp_provider_url": schema.StringAttribute{
			Optional:    true,
			Description: "IDP provider URL",
		},
		"scopes": schema.ListAttribute{
			Optional:    true,
			ElementType: types.StringType,
			Description: "Scopes",
		},
		"idp_service_account": schema.StringAttribute{
			Optional:    true,
			Description: "IDP service account",
			Sensitive:   true,
		},
		"idp_refresh_directory_timeout": schema.StringAttribute{
			Optional:    true,
			Description: "IDP refresh directory timeout",
		},
		"idp_refresh_directory_interval": schema.StringAttribute{
			Optional:    true,
			Description: "IDP refresh directory interval",
		},
		"request_params": schema.MapAttribute{
			ElementType: types.StringType,
			Optional:    true,
			Description: "Request parameters",
		},
		"authorize_service_url": schema.StringAttribute{
			Optional:    true,
			Description: "Authorize service URL",
		},
		"certificate_authority": schema.StringAttribute{
			Optional:    true,
			Description: "Certificate authority",
		},
		"certificate_authority_file": schema.StringAttribute{
			Optional:    true,
			Description: "Certificate authority file",
		},
		"certificate_authority_key_pair_id": schema.StringAttribute{
			Optional:    true,
			Description: "Certificate authority key pair ID",
		},
		"set_response_headers": schema.MapAttribute{
			ElementType: types.StringType,
			Optional:    true,
			Description: "Response headers to set",
		},
		"jwt_claims_headers": schema.MapAttribute{
			ElementType: types.StringType,
			Optional:    true,
			Description: "JWT claims headers mapping",
		},
		"default_upstream_timeout": schema.StringAttribute{
			Optional:    true,
			Description: "Default upstream timeout",
		},
		"metrics_address": schema.StringAttribute{
			Optional:    true,
			Description: "Metrics address",
		},
		"tracing_provider": schema.StringAttribute{
			Optional:    true,
			Description: "Tracing provider",
		},
		"tracing_sample_rate": schema.Float64Attribute{
			Optional:    true,
			Description: "Tracing sample rate",
		},
		"tracing_datadog_address": schema.StringAttribute{
			Optional:    true,
			Description: "Tracing Datadog address",
		},
		"tracing_jaeger_collector_endpoint": schema.StringAttribute{
			Optional:    true,
			Description: "Tracing Jaeger collector endpoint",
		},
		"tracing_jaeger_agent_endpoint": schema.StringAttribute{
			Optional:    true,
			Description: "Tracing Jaeger agent endpoint",
		},
		"tracing_zipkin_endpoint": schema.StringAttribute{
			Optional:    true,
			Description: "Tracing Zipkin endpoint",
		},
		"grpc_address": schema.StringAttribute{
			Optional:    true,
			Description: "gRPC address",
		},
		"grpc_insecure": schema.BoolAttribute{
			Optional:    true,
			Description: "gRPC insecure",
		},
		"cache_service_url": schema.StringAttribute{
			Optional:    true,
			Description: "Cache service URL",
		},
		"databroker_service_url": schema.StringAttribute{
			Optional:    true,
			Description: "Databroker service URL",
		},
		"client_ca": schema.StringAttribute{
			Optional:    true,
			Description: "Client CA",
		},
		"client_ca_file": schema.StringAttribute{
			Optional:    true,
			Description: "Client CA file",
		},
		"client_ca_key_pair_id": schema.StringAttribute{
			Optional:    true,
			Description: "Client CA key pair ID",
		},
		"google_cloud_serverless_authentication_service_account": schema.StringAttribute{
			Optional:    true,
			Description: "Google Cloud Serverless Authentication Service Account",
		},
		"autocert": schema.BoolAttribute{
			Optional:    true,
			Description: "Autocert",
		},
		"autocert_use_staging": schema.BoolAttribute{
			Optional:    true,
			Description: "Autocert use staging",
		},
		"autocert_must_staple": schema.BoolAttribute{
			Optional:    true,
			Description: "Autocert must staple",
		},
		"autocert_dir": schema.StringAttribute{
			Optional:    true,
			Description: "Autocert directory",
		},
		"skip_xff_append": schema.BoolAttribute{
			Optional:    true,
			Description: "Skip XFF append",
		},
		"primary_color": schema.StringAttribute{
			Optional:    true,
			Description: "Primary color",
		},
		"secondary_color": schema.StringAttribute{
			Optional:    true,
			Description: "Secondary color",
		},
		"darkmode_primary_color": schema.StringAttribute{
			Optional:    true,
			Description: "Darkmode primary color",
		},
		"darkmode_secondary_color": schema.StringAttribute{
			Optional:    true,
			Description: "Darkmode secondary color",
		},
		"logo_url": schema.StringAttribute{
			Optional:    true,
			Description: "Logo URL",
		},
		"favicon_url": schema.StringAttribute{
			Optional:    true,
			Description: "Favicon URL",
		},
		"error_message_first_paragraph": schema.StringAttribute{
			Optional:    true,
			Description: "Error message first paragraph",
		},
		"identity_provider": schema.StringAttribute{
			Optional:    true,
			Description: "Identity provider",
		},
		"identity_provider_options": schema.MapAttribute{
			ElementType: types.StringType,
			Optional:    true,
			Description: "Identity provider options",
		},
		"identity_provider_refresh_interval": schema.StringAttribute{
			Optional:    true,
			Description: "Identity provider refresh interval",
		},
		"identity_provider_refresh_timeout": schema.StringAttribute{
			Optional:    true,
			Description: "Identity provider refresh timeout",
		},
		"access_log_fields": schema.ListAttribute{
			Optional:    true,
			ElementType: types.StringType,
			Description: "Access log fields",
		},
		"authorize_log_fields": schema.ListAttribute{
			Optional:    true,
			ElementType: types.StringType,
			Description: "Authorize log fields",
		},
		"pass_identity_headers": schema.BoolAttribute{
			Optional:    true,
			Description: "Pass identity headers",
		},
	},
}
