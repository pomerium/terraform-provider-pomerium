package provider

import (
	_ "embed"

	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework-validators/objectvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

//go:embed help/settings.md
var settingsResourceHelp string

func idpOneOf(name string) []validator.Object {
	var exprs []path.Expression
	for _, n := range []string{
		"identity_provider_auth0",
		"identity_provider_azure",
		"identity_provider_cognito",
		"identity_provider_github",
		"identity_provider_gitlab",
		"identity_provider_google",
		"identity_provider_okta",
		"identity_provider_onelogin",
		"identity_provider_ping",
	} {
		if n == name {
			continue
		}
		exprs = append(exprs, path.MatchRelative().AtParent().AtName(n))
	}
	return []validator.Object{
		objectvalidator.ConflictsWith(exprs...),
	}
}

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
		"address": schema.StringAttribute{
			Optional:    true,
			Description: "Specifies the IP Address and Port to serve HTTP requests from.",
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
			Description: "Sets the amount of time for the client to receive the entire request stream.",
			CustomType:  timetypes.GoDurationType{},
		},
		"timeout_write": schema.StringAttribute{
			Optional:    true,
			Description: "Sets max stream duration of an HTTP request/response exchange. Must be greater than read timeout.",
			CustomType:  timetypes.GoDurationType{},
		},
		"timeout_idle": schema.StringAttribute{
			Optional:    true,
			Description: "Sets the time at which a downstream or upstream connection will be terminated if no active streams.",
			CustomType:  timetypes.GoDurationType{},
		},
		"authenticate_service_url": schema.StringAttribute{
			Optional:    true,
			Description: "The externally accessible URL for the authenticate service.",
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
			CustomType:  timetypes.GoDurationType{},
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
		"scopes": schema.SetAttribute{
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
			CustomType:  timetypes.GoDurationType{},
		},
		"idp_refresh_directory_interval": schema.StringAttribute{
			Optional:    true,
			Description: "IDP refresh directory interval",
			CustomType:  timetypes.GoDurationType{},
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
		"jwt_groups_filter": JWTGroupsFilterSchema,
		"default_upstream_timeout": schema.StringAttribute{
			Optional:    true,
			Description: "Default upstream timeout",
			CustomType:  timetypes.GoDurationType{},
		},
		"metrics_address": schema.StringAttribute{
			Optional:    true,
			Description: "Metrics address",
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
			Description: "Google Cloud Serverless Authentication service account credentials.",
		},
		"autocert": schema.BoolAttribute{
			Optional:    true,
			Description: "Turning on autocert allows Pomerium to automatically retrieve, manage, and renew public facing TLS certificates from Lets Encrypt.",
		},
		"autocert_use_staging": schema.BoolAttribute{
			Optional:    true,
			Description: "Autocert Use Staging setting allows you to use Let's Encrypt's staging environment, which has more lenient usage limits than the production environment.",
		},
		"autocert_must_staple": schema.BoolAttribute{
			Optional:    true,
			Description: "Controls whether the must-staple flag is enabled when requesting certificates.",
		},
		"autocert_dir": schema.StringAttribute{
			Optional:    true,
			Description: "Autocert directory is the path which Autocert will store x509 certificate data.",
		},
		"skip_xff_append": schema.BoolAttribute{
			Optional:    true,
			Description: "Skip XFF append",
		},
		"primary_color": schema.StringAttribute{
			Optional:    true,
			Description: "A hex code that determines the primary color for the Enterprise Console and Route Error Details pages.",
		},
		"secondary_color": schema.StringAttribute{
			Optional:    true,
			Description: "A hex code that determines the secondary color for the Enterprise Console and Route Error Details pages.",
		},
		"darkmode_primary_color": schema.StringAttribute{
			Optional:    true,
			Description: "A hex code that determines the primary color for the Enterprise Console and Route Error Details pages when in Dark Mode.",
		},
		"darkmode_secondary_color": schema.StringAttribute{
			Optional:    true,
			Description: "A hex code that determines the secondary color for the Enterprise Console and Route Error Details pages when in Dark Mode.",
		},
		"logo_url": schema.StringAttribute{
			Optional:    true,
			Description: "A URL pointing to your logo. Defaults to Pomerium's Logo.",
		},
		"favicon_url": schema.StringAttribute{
			Optional:    true,
			Description: "A Url pointing to your favicon. Defaults to Pomerium's Favicon.",
		},
		"error_message_first_paragraph": schema.StringAttribute{
			Optional:    true,
			Description: "A paragraph that will appear on all Route Error Pages in the top section.",
		},
		"identity_provider_auth0": schema.SingleNestedAttribute{
			Optional:    true,
			Description: "Auth0 directory sync options",
			Validators:  idpOneOf("identity_provider_auth0"),
			Attributes: map[string]schema.Attribute{
				"client_id": schema.StringAttribute{
					Required: true,
				},
				"client_secret": schema.StringAttribute{
					Required:  true,
					Sensitive: true,
				},
				"domain": schema.StringAttribute{
					Required: true,
				},
			},
		},
		"identity_provider_azure": schema.SingleNestedAttribute{
			Optional:    true,
			Description: "Azure EntraID directory sync options",
			Validators:  idpOneOf("identity_provider_azure"),
			Attributes: map[string]schema.Attribute{
				"client_id": schema.StringAttribute{
					Required: true,
				},
				"client_secret": schema.StringAttribute{
					Required:  true,
					Sensitive: true,
				},
				"directory_id": schema.StringAttribute{
					Required: true,
				},
			},
		},
		"identity_provider_cognito": schema.SingleNestedAttribute{
			Optional:    true,
			Description: "Cognito directory sync options",
			Validators:  idpOneOf("identity_provider_cognito"),
			Attributes: map[string]schema.Attribute{
				"access_key_id": schema.StringAttribute{
					Required: true,
				},
				"region": schema.StringAttribute{
					Required: true,
				},
				"secret_access_key": schema.StringAttribute{
					Required:  true,
					Sensitive: true,
				},
				"session_token": schema.StringAttribute{
					Required:  true,
					Sensitive: true,
				},
				"user_pool_id": schema.StringAttribute{
					Required: true,
				},
			},
		},
		"identity_provider_github": schema.SingleNestedAttribute{
			Optional:    true,
			Description: "GitHub directory sync options",
			Validators:  idpOneOf("identity_provider_github"),
			Attributes: map[string]schema.Attribute{
				"username": schema.StringAttribute{
					Required: true,
				},
				"personal_access_token": schema.StringAttribute{
					Required:  true,
					Sensitive: true,
				},
			},
		},
		"identity_provider_gitlab": schema.SingleNestedAttribute{
			Optional:    true,
			Description: "GitLab directory sync options",
			Validators:  idpOneOf("identity_provider_gitlab"),
			Attributes: map[string]schema.Attribute{
				"private_token": schema.StringAttribute{
					Required:  true,
					Sensitive: true,
				},
			},
		},
		"identity_provider_google": schema.SingleNestedAttribute{
			Optional:    true,
			Description: "Google directory sync options",
			Validators:  idpOneOf("identity_provider_google"),
			Attributes: map[string]schema.Attribute{
				"impersonate_user": schema.StringAttribute{
					Optional: true,
				},
				"json_key": schema.StringAttribute{
					Required:  true,
					Sensitive: true,
				},
				"url": schema.StringAttribute{
					Required: true,
				},
			},
		},
		"identity_provider_okta": schema.SingleNestedAttribute{
			Optional:    true,
			Description: "Okta directory sync options",
			Validators:  idpOneOf("identity_provider_okta"),
			Attributes: map[string]schema.Attribute{
				"api_key": schema.StringAttribute{
					Required:  true,
					Sensitive: true,
				},
				"url": schema.StringAttribute{
					Required: true,
				},
			},
		},
		"identity_provider_onelogin": schema.SingleNestedAttribute{
			Optional:    true,
			Description: "OneLogin directory sync options",
			Validators:  idpOneOf("identity_provider_onelogin"),
			Attributes: map[string]schema.Attribute{
				"client_id": schema.StringAttribute{
					Required: true,
				},
				"client_secret": schema.StringAttribute{
					Required:  true,
					Sensitive: true,
				},
			},
		},
		"identity_provider_ping": schema.SingleNestedAttribute{
			Optional:    true,
			Description: "Ping directory sync options",
			Validators:  idpOneOf("identity_provider_ping"),
			Attributes: map[string]schema.Attribute{
				"client_id": schema.StringAttribute{
					Required: true,
				},
				"client_secret": schema.StringAttribute{
					Required:  true,
					Sensitive: true,
				},
				"environment_id": schema.StringAttribute{
					Required: true,
				},
			},
		},
		"identity_provider_refresh_interval": schema.StringAttribute{
			Optional:    true,
			Description: "Identity provider refresh interval",
			CustomType:  timetypes.GoDurationType{},
		},
		"identity_provider_refresh_timeout": schema.StringAttribute{
			Optional:    true,
			Description: "Identity provider refresh timeout",
			CustomType:  timetypes.GoDurationType{},
		},
		"access_log_fields": schema.SetAttribute{
			Optional:    true,
			ElementType: types.StringType,
			Description: "Displays HTTP request logs from the Pomerium Proxy service.",
		},
		"authorize_log_fields": schema.SetAttribute{
			Optional:    true,
			ElementType: types.StringType,
			Description: "Displays HTTP request logs from the Pomerium Authorize service.",
		},
		"pass_identity_headers": schema.BoolAttribute{
			Optional:    true,
			Description: "If applied, passes X-Pomerium-Jwt-Assertion header and JWT Claims Headers to all upstream applications.",
		},
		"bearer_token_format": schema.StringAttribute{
			Description: "Bearer token format.",
			Optional:    true,
			Validators: []validator.String{
				stringvalidator.OneOf("default", "idp_access_token", "idp_identity_token"),
			},
		},
		"idp_access_token_allowed_audiences": schema.SetAttribute{
			Description: "IDP access token allowed audiences.",
			Optional:    true,
			ElementType: types.StringType,
		},
		"otel_traces_exporter": schema.StringAttribute{
			Optional:    true,
			Description: "OpenTelemetry traces exporter type",
		},
		"otel_traces_sampler_arg": schema.Float64Attribute{
			Optional:    true,
			Description: "OpenTelemetry traces sampler argument",
		},
		"otel_resource_attributes": schema.SetAttribute{
			Optional:    true,
			ElementType: types.StringType,
			Description: "OpenTelemetry resource attributes",
		},
		"otel_log_level": schema.StringAttribute{
			Optional:    true,
			Description: "OpenTelemetry log level",
		},
		"otel_attribute_value_length_limit": schema.Int64Attribute{
			Optional:    true,
			Description: "OpenTelemetry attribute value length limit",
		},
		"otel_exporter_otlp_endpoint": schema.StringAttribute{
			Optional:    true,
			Description: "OpenTelemetry OTLP exporter endpoint",
		},
		"otel_exporter_otlp_traces_endpoint": schema.StringAttribute{
			Optional:    true,
			Description: "OpenTelemetry OTLP traces endpoint",
		},
		"otel_exporter_otlp_protocol": schema.StringAttribute{
			Optional:    true,
			Description: "OpenTelemetry OTLP exporter protocol",
		},
		"otel_exporter_otlp_traces_protocol": schema.StringAttribute{
			Optional:    true,
			Description: "OpenTelemetry OTLP traces protocol",
		},
		"otel_exporter_otlp_headers": schema.SetAttribute{
			Optional:    true,
			ElementType: types.StringType,
			Description: "OpenTelemetry OTLP exporter headers",
		},
		"otel_exporter_otlp_traces_headers": schema.SetAttribute{
			Optional:    true,
			ElementType: types.StringType,
			Description: "OpenTelemetry OTLP traces headers",
		},
		"otel_exporter_otlp_timeout": schema.StringAttribute{
			Optional:    true,
			Description: "OpenTelemetry OTLP exporter timeout",
			CustomType:  timetypes.GoDurationType{},
		},
		"otel_exporter_otlp_traces_timeout": schema.StringAttribute{
			Optional:    true,
			Description: "OpenTelemetry OTLP traces timeout",
			CustomType:  timetypes.GoDurationType{},
		},
		"otel_bsp_schedule_delay": schema.StringAttribute{
			Optional:    true,
			Description: "OpenTelemetry BSP schedule delay",
			CustomType:  timetypes.GoDurationType{},
		},
		"otel_bsp_max_export_batch_size": schema.Int64Attribute{
			Optional:    true,
			Description: "OpenTelemetry BSP max export batch size",
		},
	},
}
