package provider

import (
	_ "embed"

	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework-validators/objectvalidator"
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
			CustomType:  timetypes.GoDurationType{},
		},
		"timeout_write": schema.StringAttribute{
			Optional:    true,
			Description: "Timeout write",
			CustomType:  timetypes.GoDurationType{},
		},
		"timeout_idle": schema.StringAttribute{
			Optional:    true,
			Description: "Timeout idle",
			CustomType:  timetypes.GoDurationType{},
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
			Description: "Access log fields",
		},
		"authorize_log_fields": schema.SetAttribute{
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
