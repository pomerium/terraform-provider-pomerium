package provider

import (
	"context"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	client "github.com/pomerium/enterprise-client-go"
	"github.com/pomerium/enterprise-client-go/pb"
	"github.com/pomerium/sdk-go"
	"github.com/pomerium/sdk-go/proto/pomerium"
)

var _ interface {
	datasource.DataSource
} = (*RouteDataSource)(nil)

func getRouteDataSourceAttributes(idRequired bool) map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"allow_spdy": schema.BoolAttribute{
			Computed:    true,
			Description: "Allow SPDY.",
		},
		"allow_websockets": schema.BoolAttribute{
			Computed:    true,
			Description: "Allow websockets.",
		},
		"bearer_token_format": schema.StringAttribute{
			Description: "Bearer token format.",
			Computed:    true,
		},
		"circuit_breaker_thresholds": CircuitBreakerThresholdsSchema,
		"depends_on_hosts": schema.SetAttribute{
			Description: "Additional login redirect hosts.",
			Computed:    true,
			ElementType: types.StringType,
		},
		"description": schema.StringAttribute{
			Description: "Description of the route.",
			Computed:    true,
		},
		"enable_google_cloud_serverless_authentication": schema.BoolAttribute{
			Description: "Enable Google Cloud serverless authentication.",
			Computed:    true,
		},
		"from": schema.StringAttribute{
			Computed:    true,
			Description: "From URL.",
		},
		"health_checks": schema.SetNestedAttribute{
			Description: "Health checks for the route.",
			Computed:    true,
			NestedObject: schema.NestedAttributeObject{
				Attributes: map[string]schema.Attribute{
					"grpc_health_check": schema.SingleNestedAttribute{
						Description: "gRPC health check settings.",
						Computed:    true,
						Attributes: map[string]schema.Attribute{
							"authority": schema.StringAttribute{
								Description: "Authority header value.",
								Computed:    true,
							},
							"service_name": schema.StringAttribute{
								Description: "Service name to check.",
								Computed:    true,
							},
						},
					},
					"healthy_threshold": schema.Int64Attribute{
						Description: "Number of successes before marking healthy.",
						Computed:    true,
					},
					"http_health_check": schema.SingleNestedAttribute{
						Description: "HTTP health check settings.",
						Computed:    true,
						Attributes: map[string]schema.Attribute{
							"codec_client_type": schema.StringAttribute{
								Description: "Application protocol for health checks.",
								Computed:    true,
							},
							"expected_statuses": schema.SetNestedAttribute{
								Description: "Expected status code ranges.",
								Computed:    true,
								NestedObject: schema.NestedAttributeObject{
									Attributes: map[string]schema.Attribute{
										"end": schema.Int64Attribute{
											Description: "End of status code range.",
											Computed:    true,
										},
										"start": schema.Int64Attribute{
											Description: "Start of status code range.",
											Computed:    true,
										},
									},
								},
							},
							"host": schema.StringAttribute{
								Description: "The host header value.",
								Computed:    true,
							},
							"path": schema.StringAttribute{
								Description: "The request path.",
								Computed:    true,
							},
							"retriable_statuses": schema.SetNestedAttribute{
								Description: "Retriable status code ranges.",
								Computed:    true,
								NestedObject: schema.NestedAttributeObject{
									Attributes: map[string]schema.Attribute{
										"end": schema.Int64Attribute{
											Description: "End of status code range.",
											Computed:    true,
										},
										"start": schema.Int64Attribute{
											Description: "Start of status code range.",
											Computed:    true,
										},
									},
								},
							},
						},
					},
					"initial_jitter": schema.StringAttribute{
						Description: "An optional jitter amount for the first health check.",
						Computed:    true,
						CustomType:  timetypes.GoDurationType{},
					},
					"interval": schema.StringAttribute{
						Description: "The interval between health checks.",
						Computed:    true,
						CustomType:  timetypes.GoDurationType{},
					},
					"interval_jitter": schema.StringAttribute{
						Description: "An optional jitter amount for every interval.",
						Computed:    true,
						CustomType:  timetypes.GoDurationType{},
					},
					"interval_jitter_percent": schema.Int64Attribute{
						Description: "An optional jitter percentage.",
						Computed:    true,
					},
					"tcp_health_check": schema.SingleNestedAttribute{
						Description: "TCP health check settings.",
						Computed:    true,
						Attributes: map[string]schema.Attribute{
							"receive": schema.SetNestedAttribute{
								Description: "Expected response payloads.",
								Computed:    true,
								NestedObject: schema.NestedAttributeObject{
									Attributes: map[string]schema.Attribute{
										"binary_b64": schema.StringAttribute{
											Description: "Base64 encoded binary payload.",
											Computed:    true,
										},
										"text": schema.StringAttribute{
											Description: "Hex encoded payload.",
											Computed:    true,
										},
									},
								},
							},
							"send": schema.SingleNestedAttribute{
								Description: "Payload to send.",
								Computed:    true,
								Attributes: map[string]schema.Attribute{
									"binary_b64": schema.StringAttribute{
										Description: "Base64 encoded binary payload.",
										Computed:    true,
									},
									"text": schema.StringAttribute{
										Description: "Hex encoded payload.",
										Computed:    true,
									},
								},
							},
						},
					},
					"timeout": schema.StringAttribute{
						Description: "The time to wait for a health check response.",
						Computed:    true,
						CustomType:  timetypes.GoDurationType{},
					},
					"unhealthy_threshold": schema.Int64Attribute{
						Description: "Number of failures before marking unhealthy.",
						Computed:    true,
					},
				},
			},
		},
		"healthy_panic_threshold": schema.Int32Attribute{
			Description: "If the number of healthy hosts falls below this percentage, traffic will be balanced among all hosts regardless of health, allowing some requests to fail. 0% disables this behavior.",
			Optional:    true,
		},
		"host_path_regex_rewrite_pattern": schema.StringAttribute{
			Computed:    true,
			Description: "Host path regex rewrite pattern.",
		},
		"host_path_regex_rewrite_substitution": schema.StringAttribute{
			Computed:    true,
			Description: "Host path regex rewrite substitution.",
		},
		"host_rewrite": schema.StringAttribute{
			Computed:    true,
			Description: "Host rewrite.",
		},
		"host_rewrite_header": schema.StringAttribute{
			Computed:    true,
			Description: "Host rewrite header.",
		},
		"id": schema.StringAttribute{
			Description: "Unique identifier for the route.",
			Required:    idRequired,
			Computed:    !idRequired,
		},
		"idle_timeout": schema.StringAttribute{
			Computed:    true,
			Description: "Idle timeout.",
			CustomType:  timetypes.GoDurationType{},
		},
		"idp_access_token_allowed_audiences": schema.SetAttribute{
			Description: "IDP access token allowed audiences.",
			Computed:    true,
			ElementType: types.StringType,
		},
		"idp_client_id": schema.StringAttribute{
			Computed:    true,
			Description: "IDP client ID.",
		},
		"idp_client_secret": schema.StringAttribute{
			Computed:    true,
			Description: "IDP client secret.",
		},
		"jwt_groups_filter": JWTGroupsFilterSchema,
		"jwt_issuer_format": schema.StringAttribute{
			Optional:    true,
			Computed:    true,
			Description: "Format for JWT issuer strings. Use 'IssuerHostOnly' for hostname without scheme or trailing slash, or 'IssuerURI' for complete URI including scheme and trailing slash.",
			Validators: []validator.String{
				stringvalidator.OneOf(IssuerFormatValues...),
			},
		},
		"kubernetes_service_account_token": schema.StringAttribute{
			Computed:    true,
			Description: "Kubernetes service account token.",
		},
		"kubernetes_service_account_token_file": schema.StringAttribute{
			Description: "Path to the Kubernetes service account token file.",
			Computed:    true,
		},
		"load_balancing_policy": schema.StringAttribute{
			Optional:    true,
			Computed:    true,
			Description: "Load balancing policy.",
			Validators: []validator.String{
				stringvalidator.OneOf(LoadBalancingPolicyValues...),
			},
		},
		"logo_url": schema.StringAttribute{
			Description: "URL to the logo image.",
			Computed:    true,
		},
		"mcp": RouteMCPSchema(),
		"name": schema.StringAttribute{
			Computed:    true,
			Description: "Name of the route.",
		},
		"namespace_id": schema.StringAttribute{
			Computed:    true,
			Description: "ID of the namespace the route belongs to.",
		},
		"pass_identity_headers": schema.BoolAttribute{
			Computed:    true,
			Description: "Pass identity headers.",
		},
		"path": schema.StringAttribute{
			Computed:    true,
			Description: "Path.",
		},
		"policies": schema.SetAttribute{
			Computed:    true,
			ElementType: types.StringType,
			Description: "List of policy IDs associated with the route.",
		},
		"prefix": schema.StringAttribute{
			Computed:    true,
			Description: "Prefix.",
		},
		"prefix_rewrite": schema.StringAttribute{
			Computed:    true,
			Description: "Prefix rewrite.",
		},
		"preserve_host_header": schema.BoolAttribute{
			Computed:    true,
			Description: "Preserve host header.",
		},
		"regex": schema.StringAttribute{
			Computed:    true,
			Description: "Regex.",
		},
		"regex_priority_order": schema.Int64Attribute{
			Computed:    true,
			Description: "Regex priority order.",
		},
		"regex_rewrite_pattern": schema.StringAttribute{
			Computed:    true,
			Description: "Regex rewrite pattern.",
		},
		"regex_rewrite_substitution": schema.StringAttribute{
			Computed:    true,
			Description: "Regex rewrite substitution.",
		},
		"remove_request_headers": schema.SetAttribute{
			Computed:    true,
			ElementType: types.StringType,
			Description: "Remove request headers.",
		},
		"rewrite_response_headers": schema.SetNestedAttribute{
			Description: "Response header rewrite rules.",
			Computed:    true,
			NestedObject: schema.NestedAttributeObject{
				Attributes: map[string]schema.Attribute{
					"header": schema.StringAttribute{
						Required:    true,
						Description: "Header name to rewrite",
					},
					"prefix": schema.StringAttribute{
						Optional:    true,
						Description: "Prefix matcher for the header",
					},
					"value": schema.StringAttribute{
						Required:    true,
						Description: "New value for the header",
					},
				},
			},
		},
		"set_request_headers": schema.MapAttribute{
			Computed:    true,
			ElementType: types.StringType,
			Description: "Set request headers.",
		},
		"set_response_headers": schema.MapAttribute{
			Computed:    true,
			ElementType: types.StringType,
			Description: "Set response headers.",
		},
		"show_error_details": schema.BoolAttribute{
			Computed:    true,
			Description: "Show error details.",
		},
		"stat_name": schema.StringAttribute{
			Computed:    true,
			Description: "Name of the stat.",
		},
		"timeout": schema.StringAttribute{
			Computed:    true,
			Description: "Timeout.",
			CustomType:  timetypes.GoDurationType{},
		},
		"tls_client_key_pair_id": schema.StringAttribute{
			Description: "Client key pair ID for TLS client authentication.",
			Computed:    true,
		},
		"tls_custom_ca_key_pair_id": schema.StringAttribute{
			Description: "Custom CA key pair ID for TLS verification.",
			Computed:    true,
		},
		"tls_downstream_server_name": schema.StringAttribute{
			Computed:    true,
			Description: "TLS downstream server name.",
		},
		"tls_skip_verify": schema.BoolAttribute{
			Computed:    true,
			Description: "TLS skip verify.",
		},
		"tls_upstream_allow_renegotiation": schema.BoolAttribute{
			Computed:    true,
			Description: "TLS upstream allow renegotiation.",
		},
		"tls_upstream_server_name": schema.StringAttribute{
			Computed:    true,
			Description: "TLS upstream server name.",
		},
		"to": schema.SetAttribute{
			Computed:    true,
			ElementType: types.StringType,
			Description: "To URLs.",
		},
		"upstream_tunnel": schema.SingleNestedAttribute{
			Description: "Upstream tunnel settings.",
			Computed:    true,
			Attributes: map[string]schema.Attribute{
				"ssh_policy": schema.StringAttribute{
					Optional: true,
					Computed: true,
				},
			},
		},
	}
}

func NewRouteDataSource() datasource.DataSource {
	return new(RouteDataSource)
}

type RouteDataSource struct {
	client *Client
}

func (d *RouteDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_route"
}

func (d *RouteDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Route data source",
		Attributes:          getRouteDataSourceAttributes(true),
	}
}

func (d *RouteDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = ConfigureClient(req, resp)
}

func (d *RouteDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data RouteModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(d.client.ConsolidatedOrLegacy(
		func(client sdk.Client) {
			getReq := connect.NewRequest(&pomerium.GetRouteRequest{
				Id: data.ID.ValueString(),
			})
			getRes, err := client.GetRoute(ctx, getReq)
			if err != nil {
				resp.Diagnostics.AddError("Error getting route", err.Error())
				return
			}

			data = NewAPIToModelConverter(&resp.Diagnostics).Route(getRes.Msg.Route)
		},
		func(client *client.Client) {
			getReq := &pb.GetRouteRequest{
				Id: data.ID.ValueString(),
			}
			getRes, err := client.RouteService.GetRoute(ctx, getReq)
			if err != nil {
				resp.Diagnostics.AddError("Error reading route", err.Error())
				return
			}

			data = NewEnterpriseToModelConverter(&resp.Diagnostics).Route(getRes.GetRoute())
		})...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
