package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	client "github.com/pomerium/enterprise-client-go"
	"github.com/pomerium/enterprise-client-go/pb"
)

var _ datasource.DataSource = &RouteDataSource{}

func getRouteDataSourceAttributes(idRequired bool) map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"id": schema.StringAttribute{
			Description: "Unique identifier for the route.",
			Required:    idRequired,
			Computed:    !idRequired,
		},
		"name": schema.StringAttribute{
			Computed:    true,
			Description: "Name of the route.",
		},
		"from": schema.StringAttribute{
			Computed:    true,
			Description: "From URL.",
		},
		"to": schema.SetAttribute{
			Computed:    true,
			ElementType: types.StringType,
			Description: "To URLs.",
		},
		"namespace_id": schema.StringAttribute{
			Computed:    true,
			Description: "ID of the namespace the route belongs to.",
		},
		"policies": schema.SetAttribute{
			Computed:    true,
			ElementType: types.StringType,
			Description: "List of policy IDs associated with the route.",
		},
		"stat_name": schema.StringAttribute{
			Computed:    true,
			Description: "Name of the stat.",
		},
		"prefix": schema.StringAttribute{
			Computed:    true,
			Description: "Prefix.",
		},
		"path": schema.StringAttribute{
			Computed:    true,
			Description: "Path.",
		},
		"regex": schema.StringAttribute{
			Computed:    true,
			Description: "Regex.",
		},
		"prefix_rewrite": schema.StringAttribute{
			Computed:    true,
			Description: "Prefix rewrite.",
		},
		"regex_rewrite_pattern": schema.StringAttribute{
			Computed:    true,
			Description: "Regex rewrite pattern.",
		},
		"regex_rewrite_substitution": schema.StringAttribute{
			Computed:    true,
			Description: "Regex rewrite substitution.",
		},
		"host_rewrite": schema.StringAttribute{
			Computed:    true,
			Description: "Host rewrite.",
		},
		"host_rewrite_header": schema.StringAttribute{
			Computed:    true,
			Description: "Host rewrite header.",
		},
		"host_path_regex_rewrite_pattern": schema.StringAttribute{
			Computed:    true,
			Description: "Host path regex rewrite pattern.",
		},
		"host_path_regex_rewrite_substitution": schema.StringAttribute{
			Computed:    true,
			Description: "Host path regex rewrite substitution.",
		},
		"regex_priority_order": schema.Int64Attribute{
			Computed:    true,
			Description: "Regex priority order.",
		},
		"timeout": schema.StringAttribute{
			Computed:    true,
			Description: "Timeout.",
			CustomType:  timetypes.GoDurationType{},
		},
		"idle_timeout": schema.StringAttribute{
			Computed:    true,
			Description: "Idle timeout.",
			CustomType:  timetypes.GoDurationType{},
		},
		"allow_websockets": schema.BoolAttribute{
			Computed:    true,
			Description: "Allow websockets.",
		},
		"allow_spdy": schema.BoolAttribute{
			Computed:    true,
			Description: "Allow SPDY.",
		},
		"tls_skip_verify": schema.BoolAttribute{
			Computed:    true,
			Description: "TLS skip verify.",
		},
		"tls_upstream_server_name": schema.StringAttribute{
			Computed:    true,
			Description: "TLS upstream server name.",
		},
		"tls_downstream_server_name": schema.StringAttribute{
			Computed:    true,
			Description: "TLS downstream server name.",
		},
		"tls_upstream_allow_renegotiation": schema.BoolAttribute{
			Computed:    true,
			Description: "TLS upstream allow renegotiation.",
		},
		"set_request_headers": schema.MapAttribute{
			Computed:    true,
			ElementType: types.StringType,
			Description: "Set request headers.",
		},
		"remove_request_headers": schema.SetAttribute{
			Computed:    true,
			ElementType: types.StringType,
			Description: "Remove request headers.",
		},
		"set_response_headers": schema.MapAttribute{
			Computed:    true,
			ElementType: types.StringType,
			Description: "Set response headers.",
		},
		"preserve_host_header": schema.BoolAttribute{
			Computed:    true,
			Description: "Preserve host header.",
		},
		"pass_identity_headers": schema.BoolAttribute{
			Computed:    true,
			Description: "Pass identity headers.",
		},
		"kubernetes_service_account_token": schema.StringAttribute{
			Computed:    true,
			Description: "Kubernetes service account token.",
		},
		"idp_client_id": schema.StringAttribute{
			Computed:    true,
			Description: "IDP client ID.",
		},
		"idp_client_secret": schema.StringAttribute{
			Computed:    true,
			Description: "IDP client secret.",
		},
		"show_error_details": schema.BoolAttribute{
			Computed:    true,
			Description: "Show error details.",
		},
		"jwt_groups_filter": JWTGroupsFilterSchema,
		"jwt_issuer_format": schema.StringAttribute{
			Optional:    true,
			Computed:    true,
			Description: "Format for JWT issuer strings. Use 'IssuerHostOnly' for hostname without scheme or trailing slash, or 'IssuerURI' for complete URI including scheme and trailing slash.",
			Validators: []validator.String{
				stringvalidator.OneOf(GetValidEnumValues[pb.IssuerFormat]()...),
			},
		},
		"load_balancing_policy": schema.StringAttribute{
			Optional:    true,
			Computed:    true,
			Description: "Load balancing policy.",
			Validators: []validator.String{
				stringvalidator.OneOf(GetValidEnumValuesCanonical[pb.LoadBalancingPolicy]("LOAD_BALANCING_POLICY")...),
			},
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
		"tls_custom_ca_key_pair_id": schema.StringAttribute{
			Description: "Custom CA key pair ID for TLS verification.",
			Computed:    true,
		},
		"tls_client_key_pair_id": schema.StringAttribute{
			Description: "Client key pair ID for TLS client authentication.",
			Computed:    true,
		},
		"description": schema.StringAttribute{
			Description: "Description of the route.",
			Computed:    true,
		},
		"kubernetes_service_account_token_file": schema.StringAttribute{
			Description: "Path to the Kubernetes service account token file.",
			Computed:    true,
		},
		"logo_url": schema.StringAttribute{
			Description: "URL to the logo image.",
			Computed:    true,
		},
		"enable_google_cloud_serverless_authentication": schema.BoolAttribute{
			Description: "Enable Google Cloud serverless authentication.",
			Computed:    true,
		},
		"bearer_token_format": schema.StringAttribute{
			Description: "Bearer token format.",
			Computed:    true,
		},
		"idp_access_token_allowed_audiences": schema.SetAttribute{
			Description: "IDP access token allowed audiences.",
			Computed:    true,
			ElementType: types.StringType,
		},
		"health_checks": schema.SetNestedAttribute{
			Description: "Health checks for the route.",
			Computed:    true,
			NestedObject: schema.NestedAttributeObject{
				Attributes: map[string]schema.Attribute{
					"timeout": schema.StringAttribute{
						Description: "The time to wait for a health check response.",
						Computed:    true,
						CustomType:  timetypes.GoDurationType{},
					},
					"interval": schema.StringAttribute{
						Description: "The interval between health checks.",
						Computed:    true,
						CustomType:  timetypes.GoDurationType{},
					},
					"initial_jitter": schema.StringAttribute{
						Description: "An optional jitter amount for the first health check.",
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
					"unhealthy_threshold": schema.Int64Attribute{
						Description: "Number of failures before marking unhealthy.",
						Computed:    true,
					},
					"healthy_threshold": schema.Int64Attribute{
						Description: "Number of successes before marking healthy.",
						Computed:    true,
					},
					"http_health_check": schema.SingleNestedAttribute{
						Description: "HTTP health check settings.",
						Computed:    true,
						Attributes: map[string]schema.Attribute{
							"host": schema.StringAttribute{
								Description: "The host header value.",
								Computed:    true,
							},
							"path": schema.StringAttribute{
								Description: "The request path.",
								Computed:    true,
							},
							"expected_statuses": schema.SetNestedAttribute{
								Description: "Expected status code ranges.",
								Computed:    true,
								NestedObject: schema.NestedAttributeObject{
									Attributes: map[string]schema.Attribute{
										"start": schema.Int64Attribute{
											Description: "Start of status code range.",
											Computed:    true,
										},
										"end": schema.Int64Attribute{
											Description: "End of status code range.",
											Computed:    true,
										},
									},
								},
							},
							"retriable_statuses": schema.SetNestedAttribute{
								Description: "Retriable status code ranges.",
								Computed:    true,
								NestedObject: schema.NestedAttributeObject{
									Attributes: map[string]schema.Attribute{
										"start": schema.Int64Attribute{
											Description: "Start of status code range.",
											Computed:    true,
										},
										"end": schema.Int64Attribute{
											Description: "End of status code range.",
											Computed:    true,
										},
									},
								},
							},
							"codec_client_type": schema.StringAttribute{
								Description: "Application protocol for health checks.",
								Computed:    true,
							},
						},
					},
					"tcp_health_check": schema.SingleNestedAttribute{
						Description: "TCP health check settings.",
						Computed:    true,
						Attributes: map[string]schema.Attribute{
							"send": schema.SingleNestedAttribute{
								Description: "Payload to send.",
								Computed:    true,
								Attributes: map[string]schema.Attribute{
									"text": schema.StringAttribute{
										Description: "Hex encoded payload.",
										Computed:    true,
									},
									"binary_b64": schema.StringAttribute{
										Description: "Base64 encoded binary payload.",
										Computed:    true,
									},
								},
							},
							"receive": schema.SetNestedAttribute{
								Description: "Expected response payloads.",
								Computed:    true,
								NestedObject: schema.NestedAttributeObject{
									Attributes: map[string]schema.Attribute{
										"text": schema.StringAttribute{
											Description: "Hex encoded payload.",
											Computed:    true,
										},
										"binary_b64": schema.StringAttribute{
											Description: "Base64 encoded binary payload.",
											Computed:    true,
										},
									},
								},
							},
						},
					},
					"grpc_health_check": schema.SingleNestedAttribute{
						Description: "gRPC health check settings.",
						Computed:    true,
						Attributes: map[string]schema.Attribute{
							"service_name": schema.StringAttribute{
								Description: "Service name to check.",
								Computed:    true,
							},
							"authority": schema.StringAttribute{
								Description: "Authority header value.",
								Computed:    true,
							},
						},
					},
				},
			},
		},
		"depends_on_hosts": schema.SetAttribute{
			Description: "Additional login redirect hosts.",
			Computed:    true,
			ElementType: types.StringType,
		},
		"circuit_breaker_thresholds": circuitBreakerThresholdsAttribute,
	}
}

func NewRouteDataSource() datasource.DataSource {
	return &RouteDataSource{}
}

type RouteDataSource struct {
	client *client.Client
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
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *client.Client, got: %T.", req.ProviderData),
		)
		return
	}

	d.client = client
}

func (d *RouteDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data RouteModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	routeResp, err := d.client.RouteService.GetRoute(ctx, &pb.GetRouteRequest{
		Id: data.ID.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("Error reading route", err.Error())
		return
	}

	diags := ConvertRouteFromPB(&data, routeResp.Route)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
