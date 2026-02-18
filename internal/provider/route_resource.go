package provider

import (
	"context"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	client "github.com/pomerium/enterprise-client-go"
	"github.com/pomerium/enterprise-client-go/pb"
	"github.com/pomerium/sdk-go"
	"github.com/pomerium/sdk-go/proto/pomerium"
)

// Ensure provider defined types fully satisfy framework interfaces.
var (
	_ resource.Resource                = &RouteResource{}
	_ resource.ResourceWithImportState = &RouteResource{}
)

func NewRouteResource() resource.Resource {
	return &RouteResource{}
}

// RouteResource defines the resource implementation.
type RouteResource struct {
	client *Client
}

// RouteResourceModel describes the resource data model.
type RouteResourceModel = RouteModel

func (r *RouteResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_route"
}

func (r *RouteResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Route for Pomerium.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Unique identifier for the route.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "Name of the route.",
				Required:    true,
			},
			"from": schema.StringAttribute{
				Description: "The external URL for a proxied request. Must contain a scheme and Hostname, must not contain a path.",
				Required:    true,
			},
			"to": schema.SetAttribute{
				ElementType: types.StringType,
				Description: "The destination(s) of a proxied request. Must contain a scheme and Hostname, with an optional weight.",
				Required:    true,
			},
			"namespace_id": schema.StringAttribute{
				Description: "ID of the namespace the route belongs to.",
				Required:    true,
			},
			"policies": schema.SetAttribute{
				ElementType: types.StringType,
				Description: "List of policy IDs associated with the route.",
				Optional:    true,
			},
			"stat_name": schema.StringAttribute{
				Description: "Name of the stat.",
				Optional:    true,
				Computed:    true,
			},
			"prefix": schema.StringAttribute{
				Description: "Matches incoming requests with a path that begins with the specified prefix.",
				Computed:    true,
				Optional:    true,
				Default:     stringdefault.StaticString(""),
			},
			"path": schema.StringAttribute{
				Description: "Matches incoming requests with a path that is an exact match for the specified path.",
				Computed:    true,
				Optional:    true,
				Default:     stringdefault.StaticString(""),
			},
			"regex": schema.StringAttribute{
				Description: "Matches incoming requests with a path that matches the specified regular expression.",
				Computed:    true,
				Optional:    true,
				Default:     stringdefault.StaticString(""),
			},
			"prefix_rewrite": schema.StringAttribute{
				Description: "While forwarding a request, Prefix Rewrite swaps the matched prefix (or path) with the specified value.",
				Computed:    true,
				Optional:    true,
				Default:     stringdefault.StaticString(""),
			},
			"regex_rewrite_pattern": schema.StringAttribute{
				Description: "Rewrites the URL path according to the regex rewrite pattern.",
				Computed:    true,
				Optional:    true,
				Default:     stringdefault.StaticString(""),
			},
			"regex_rewrite_substitution": schema.StringAttribute{
				Description: "Rewrites the URL path according to the regex rewrite substitution.",
				Computed:    true,
				Optional:    true,
				Default:     stringdefault.StaticString(""),
			},
			"host_rewrite": schema.StringAttribute{
				Description: "Rewrites the Host header to a new literal value.",
				Optional:    true,
			},
			"host_rewrite_header": schema.StringAttribute{
				Description: "Rewrites the Host header to match an incoming header value.",
				Optional:    true,
			},
			"host_path_regex_rewrite_pattern": schema.StringAttribute{
				Description: "Rewrites the Host header according to a regular expression matching the path.",
				Optional:    true,
			},
			"host_path_regex_rewrite_substitution": schema.StringAttribute{
				Description: "Rewrites the Host header according to a regular expression matching the substitution.",
				Optional:    true,
			},
			"regex_priority_order": schema.Int64Attribute{
				Description: "Regex priority order.",
				Optional:    true,
			},
			"timeout": schema.StringAttribute{
				Description: "Sets the per-route timeout value. Cannot exceed global timeout values. Defaults to 30 seconds.",
				Optional:    true,
				CustomType:  timetypes.GoDurationType{},
				Computed:    true,
			},
			"idle_timeout": schema.StringAttribute{
				Description: "Sets the time to terminate the upstream connection if there are no active streams. Defaults to 5 minutes.",
				Optional:    true,
				CustomType:  timetypes.GoDurationType{},
				Computed:    true,
			},
			"allow_websockets": schema.BoolAttribute{
				Description: "If applied, this setting enables Pomerium to proxy websocket connections.",
				Computed:    true,
				Optional:    true,
				Default:     booldefault.StaticBool(false),
			},
			"allow_spdy": schema.BoolAttribute{
				Description: "If applied, this setting enables Pomerium to proxy SPDY protocol upgrades.",
				Computed:    true,
				Optional:    true,
				Default:     booldefault.StaticBool(false),
			},
			"tls_skip_verify": schema.BoolAttribute{
				Description: "If applied, Pomerium accepts any certificate presented by the upstream server and any Hostname in that certificate. Use for testing only.",
				Computed:    true,
				Optional:    true,
				Default:     booldefault.StaticBool(false),
			},
			"tls_upstream_server_name": schema.StringAttribute{
				Description: "This server name overrides the Hostname in the 'To:' field, and will be used to verify the certificate name.",
				Computed:    true,
				Optional:    true,
				Default:     stringdefault.StaticString(""),
			},
			"tls_downstream_server_name": schema.StringAttribute{
				Description: "TLS downstream server name.",
				Computed:    true,
				Optional:    true,
				Default:     stringdefault.StaticString(""),
			},
			"tls_upstream_allow_renegotiation": schema.BoolAttribute{
				Description: "TLS upstream allow renegotiation.",
				Computed:    true,
				Optional:    true,
				Default:     booldefault.StaticBool(false),
			},
			"set_request_headers": schema.MapAttribute{
				ElementType: types.StringType,
				Description: "Sets static and dynamic values for given request headers. Available substitutions: ${pomerium.id_token}, ${pomerium.access_token}, ${pomerium.client_cert_fingerprint}.",
				Optional:    true,
			},
			"remove_request_headers": schema.SetAttribute{
				ElementType: types.StringType,
				Description: "Removes given request headers so they do not reach the upstream server.",
				Optional:    true,
			},
			"set_response_headers": schema.MapAttribute{
				ElementType: types.StringType,
				Description: "Sets static HTTP Response Header values for a route. These headers take precedence over globally set response headers.",
				Optional:    true,
			},
			"preserve_host_header": schema.BoolAttribute{
				Description: "Passes the host header from the incoming request to the proxied host, instead of the destination hostname.",
				Computed:    true,
				Optional:    true,
				Default:     booldefault.StaticBool(false),
			},
			"pass_identity_headers": schema.BoolAttribute{
				Description: "If applied, passes X-Pomerium-Jwt-Assertion header and JWT Claims Headers to the upstream application.",
				Optional:    true,
			},
			"kubernetes_service_account_token": schema.StringAttribute{
				Description: "Kubernetes service account token.",
				Computed:    true,
				Optional:    true,
				Default:     stringdefault.StaticString(""),
			},
			"idp_client_id": schema.StringAttribute{
				Description: "IDP client ID.",
				Optional:    true,
			},
			"idp_client_secret": schema.StringAttribute{
				Description: "IDP client secret.",
				Optional:    true,
			},
			"show_error_details": schema.BoolAttribute{
				Description: "If applied, shows error details, including policy explanation and remediation for 403 Forbidden responses.",
				Optional:    true,
				Computed:    true,
			},
			"jwt_groups_filter": JWTGroupsFilterSchema,
			"jwt_issuer_format": schema.StringAttribute{
				Optional:    true,
				Description: "Format for JWT issuer strings. Use 'IssuerHostOnly' for hostname without scheme or trailing slash, or 'IssuerURI' for complete URI including scheme and trailing slash.",
				Validators: []validator.String{
					stringvalidator.OneOf(IssuerFormatValues...),
				},
			},
			"load_balancing_policy": schema.StringAttribute{
				Description:         "Load balancing policy.",
				MarkdownDescription: GetValidEnumValuesCanonicalMarkdown("Load Balancing Policy", LoadBalancingPolicyValues),
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.OneOf(LoadBalancingPolicyValues...),
				},
			},
			"rewrite_response_headers": schema.SetNestedAttribute{
				Description: "Modifies response headers before they are returned to the client. 'Header' matches the HTTP header name; 'prefix' will be replaced with 'value'.",
				Optional:    true,
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
				Optional:    true,
			},
			"tls_client_key_pair_id": schema.StringAttribute{
				Description: "Client key pair ID for TLS client authentication.",
				Optional:    true,
			},
			"description": schema.StringAttribute{
				Description: "Description of the route.",
				Optional:    true,
			},
			"kubernetes_service_account_token_file": schema.StringAttribute{
				Description: "Path to the Kubernetes service account token file.",
				Computed:    true,
				Optional:    true,
				Default:     stringdefault.StaticString(""),
			},
			"logo_url": schema.StringAttribute{
				Description: "URL to the logo image.",
				Optional:    true,
			},
			"enable_google_cloud_serverless_authentication": schema.BoolAttribute{
				Description: "Enable Google Cloud serverless authentication.",
				Optional:    true,
			},
			"bearer_token_format": schema.StringAttribute{
				Description: "Bearer token format.",
				Optional:    true,
				Validators: []validator.String{
					stringvalidator.OneOf(BearerTokenFormatValues...),
				},
			},
			"idp_access_token_allowed_audiences": schema.SetAttribute{
				Description: "IDP access token allowed audiences.",
				Optional:    true,
				ElementType: types.StringType,
			},
			"health_checks": schema.SetNestedAttribute{
				Description: "Health checks for the route.",
				Optional:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"timeout": schema.StringAttribute{
							Description: "The time to wait for a health check response. If the timeout is reached the health check attempt will be considered a failure.",
							Optional:    true,
							CustomType:  timetypes.GoDurationType{},
						},
						"interval": schema.StringAttribute{
							Description: "The interval between health checks.",
							Optional:    true,
							CustomType:  timetypes.GoDurationType{},
						},
						"initial_jitter": schema.StringAttribute{
							Description: "An optional jitter amount in milliseconds. If specified, Envoy will start health checking after for a random time in ms between 0 and initial_jitter.",
							Optional:    true,
							CustomType:  timetypes.GoDurationType{},
						},
						"interval_jitter": schema.StringAttribute{
							Description: "An optional jitter amount in milliseconds. If specified, during every interval Envoy will add interval_jitter to the wait time.",
							Optional:    true,
							CustomType:  timetypes.GoDurationType{},
						},
						"interval_jitter_percent": schema.Int64Attribute{
							Description: "An optional jitter amount as a percentage of interval_ms. If specified, during every interval Envoy will add interval_ms * interval_jitter_percent / 100 to the wait time.",
							Optional:    true,
						},
						"unhealthy_threshold": schema.Int64Attribute{
							Description: "The number of unhealthy health checks required before a host is marked unhealthy.",
							Optional:    true,
						},
						"healthy_threshold": schema.Int64Attribute{
							Description: "The number of healthy health checks required before a host is marked healthy.",
							Optional:    true,
						},
						"http_health_check": schema.SingleNestedAttribute{
							Description: "HTTP health check settings.",
							Optional:    true,
							Attributes: map[string]schema.Attribute{
								"host": schema.StringAttribute{
									Description: "The value of the host header in the HTTP health check request.",
									Optional:    true,
								},
								"path": schema.StringAttribute{
									Description: "Specifies the HTTP path that will be requested during health checking.",
									Optional:    true,
								},
								"expected_statuses": schema.SetNestedAttribute{
									Description: "Specifies a list of HTTP response statuses considered healthy.",
									Optional:    true,
									NestedObject: schema.NestedAttributeObject{
										Attributes: map[string]schema.Attribute{
											"start": schema.Int64Attribute{
												Description: "Start of status code range.",
												Required:    true,
											},
											"end": schema.Int64Attribute{
												Description: "End of status code range.",
												Required:    true,
											},
										},
									},
								},
								"retriable_statuses": schema.SetNestedAttribute{
									Description: "Specifies a list of HTTP response statuses considered retriable.",
									Optional:    true,
									NestedObject: schema.NestedAttributeObject{
										Attributes: map[string]schema.Attribute{
											"start": schema.Int64Attribute{
												Description: "Start of status code range.",
												Required:    true,
											},
											"end": schema.Int64Attribute{
												Description: "End of status code range.",
												Required:    true,
											},
										},
									},
								},
								"codec_client_type": schema.StringAttribute{
									Description: "Use specified application protocol for health checks.",
									Optional:    true,
									Validators: []validator.String{
										stringvalidator.OneOf(CodecClientTypeValues...),
									},
								},
							},
						},
						"tcp_health_check": schema.SingleNestedAttribute{
							Description: "TCP health check settings.",
							Optional:    true,
							Attributes: map[string]schema.Attribute{
								"send": schema.SingleNestedAttribute{
									Description: "Empty payloads imply a connect-only health check.",
									Optional:    true,
									Attributes: map[string]schema.Attribute{
										"text": schema.StringAttribute{
											Description: "Hex encoded payload. E.g., '000000FF'.",
											Optional:    true,
										},
										"binary_b64": schema.StringAttribute{
											Description: "Base64 encoded binary payload.",
											Optional:    true,
										},
									},
								},
								"receive": schema.SetNestedAttribute{
									Description: "When checking the response, 'fuzzy' matching is performed such that each payload block must be found, and in the order specified, but not necessarily contiguous.",
									Optional:    true,
									NestedObject: schema.NestedAttributeObject{
										Attributes: map[string]schema.Attribute{
											"text": schema.StringAttribute{
												Description: "Hex encoded payload. E.g., '000000FF'.",
												Optional:    true,
											},
											"binary_b64": schema.StringAttribute{
												Description: "Base64 encoded binary payload.",
												Optional:    true,
											},
										},
									},
								},
							},
						},
						"grpc_health_check": schema.SingleNestedAttribute{
							Description: "gRPC health check settings.",
							Optional:    true,
							Attributes: map[string]schema.Attribute{
								"service_name": schema.StringAttribute{
									Description: "An optional service name parameter which will be sent to gRPC service.",
									Optional:    true,
								},
								"authority": schema.StringAttribute{
									Description: "The value of the :authority header in the gRPC health check request.",
									Optional:    true,
								},
							},
						},
					},
				},
			},
			"depends_on_hosts": schema.SetAttribute{
				Description: "Additional login redirect hosts.",
				Optional:    true,
				ElementType: types.StringType,
			},
			"circuit_breaker_thresholds": CircuitBreakerThresholdsSchema,
			"healthy_panic_threshold": schema.Int32Attribute{
				Description: "If the number of healthy hosts falls below this percentage, traffic will be balanced among all hosts regardless of health, allowing some requests to fail. 0% disables this behavior.",
				Optional:    true,
			},
		},
	}
}

func (r *RouteResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = ConfigureClient(req, resp)
}

func (r *RouteResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan RouteResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.client.ConsolidatedOrLegacy(ctx,
		func(client sdk.Client) {
			apiRoute := NewModelToAPIConverter(&resp.Diagnostics).Route(plan)
			if resp.Diagnostics.HasError() {
				return
			}

			createReq := connect.NewRequest(&pomerium.CreateRouteRequest{
				Route: apiRoute,
			})
			createRes, err := client.CreateRoute(ctx, createReq)
			if err != nil {
				resp.Diagnostics.AddError("Error creating route", err.Error())
				return
			}

			plan = NewAPIToModelConverter(&resp.Diagnostics).Route(createRes.Msg.Route)
		},
		func(client *client.Client) {
			pbRoute := NewModelToEnterpriseConverter(&resp.Diagnostics).Route(plan)
			if resp.Diagnostics.HasError() {
				return
			}

			setReq := &pb.SetRouteRequest{
				Route: pbRoute,
			}
			setRes, err := client.RouteService.SetRoute(ctx, setReq)
			if err != nil {
				resp.Diagnostics.AddError("set route", err.Error())
				return
			}

			plan = NewEnterpriseToModelConverter(&resp.Diagnostics).Route(setRes.GetRoute())
		})...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Trace(ctx, "Created a route", map[string]any{
		"id":   plan.ID.ValueString(),
		"name": plan.Name.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *RouteResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state RouteResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.client.ConsolidatedOrLegacy(ctx,
		func(client sdk.Client) {
			getReq := connect.NewRequest(&pomerium.GetRouteRequest{
				Id: state.ID.ValueString(),
			})
			getRes, err := client.GetRoute(ctx, getReq)
			if connect.CodeOf(err) == connect.CodeNotFound {
				resp.State.RemoveResource(ctx)
				return
			} else if err != nil {
				resp.Diagnostics.AddError("Error getting route", err.Error())
				return
			}

			state = NewAPIToModelConverter(&resp.Diagnostics).Route(getRes.Msg.Route)
		},
		func(client *client.Client) {
			getReq := &pb.GetRouteRequest{
				Id: state.ID.ValueString(),
			}
			getRes, err := client.RouteService.GetRoute(ctx, getReq)
			if err != nil {
				if status.Code(err) == codes.NotFound {
					resp.State.RemoveResource(ctx)
					return
				}
				resp.Diagnostics.AddError("get route", err.Error())
				return
			}

			state = NewEnterpriseToModelConverter(&resp.Diagnostics).Route(getRes.GetRoute())
		})...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *RouteResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan RouteResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.client.ConsolidatedOrLegacy(ctx,
		func(client sdk.Client) {
			apiRoute := NewModelToAPIConverter(&resp.Diagnostics).Route(plan)
			if resp.Diagnostics.HasError() {
				return
			}

			updateReq := connect.NewRequest(&pomerium.UpdateRouteRequest{
				Route: apiRoute,
			})
			updateRes, err := client.UpdateRoute(ctx, updateReq)
			if err != nil {
				resp.Diagnostics.AddError("Error updating route", err.Error())
				return
			}

			plan = NewAPIToModelConverter(&resp.Diagnostics).Route(updateRes.Msg.Route)
		},
		func(client *client.Client) {
			pbRoute := NewModelToEnterpriseConverter(&resp.Diagnostics).Route(plan)
			if resp.Diagnostics.HasError() {
				return
			}

			setReq := &pb.SetRouteRequest{
				Route: pbRoute,
			}
			setRes, err := client.RouteService.SetRoute(ctx, setReq)
			if err != nil {
				resp.Diagnostics.AddError("set route", err.Error())
				return
			}

			plan = NewEnterpriseToModelConverter(&resp.Diagnostics).Route(setRes.GetRoute())
		})...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *RouteResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data RouteResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.client.ConsolidatedOrLegacy(ctx,
		func(client sdk.Client) {
			deleteReq := connect.NewRequest(&pomerium.DeleteRouteRequest{
				Id: data.ID.ValueString(),
			})
			_, err := client.DeleteRoute(ctx, deleteReq)
			if err != nil {
				resp.Diagnostics.AddError("Error deleting route", err.Error())
				return
			}
		},
		func(client *client.Client) {
			deleteReq := &pb.DeleteRouteRequest{
				Id: data.ID.ValueString(),
			}
			_, err := client.RouteService.DeleteRoute(ctx, deleteReq)
			if err != nil {
				resp.Diagnostics.AddError("delete route", err.Error())
				return
			}
		})...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.State.RemoveResource(ctx)
}

func (r *RouteResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
