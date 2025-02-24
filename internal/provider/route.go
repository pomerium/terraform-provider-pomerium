package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	client "github.com/pomerium/enterprise-client-go"
	"github.com/pomerium/enterprise-client-go/pb"
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
	client *client.Client
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
				Optional:    true,
			},
			"path": schema.StringAttribute{
				Description: "Matches incoming requests with a path that is an exact match for the specified path.",
				Optional:    true,
			},
			"regex": schema.StringAttribute{
				Description: "Matches incoming requests with a path that matches the specified regular expression.",
				Optional:    true,
			},
			"prefix_rewrite": schema.StringAttribute{
				Description: "While forwarding a request, Prefix Rewrite swaps the matched prefix (or path) with the specified value.",
				Optional:    true,
			},
			"regex_rewrite_pattern": schema.StringAttribute{
				Description: "Rewrites the URL path according to the regex rewrite pattern.",
				Optional:    true,
			},
			"regex_rewrite_substitution": schema.StringAttribute{
				Description: "Rewrites the URL path according to the regex rewrite substitution.",
				Optional:    true,
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
				Optional:    true,
			},
			"allow_spdy": schema.BoolAttribute{
				Description: "If applied, this setting enables Pomerium to proxy SPDY protocol upgrades.",
				Optional:    true,
			},
			"tls_skip_verify": schema.BoolAttribute{
				Description: "If applied, Pomerium accepts any certificate presented by the upstream server and any Hostname in that certificate. Use for testing only.",
				Optional:    true,
			},
			"tls_upstream_server_name": schema.StringAttribute{
				Description: "This server name overrides the Hostname in the 'To:' field, and will be used to verify the certificate name.",
				Optional:    true,
			},
			"tls_downstream_server_name": schema.StringAttribute{
				Description: "TLS downstream server name.",
				Optional:    true,
			},
			"tls_upstream_allow_renegotiation": schema.BoolAttribute{
				Description: "TLS upstream allow renegotiation.",
				Optional:    true,
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
				Optional:    true,
			},
			"pass_identity_headers": schema.BoolAttribute{
				Description: "If applied, passes X-Pomerium-Jwt-Assertion header and JWT Claims Headers to the upstream application.",
				Optional:    true,
			},
			"kubernetes_service_account_token": schema.StringAttribute{
				Description: "Kubernetes service account token.",
				Optional:    true,
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
				Computed:    true,
				Description: "Format for JWT issuer strings. Use 'IssuerHostOnly' for hostname without scheme or trailing slash, or 'IssuerURI' for complete URI including scheme and trailing slash.",
				Validators: []validator.String{
					stringvalidator.OneOf(GetValidEnumValues[pb.IssuerFormat]()...),
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
				Optional:    true,
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
					stringvalidator.OneOf("default", "idp_access_token", "idp_identity_token"),
				},
			},
			"idp_access_token_allowed_audiences": schema.SetAttribute{
				Description: "IDP access token allowed audiences.",
				Optional:    true,
				ElementType: types.StringType,
			},
		},
	}
}

func (r *RouteResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	c, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected Config, got: %T.", req.ProviderData),
		)

		return
	}

	r.client = c
}

func (r *RouteResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan RouteResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	if resp.Diagnostics.HasError() {
		return
	}

	pbRoute, diags := ConvertRouteToPB(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if diags.HasError() {
		return
	}

	respRoute, err := r.client.RouteService.SetRoute(ctx, &pb.SetRouteRequest{
		Route: pbRoute,
	})
	if err != nil {
		resp.Diagnostics.AddError("set route", err.Error())
		return
	}

	diags = ConvertRouteFromPB(&plan, respRoute.Route)
	resp.Diagnostics.Append(diags...)
	if diags.HasError() {
		return
	}

	tflog.Trace(ctx, "Created a route", map[string]interface{}{
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

	respRoute, err := r.client.RouteService.GetRoute(ctx, &pb.GetRouteRequest{
		Id: state.ID.ValueString(),
	})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("get route", err.Error())
		return
	}

	diags := ConvertRouteFromPB(&state, respRoute.Route)
	resp.Diagnostics.Append(diags...)
	if diags.HasError() {
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

	pbRoute, diags := ConvertRouteToPB(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if diags.HasError() {
		return
	}

	respRoute, err := r.client.RouteService.SetRoute(ctx, &pb.SetRouteRequest{
		Route: pbRoute,
	})
	if err != nil {
		resp.Diagnostics.AddError("set route", err.Error())
		return
	}

	diags = ConvertRouteFromPB(&plan, respRoute.Route)
	resp.Diagnostics.Append(diags...)
	if diags.HasError() {
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

	_, err := r.client.RouteService.DeleteRoute(ctx, &pb.DeleteRouteRequest{
		Id: data.ID.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("delete route", err.Error())
		return
	}

	resp.State.RemoveResource(ctx)
}

func (r *RouteResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
