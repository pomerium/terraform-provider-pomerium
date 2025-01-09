package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
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
				Description: "From URL.",
				Required:    true,
			},
			"to": schema.ListAttribute{
				ElementType: types.StringType,
				Description: "To URLs.",
				Required:    true,
			},
			"namespace_id": schema.StringAttribute{
				Description: "ID of the namespace the route belongs to.",
				Required:    true,
			},
			"policies": schema.ListAttribute{
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
				Description: "Prefix.",
				Optional:    true,
			},
			"path": schema.StringAttribute{
				Description: "Path.",
				Optional:    true,
			},
			"regex": schema.StringAttribute{
				Description: "Regex.",
				Optional:    true,
			},
			"prefix_rewrite": schema.StringAttribute{
				Description: "Prefix rewrite.",
				Optional:    true,
			},
			"regex_rewrite_pattern": schema.StringAttribute{
				Description: "Regex rewrite pattern.",
				Optional:    true,
			},
			"regex_rewrite_substitution": schema.StringAttribute{
				Description: "Regex rewrite substitution.",
				Optional:    true,
			},
			"host_rewrite": schema.StringAttribute{
				Description: "Host rewrite.",
				Optional:    true,
			},
			"host_rewrite_header": schema.StringAttribute{
				Description: "Host rewrite header.",
				Optional:    true,
			},
			"host_path_regex_rewrite_pattern": schema.StringAttribute{
				Description: "Host path regex rewrite pattern.",
				Optional:    true,
			},
			"host_path_regex_rewrite_substitution": schema.StringAttribute{
				Description: "Host path regex rewrite substitution.",
				Optional:    true,
			},
			"regex_priority_order": schema.Int64Attribute{
				Description: "Regex priority order.",
				Optional:    true,
			},
			"timeout": schema.StringAttribute{
				Description: "Timeout.",
				Optional:    true,
				CustomType:  timetypes.GoDurationType{},
				Computed:    true,
			},
			"idle_timeout": schema.StringAttribute{
				Description: "Idle timeout.",
				Optional:    true,
				CustomType:  timetypes.GoDurationType{},
				Computed:    true,
			},
			"allow_websockets": schema.BoolAttribute{
				Description: "Allow websockets.",
				Optional:    true,
			},
			"allow_spdy": schema.BoolAttribute{
				Description: "Allow SPDY.",
				Optional:    true,
			},
			"tls_skip_verify": schema.BoolAttribute{
				Description: "TLS skip verify.",
				Optional:    true,
			},
			"tls_upstream_server_name": schema.StringAttribute{
				Description: "TLS upstream server name.",
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
				Description: "Set request headers.",
				Optional:    true,
			},
			"remove_request_headers": schema.ListAttribute{
				ElementType: types.StringType,
				Description: "Remove request headers.",
				Optional:    true,
			},
			"set_response_headers": schema.MapAttribute{
				ElementType: types.StringType,
				Description: "Set response headers.",
				Optional:    true,
			},
			"preserve_host_header": schema.BoolAttribute{
				Description: "Preserve host header.",
				Optional:    true,
			},
			"pass_identity_headers": schema.BoolAttribute{
				Description: "Pass identity headers.",
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
				Description: "Show error details.",
				Optional:    true,
				Computed:    true,
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
