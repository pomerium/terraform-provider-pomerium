package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
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
	resp.Schema = RouteSchema(false)
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

	plan.ID = types.StringValue(respRoute.Route.Id)

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

	_, err := r.client.RouteService.SetRoute(ctx, &pb.SetRouteRequest{
		Route: pbRoute,
	})
	if err != nil {
		resp.Diagnostics.AddError("set route", err.Error())
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

func ConvertRouteToPB(
	ctx context.Context,
	src *RouteResourceModel,
) (*pb.Route, diag.Diagnostics) {
	pbRoute := new(pb.Route)
	var diagnostics diag.Diagnostics

	pbRoute.Id = src.ID.ValueString()
	pbRoute.Name = src.Name.ValueString()
	pbRoute.From = src.From.ValueString()
	pbRoute.NamespaceId = src.NamespaceID.ValueString()

	diags := src.To.ElementsAs(ctx, &pbRoute.To, false)
	diagnostics.Append(diags...)

	if !src.Policies.IsNull() {
		diags = src.Policies.ElementsAs(ctx, &pbRoute.PolicyIds, false)
		diagnostics.Append(diags...)
	}
	return pbRoute, diagnostics
}

func ConvertRouteFromPB(
	dst *RouteResourceModel,
	src *pb.Route,
) diag.Diagnostics {
	var diagnostics diag.Diagnostics

	dst.ID = types.StringValue(src.Id)
	dst.Name = types.StringValue(src.Name)
	dst.From = types.StringValue(src.From)
	dst.NamespaceID = types.StringValue(src.NamespaceId)

	toList := make([]attr.Value, len(src.To))
	for i, v := range src.To {
		toList[i] = types.StringValue(v)
	}
	dst.To = types.ListValueMust(types.StringType, toList)

	policiesList := make([]attr.Value, len(src.PolicyIds))
	for i, v := range src.PolicyIds {
		policiesList[i] = types.StringValue(v)
	}
	dst.Policies = types.ListValueMust(types.StringType, policiesList)

	return diagnostics
}
