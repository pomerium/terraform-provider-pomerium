package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	client "github.com/pomerium/enterprise-client-go"
	"github.com/pomerium/enterprise-client-go/pb"
)

var (
	_ resource.Resource                = &SettingsResource{}
	_ resource.ResourceWithImportState = &SettingsResource{}
)

func NewSettingsResource() resource.Resource {
	return &SettingsResource{}
}

type SettingsResource struct {
	client *client.Client
}

func (r *SettingsResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_settings"
}

func (r *SettingsResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = SettingsResourceSchema
}

func (r *SettingsResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *SettingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan SettingsModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	planSettings, diags := ConvertSettingsToPB(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if diags.HasError() {
		return
	}

	respSettings, err := r.client.SettingsService.SetSettings(ctx, &pb.SetSettingsRequest{
		Settings: planSettings,
	})
	if err != nil {
		resp.Diagnostics.AddError("set settings", err.Error())
		return
	}

	diags = ConvertSettingsFromPB(&plan, respSettings.Settings)
	resp.Diagnostics.Append(diags...)
	if diags.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *SettingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state SettingsModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	respSettings, err := r.client.SettingsService.GetSettings(ctx, &pb.GetSettingsRequest{
		ClusterId: state.ClusterID.ValueStringPointer(),
	})
	if err != nil {
		resp.Diagnostics.AddError("get settings", err.Error())
		return
	}

	diags := ConvertSettingsFromPB(&state, respSettings.Settings)
	resp.Diagnostics.Append(diags...)
	if diags.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *SettingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan SettingsModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	planSettings, diags := ConvertSettingsToPB(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if diags.HasError() {
		return
	}

	respSettings, err := r.client.SettingsService.SetSettings(ctx, &pb.SetSettingsRequest{
		Settings: planSettings,
	})
	if err != nil {
		resp.Diagnostics.AddError("set settings", err.Error())
		return
	}

	plan.ID = types.StringValue(respSettings.GetSettings().GetId())
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *SettingsResource) Delete(ctx context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	resp.State.RemoveResource(ctx)
}

func (r *SettingsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
