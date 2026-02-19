package provider

import (
	"context"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	client "github.com/pomerium/enterprise-client-go"
	"github.com/pomerium/enterprise-client-go/pb"
	"github.com/pomerium/sdk-go"
	"github.com/pomerium/sdk-go/proto/pomerium"
)

var (
	_ resource.Resource                = &SettingsResource{}
	_ resource.ResourceWithImportState = &SettingsResource{}
)

func NewSettingsResource() resource.Resource {
	return &SettingsResource{}
}

type SettingsResource struct {
	client *Client
}

func (r *SettingsResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_settings"
}

func (r *SettingsResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = SettingsResourceSchema
}

func (r *SettingsResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = ConfigureClient(req, resp)
}

func (r *SettingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan SettingsModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.client.ConsolidatedOrLegacy(
		func(client sdk.Client) {
			apiSettings := NewModelToAPIConverter(&resp.Diagnostics).Settings(plan)
			if resp.Diagnostics.HasError() {
				return
			}

			updateReq := connect.NewRequest(&pomerium.UpdateSettingsRequest{
				Settings: apiSettings,
			})
			updateRes, err := client.UpdateSettings(ctx, updateReq)
			if err != nil {
				resp.Diagnostics.AddError("Error updating service account", err.Error())
				return
			}

			plan = NewAPIToModelConverter(&resp.Diagnostics).Settings(updateRes.Msg.Settings)
		},
		func(client *client.Client) {
			planSettings := NewModelToEnterpriseConverter(&resp.Diagnostics).Settings(plan)
			if resp.Diagnostics.HasError() {
				return
			}

			setReq := &pb.SetSettingsRequest{
				Settings: planSettings,
			}
			setRes, err := client.SettingsService.SetSettings(ctx, setReq)
			if err != nil {
				resp.Diagnostics.AddError("set settings", err.Error())
				return
			}

			plan = NewEnterpriseToModelConverter(&resp.Diagnostics).Settings(setRes.GetSettings())
		})...)
	if resp.Diagnostics.HasError() {
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

	resp.Diagnostics.Append(r.client.ConsolidatedOrLegacy(
		func(client sdk.Client) {
			getReq := connect.NewRequest(&pomerium.GetSettingsRequest{
				For: &pomerium.GetSettingsRequest_Id{
					Id: state.ID.ValueString(),
				},
			})
			getRes, err := client.GetSettings(ctx, getReq)
			if connect.CodeOf(err) == connect.CodeNotFound {
				resp.State.RemoveResource(ctx)
				return
			} else if err != nil {
				resp.Diagnostics.AddError("Error getting settings", err.Error())
				return
			}

			state = NewAPIToModelConverter(&resp.Diagnostics).Settings(getRes.Msg.Settings)
		},
		func(client *client.Client) {
			getReq := &pb.GetSettingsRequest{
				ClusterId: state.ClusterID.ValueStringPointer(),
			}
			getRes, err := client.SettingsService.GetSettings(ctx, getReq)
			if err != nil {
				resp.Diagnostics.AddError("get settings", err.Error())
				return
			}

			state = NewEnterpriseToModelConverter(&resp.Diagnostics).Settings(getRes.GetSettings())
		})...)
	if resp.Diagnostics.HasError() {
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

	resp.Diagnostics.Append(r.client.ConsolidatedOrLegacy(
		func(client sdk.Client) {
			apiSettings := NewModelToAPIConverter(&resp.Diagnostics).Settings(plan)
			if resp.Diagnostics.HasError() {
				return
			}

			updateReq := connect.NewRequest(&pomerium.UpdateSettingsRequest{
				Settings: apiSettings,
			})
			updateRes, err := client.UpdateSettings(ctx, updateReq)
			if err != nil {
				resp.Diagnostics.AddError("Error updating service account", err.Error())
				return
			}

			plan = NewAPIToModelConverter(&resp.Diagnostics).Settings(updateRes.Msg.Settings)
		},
		func(client *client.Client) {
			planSettings := NewModelToEnterpriseConverter(&resp.Diagnostics).Settings(plan)
			if resp.Diagnostics.HasError() {
				return
			}

			setReq := &pb.SetSettingsRequest{
				Settings: planSettings,
			}
			setRes, err := client.SettingsService.SetSettings(ctx, setReq)
			if err != nil {
				resp.Diagnostics.AddError("set settings", err.Error())
				return
			}

			plan.ID = types.StringValue(setRes.GetSettings().GetId())
		})...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *SettingsResource) Delete(ctx context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	resp.State.RemoveResource(ctx)
}

func (r *SettingsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
