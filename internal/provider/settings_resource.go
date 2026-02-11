package provider

import (
	"context"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"google.golang.org/protobuf/proto"

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
	var model SettingsModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}

	modelToCore := newModelToCoreConverter()
	updateReq := modelToCore.UpdateSettingsRequest(&model)
	resp.Diagnostics.Append(modelToCore.diagnostics...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateRes, err := r.client.shared.UpdateSettings(ctx, updateReq)
	if err != nil {
		resp.Diagnostics.AddError("set settings", err.Error())
		return
	}

	coreToModel := newCoreToModelConverter()
	model = *coreToModel.Settings(updateRes.Msg.GetSettings())
	resp.Diagnostics.Append(coreToModel.diagnostics...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

func (r *SettingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var model SettingsModel

	resp.Diagnostics.Append(req.State.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}

	listReq := connect.NewRequest(&pomerium.ListSettingsRequest{
		Limit: proto.Uint64(1),
	})
	if !model.ClusterID.IsNull() {
		listReq.Header().Set("Cluster-Id", model.ClusterID.ValueString())
	}

	listRes, err := r.client.shared.ListSettings(ctx, listReq)
	if err != nil {
		resp.Diagnostics.AddError("get settings", err.Error())
		return
	} else if len(listRes.Msg.Settings) == 0 {
		resp.Diagnostics.AddError("no settings found", "no settings found")
		return
	}

	coreToModel := newCoreToModelConverter()
	model = *coreToModel.Settings(listRes.Msg.GetSettings()[0])
	resp.Diagnostics.Append(coreToModel.diagnostics...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

func (r *SettingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var model SettingsModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}

	modelToCore := newModelToCoreConverter()
	updateReq := modelToCore.UpdateSettingsRequest(&model)
	resp.Diagnostics.Append(modelToCore.diagnostics...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateRes, err := r.client.shared.UpdateSettings(ctx, updateReq)
	if err != nil {
		resp.Diagnostics.AddError("set settings", err.Error())
		return
	}

	coreToModel := newCoreToModelConverter()
	model = *coreToModel.Settings(updateRes.Msg.GetSettings())
	resp.Diagnostics.Append(coreToModel.diagnostics...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

func (r *SettingsResource) Delete(ctx context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	resp.State.RemoveResource(ctx)
}

func (r *SettingsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
