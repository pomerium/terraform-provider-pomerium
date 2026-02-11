package provider

import (
	"context"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/sdk-go/proto/pomerium"
)

var (
	_ resource.Resource                = &KeyPairResource{}
	_ resource.ResourceWithImportState = &KeyPairResource{}
)

type KeyPairResource struct {
	client *Client
}

// Update the model alias
type KeyPairResourceModel = KeyPairModel

func NewKeyPairResource() resource.Resource {
	return &KeyPairResource{}
}

func (r *KeyPairResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_key_pair"
}

func (r *KeyPairResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "KeyPairs managed by Pomerium.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Name of the key pair",
			},
			"namespace_id": schema.StringAttribute{
				Required:    true,
				Description: "ID of the namespace this key pair belongs to",
			},
			"certificate": schema.StringAttribute{
				Required:    true,
				Description: "PEM encoded certificate",
			},
			"key": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "PEM encoded private key",
			},
		},
	}
}

func (r *KeyPairResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = ConfigureClient(req, resp)
}

func (r *KeyPairResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var model KeyPairResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}

	modelToCore := newModelToCoreConverter(&resp.Diagnostics)
	createReq := modelToCore.CreateKeyPairRequest(&model)
	if resp.Diagnostics.HasError() {
		return
	}

	createRes, err := r.client.shared.CreateKeyPair(ctx, createReq)
	if err != nil {
		resp.Diagnostics.AddError("Error creating key pair", err.Error())
		return
	}

	coreToModel := newCoreToModelConverter(&resp.Diagnostics)
	model = *coreToModel.KeyPair(createRes.Msg.GetKeyPair())
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Trace(ctx, "Created a key pair", map[string]interface{}{
		"id": model.ID.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

func (r *KeyPairResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var model KeyPairResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}

	getRes, err := r.client.shared.GetKeyPair(ctx, connect.NewRequest(&pomerium.GetKeyPairRequest{
		Id: model.ID.ValueString(),
	}))
	if err != nil {
		if status.Code(err) == codes.NotFound {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error reading key pair", err.Error())
		return
	}

	coreToModel := newCoreToModelConverter(&resp.Diagnostics)
	model = *coreToModel.KeyPair(getRes.Msg.GetKeyPair())
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

func (r *KeyPairResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var model KeyPairResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}

	modelToCore := newModelToCoreConverter(&resp.Diagnostics)
	updateReq := modelToCore.UpdateKeyPairRequest(&model)
	if resp.Diagnostics.HasError() {
		return
	}

	updateRes, err := r.client.shared.UpdateKeyPair(ctx, updateReq)
	if err != nil {
		resp.Diagnostics.AddError("Error updating key pair", err.Error())
		return
	}

	coreToModel := newCoreToModelConverter(&resp.Diagnostics)
	model = *coreToModel.KeyPair(updateRes.Msg.GetKeyPair())
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

func (r *KeyPairResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var model KeyPairResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.shared.DeleteKeyPair(ctx, connect.NewRequest(&pomerium.DeleteKeyPairRequest{
		Id: model.ID.ValueString(),
	}))
	if err != nil {
		resp.Diagnostics.AddError("Error deleting key pair", err.Error())
		return
	}

	resp.State.RemoveResource(ctx)
}

func (r *KeyPairResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
