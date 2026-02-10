package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/enterprise-client-go/pb"
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
	var plan KeyPairResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createReq := ConvertKeyPairToCreatePB(&plan)
	respKeyPair, err := r.client.KeyChainService.CreateKeyPair(ctx, createReq)
	if err != nil {
		resp.Diagnostics.AddError("Error creating key pair", err.Error())
		return
	}

	plan.ID = types.StringValue(respKeyPair.KeyPair.Id)

	tflog.Trace(ctx, "Created a key pair", map[string]interface{}{
		"id": plan.ID.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *KeyPairResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state KeyPairResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	respKeyPair, err := r.client.KeyChainService.GetKeyPair(ctx, &pb.GetKeyPairRequest{
		Id: state.ID.ValueString(),
	})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error reading key pair", err.Error())
		return
	}

	state.ID = types.StringValue(respKeyPair.KeyPair.Id)
	state.NamespaceID = types.StringValue(respKeyPair.KeyPair.NamespaceId)
	state.Name = types.StringValue(respKeyPair.KeyPair.Name)
	state.Certificate = types.StringValue(string(respKeyPair.KeyPair.Certificate))

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *KeyPairResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan KeyPairResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateReq := ConvertKeyPairToUpdatePB(&plan)
	_, err := r.client.KeyChainService.UpdateKeyPair(ctx, updateReq)
	if err != nil {
		resp.Diagnostics.AddError("Error updating key pair", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *KeyPairResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state KeyPairResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.KeyChainService.DeleteKeyPair(ctx, &pb.DeleteKeyPairRequest{
		Id: state.ID.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("Error deleting key pair", err.Error())
		return
	}

	resp.State.RemoveResource(ctx)
}

func (r *KeyPairResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
