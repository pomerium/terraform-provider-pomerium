package provider

import (
	"context"
	"fmt"

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

var (
	_ resource.Resource                = &KeyChainResource{}
	_ resource.ResourceWithImportState = &KeyChainResource{}
)

type KeyChainResource struct {
	client *client.Client
}

// Update the model alias
type KeyChainResourceModel = KeyPairModel

func NewKeyChainResource() resource.Resource {
	return &KeyChainResource{}
}

func (r *KeyChainResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_key_pair"
}

func (r *KeyChainResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
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

func (r *KeyChainResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *client.Client, got: %T", req.ProviderData),
		)
		return
	}

	r.client = client
}

func (r *KeyChainResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan KeyChainResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	keyPairReq := &pb.CreateKeyPairRequest{
		NamespaceId: plan.NamespaceID.ValueString(),
		Name:        plan.Name.ValueString(),
		Format:      pb.Format_PEM,
		Certificate: []byte(plan.Certificate.ValueString()),
	}

	if !plan.Key.IsNull() {
		keyData := []byte(plan.Key.ValueString())
		keyPairReq.Key = keyData
	}

	respKeyPair, err := r.client.KeyChainService.CreateKeyPair(ctx, keyPairReq)
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

func (r *KeyChainResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state KeyChainResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	respKeyPair, err := r.client.KeyChainService.GetKeyPair(ctx, &pb.GetKeyPairRequest{
		Id: state.ID.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("Error reading key pair", err.Error())
		return
	}

	state.ID = types.StringValue(respKeyPair.KeyPair.Id)
	state.NamespaceID = types.StringValue(respKeyPair.KeyPair.NamespaceId)
	state.Name = types.StringValue(respKeyPair.KeyPair.Name)
	state.Certificate = types.StringValue(string(respKeyPair.KeyPair.Certificate))

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *KeyChainResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan KeyChainResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	fmt := pb.Format_PEM
	updateReq := &pb.UpdateKeyPairRequest{
		Id:          plan.ID.ValueString(),
		Name:        plan.Name.ValueStringPointer(),
		Format:      &fmt,
		Certificate: []byte(plan.Certificate.ValueString()),
	}

	if !plan.Key.IsNull() {
		updateReq.Key = []byte(plan.Key.ValueString())
	}

	_, err := r.client.KeyChainService.UpdateKeyPair(ctx, updateReq)
	if err != nil {
		resp.Diagnostics.AddError("Error updating key pair", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *KeyChainResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state KeyChainResourceModel

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

func (r *KeyChainResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
