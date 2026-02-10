package provider

import (
	"context"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/sdk-go/proto/pomerium"
)

var (
	_ resource.Resource                = &ServiceAccountResource{}
	_ resource.ResourceWithImportState = &ServiceAccountResource{}
)

func NewServiceAccountResource() resource.Resource {
	return &ServiceAccountResource{}
}

type ServiceAccountResource struct {
	client *Client
}

type ServiceAccountResourceModel struct {
	ServiceAccountModel
	JWT types.String `tfsdk:"jwt"`
}

func (r *ServiceAccountResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_service_account"
}

func (r *ServiceAccountResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Service Account for Pomerium.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Unique identifier for the service account.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "Name of the service account.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"namespace_id": schema.StringAttribute{
				Description: "ID of the namespace the service account belongs to.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"description": schema.StringAttribute{
				Description: "Description of the service account.",
				Optional:    true,
			},
			"user_id": schema.StringAttribute{
				Description: "User ID associated with the service account.",
				Computed:    true,
			},
			"expires_at": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp when the service account expires.",
			},
			"jwt": schema.StringAttribute{
				Computed:    true,
				Sensitive:   true,
				Description: "The Service Account JWT used for authentication. This is only populated when creating a new service account.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *ServiceAccountResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = ConfigureClient(req, resp)
}

func (r *ServiceAccountResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var state ServiceAccountResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	modelToCore := newModelToCoreConverter()
	coreServiceAccount := modelToCore.ServiceAccount(&state)
	resp.Diagnostics.Append(modelToCore.diagnostics...)
	if resp.Diagnostics.HasError() {
		return
	}

	respServiceAccount, err := r.client.shared.CreateServiceAccount(ctx, connect.NewRequest(&pomerium.CreateServiceAccountRequest{
		ServiceAccount: coreServiceAccount,
	}))
	if err != nil {
		resp.Diagnostics.AddError("Error creating service account", err.Error())
		return
	}

	coreToModel := newCoreToModelConverter()
	state.ServiceAccountModel = *coreToModel.ServiceAccount(respServiceAccount.Msg.ServiceAccount)
	resp.Diagnostics.Append(coreToModel.diagnostics...)
	if resp.Diagnostics.HasError() {
		return
	}

	state.JWT = types.StringValue(respServiceAccount.Msg.Jwt)

	tflog.Trace(ctx, "Created a service account", map[string]interface{}{
		"id":   state.ID.ValueString(),
		"name": state.Name.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ServiceAccountResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ServiceAccountResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	respServiceAccount, err := r.client.shared.GetServiceAccount(ctx, connect.NewRequest(&pomerium.GetServiceAccountRequest{
		Id: state.ID.ValueString(),
	}))
	if err != nil {
		if status.Code(err) == codes.NotFound {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error reading service account", err.Error())
		return
	}

	coreToModel := newCoreToModelConverter()
	state.ServiceAccountModel = *coreToModel.ServiceAccount(respServiceAccount.Msg.ServiceAccount)
	resp.Diagnostics.Append(coreToModel.diagnostics...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ServiceAccountResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan ServiceAccountResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	modelToCore := newModelToCoreConverter()
	dst := modelToCore.ServiceAccount(&plan)
	resp.Diagnostics.Append(modelToCore.diagnostics...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.shared.UpdateServiceAccount(ctx, connect.NewRequest(&pomerium.UpdateServiceAccountRequest{
		ServiceAccount: dst,
	}))
	if err != nil {
		resp.Diagnostics.AddError("Error updating service account", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ServiceAccountResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ServiceAccountResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.shared.DeleteServiceAccount(ctx, connect.NewRequest(&pomerium.DeleteServiceAccountRequest{
		Id: state.ID.ValueString(),
	}))
	if err != nil {
		resp.Diagnostics.AddError("Error deleting service account", err.Error())
		return
	}

	resp.State.RemoveResource(ctx)
}

func (r *ServiceAccountResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
