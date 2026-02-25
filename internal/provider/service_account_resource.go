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

	client "github.com/pomerium/enterprise-client-go"
	"github.com/pomerium/enterprise-client-go/pb"
	"github.com/pomerium/sdk-go"
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
				Optional:    true,
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
	var plan ServiceAccountResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.client.ConsolidatedOrLegacy(
		func(client sdk.Client) {
			apiServiceAccount := NewModelToAPIConverter(&resp.Diagnostics).ServiceAccount(plan.ServiceAccountModel)
			if resp.Diagnostics.HasError() {
				return
			}

			createReq := connect.NewRequest(&pomerium.CreateServiceAccountRequest{
				ServiceAccount: apiServiceAccount,
			})
			createRes, err := client.CreateServiceAccount(ctx, createReq)
			if err != nil {
				resp.Diagnostics.AddError("Error creating service account", err.Error())
				return
			}

			plan.ServiceAccountModel = NewAPIToModelConverter(&resp.Diagnostics).ServiceAccount(createRes.Msg.ServiceAccount)
			plan.JWT = types.StringValue(createRes.Msg.Jwt)
		},
		func(client *client.Client) {
			pbServiceAccount := NewModelToEnterpriseConverter(&resp.Diagnostics).ServiceAccount(plan.ServiceAccountModel)
			if resp.Diagnostics.HasError() {
				return
			}

			addReq := &pb.AddPomeriumServiceAccountRequest{
				ServiceAccount: pbServiceAccount,
			}
			addRes, err := client.PomeriumServiceAccountService.AddPomeriumServiceAccount(ctx, addReq)
			if err != nil {
				resp.Diagnostics.AddError("Error creating service account", err.Error())
				return
			}

			plan.ServiceAccountModel = NewEnterpriseToModelConverter(&resp.Diagnostics).ServiceAccount(addRes.GetServiceAccount())
			if resp.Diagnostics.HasError() {
				return
			}

			plan.JWT = types.StringValue(addRes.JWT)
		})...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Trace(ctx, "Created a service account", map[string]any{
		"id":   plan.ID.ValueString(),
		"name": plan.Name.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ServiceAccountResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ServiceAccountResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.client.ConsolidatedOrLegacy(
		func(client sdk.Client) {
			getReq := connect.NewRequest(&pomerium.GetServiceAccountRequest{
				Id: state.ID.ValueString(),
			})
			getRes, err := client.GetServiceAccount(ctx, getReq)
			if connect.CodeOf(err) == connect.CodeNotFound {
				resp.State.RemoveResource(ctx)
				return
			} else if err != nil {
				resp.Diagnostics.AddError("Error getting service account", err.Error())
				return
			}

			state.ServiceAccountModel = NewAPIToModelConverter(&resp.Diagnostics).ServiceAccount(getRes.Msg.ServiceAccount)
		},
		func(client *client.Client) {
			getReq := &pb.GetPomeriumServiceAccountRequest{
				Id: state.ID.ValueString(),
			}
			getRes, err := client.PomeriumServiceAccountService.GetPomeriumServiceAccount(ctx, getReq)
			if err != nil {
				if status.Code(err) == codes.NotFound {
					resp.State.RemoveResource(ctx)
					return
				}
				resp.Diagnostics.AddError("Error reading service account", err.Error())
				return
			}

			state.ServiceAccountModel = NewEnterpriseToModelConverter(&resp.Diagnostics).ServiceAccount(getRes.GetServiceAccount())
		})...)
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

	resp.Diagnostics.Append(r.client.ConsolidatedOrLegacy(
		func(client sdk.Client) {
			apiServiceAccount := NewModelToAPIConverter(&resp.Diagnostics).ServiceAccount(plan.ServiceAccountModel)
			if resp.Diagnostics.HasError() {
				return
			}

			updateReq := connect.NewRequest(&pomerium.UpdateServiceAccountRequest{
				ServiceAccount: apiServiceAccount,
			})
			updateRes, err := client.UpdateServiceAccount(ctx, updateReq)
			if err != nil {
				resp.Diagnostics.AddError("Error updating service account", err.Error())
				return
			}

			plan.ServiceAccountModel = NewAPIToModelConverter(&resp.Diagnostics).ServiceAccount(updateRes.Msg.ServiceAccount)
		},
		func(client *client.Client) {
			pbServiceAccount := NewModelToEnterpriseConverter(&resp.Diagnostics).ServiceAccount(plan.ServiceAccountModel)
			if resp.Diagnostics.HasError() {
				return
			}

			setReq := &pb.SetPomeriumServiceAccountRequest{
				ServiceAccount: pbServiceAccount,
			}
			_, err := client.PomeriumServiceAccountService.SetPomeriumServiceAccount(ctx, setReq)
			if err != nil {
				resp.Diagnostics.AddError("Error updating service account", err.Error())
				return
			}
		})...)
	if resp.Diagnostics.HasError() {
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

	resp.Diagnostics.Append(r.client.ConsolidatedOrLegacy(
		func(client sdk.Client) {
			deleteReq := connect.NewRequest(&pomerium.DeleteServiceAccountRequest{
				Id: state.ID.ValueString(),
			})
			_, err := client.DeleteServiceAccount(ctx, deleteReq)
			if err != nil {
				resp.Diagnostics.AddError("Error deleting service account", err.Error())
				return
			}
		},
		func(client *client.Client) {
			deleteReq := &pb.DeletePomeriumServiceAccountRequest{
				Id: state.ID.ValueString(),
			}
			_, err := client.PomeriumServiceAccountService.DeletePomeriumServiceAccount(ctx, deleteReq)
			if err != nil {
				resp.Diagnostics.AddError("Error deleting service account", err.Error())
				return
			}
		})...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.State.RemoveResource(ctx)
}

func (r *ServiceAccountResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
