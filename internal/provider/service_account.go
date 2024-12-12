package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
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
	_ resource.Resource                = &ServiceAccountResource{}
	_ resource.ResourceWithImportState = &ServiceAccountResource{}
)

func NewServiceAccountResource() resource.Resource {
	return &ServiceAccountResource{}
}

type ServiceAccountResource struct {
	client *client.Client
}

type ServiceAccountResourceModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	NamespaceID types.String `tfsdk:"namespace_id"`
	Description types.String `tfsdk:"description"`
	UserID      types.String `tfsdk:"user_id"`
	ExpiresAt   types.String `tfsdk:"expires_at"`
}

func (r *ServiceAccountResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_service_account"
}

func (r *ServiceAccountResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Service Account resource for Pomerium.",

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
				Required:    true,
			},
			"namespace_id": schema.StringAttribute{
				Description: "ID of the namespace the service account belongs to.",
				Required:    true,
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
				Description: "Timestamp when the service account expires.",
				Computed:    true,
			},
		},
	}
}

func (r *ServiceAccountResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	c, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Provider Data Type",
			fmt.Sprintf("Expected *client.Client, got: %T.", req.ProviderData),
		)
		return
	}

	r.client = c
}

func (r *ServiceAccountResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ServiceAccountResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	pbServiceAccount, diags := ConvertServiceAccountToPB(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	respServiceAccount, err := r.client.ServiceAccountService.AddPomeriumServiceAccount(ctx, &pb.AddPomeriumServiceAccountRequest{
		ServiceAccount: pbServiceAccount,
	})
	if err != nil {
		resp.Diagnostics.AddError("Error creating service account", err.Error())
		return
	}

	plan.ID = types.StringValue(respServiceAccount.ServiceAccount.Id)

	tflog.Trace(ctx, "Created a service account", map[string]interface{}{
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

	respServiceAccount, err := r.client.ServiceAccountService.GetPomeriumServiceAccount(ctx, &pb.GetPomeriumServiceAccountRequest{
		Id: state.ID.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("Error reading service account", err.Error())
		return
	}

	diags := ConvertServiceAccountFromPB(&state, respServiceAccount.ServiceAccount)
	resp.Diagnostics.Append(diags...)
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

	pbServiceAccount, diags := ConvertServiceAccountToPB(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.ServiceAccountService.SetPomeriumServiceAccount(ctx, &pb.SetPomeriumServiceAccountRequest{
		ServiceAccount: pbServiceAccount,
	})
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

	_, err := r.client.ServiceAccountService.DeletePomeriumServiceAccount(ctx, &pb.DeletePomeriumServiceAccountRequest{
		Id: state.ID.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("Error deleting service account", err.Error())
		return
	}

	resp.State.RemoveResource(ctx)
}

func (r *ServiceAccountResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func ConvertServiceAccountToPB(_ context.Context, src *ServiceAccountResourceModel) (*pb.PomeriumServiceAccount, diag.Diagnostics) {
	var diagnostics diag.Diagnostics

	namespaceID := src.NamespaceID.ValueString()
	pbServiceAccount := &pb.PomeriumServiceAccount{
		Id:          src.ID.ValueString(),
		UserId:      src.Name.ValueString(),
		NamespaceId: &namespaceID,
	}

	if !src.Description.IsNull() {
		desc := src.Description.ValueString()
		pbServiceAccount.Description = &desc
	}

	return pbServiceAccount, diagnostics
}

func ConvertServiceAccountFromPB(dst *ServiceAccountResourceModel, src *pb.PomeriumServiceAccount) diag.Diagnostics {
	var diagnostics diag.Diagnostics

	dst.ID = types.StringValue(src.Id)
	dst.Name = types.StringValue(src.UserId)
	if src.NamespaceId != nil {
		dst.NamespaceID = types.StringValue(*src.NamespaceId)
	} else {
		dst.NamespaceID = types.StringNull()
	}
	if src.Description != nil {
		dst.Description = types.StringValue(*src.Description)
	} else {
		dst.Description = types.StringNull()
	}
	dst.UserID = types.StringValue(src.UserId)
	if src.ExpiresAt != nil {
		dst.ExpiresAt = types.StringValue(src.ExpiresAt.AsTime().Format(time.RFC3339))
	} else {
		dst.ExpiresAt = types.StringNull()
	}

	return diagnostics
}
