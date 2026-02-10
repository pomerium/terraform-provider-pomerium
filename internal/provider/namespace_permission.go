package provider

import (
	"context"
	_ "embed"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/enterprise-client-go/pb"
)

//go:embed help/namespace_permissions.md
var namespacePermissionMD string

func NewNamespacePermissionResource() resource.Resource {
	return &NamespacePermissionResource{}
}

type NamespacePermissionResource struct {
	client *Client
}

func (r *NamespacePermissionResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_namespace_permission"
}

func (r *NamespacePermissionResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: namespacePermissionMD,
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Unique identifier for the namespace permission.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"namespace_id": schema.StringAttribute{
				Description: "ID of the namespace.",
				Required:    true,
			},
			"role": schema.StringAttribute{
				Description: "Role of the permission.",
				Required:    true,
				Validators: []validator.String{
					stringvalidator.OneOf("viewer", "manager", "admin"),
				},
			},
			"subject_id": schema.StringAttribute{
				Description: "ID of the subject.",
				Required:    true,
			},
			"subject_type": schema.StringAttribute{
				Description: "Type of the subject.",
				Required:    true,
				Validators: []validator.String{
					stringvalidator.OneOf("group", "user"),
				},
			},
		},
	}
}

func (r *NamespacePermissionResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = ConfigureClient(req, resp)
}

func (r *NamespacePermissionResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan NamespacePermissionModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	pbNamespacePermission, diags := ConvertNamespacePermissionToPB(&plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	respNP, err := r.client.NamespacePermissionService.SetNamespacePermission(ctx, &pb.SetNamespacePermissionRequest{
		NamespacePermission: pbNamespacePermission,
	})
	if err != nil {
		resp.Diagnostics.AddError("failed to create namespace permission", err.Error())
		return
	}

	plan.ID = types.StringValue(respNP.NamespacePermission.Id)

	tflog.Trace(ctx, "Created a namespace permission", map[string]interface{}{
		"id":           plan.ID.ValueString(),
		"namespace_id": plan.NamespaceID.ValueString(),
		"role":         plan.Role.ValueString(),
		"subject_id":   plan.SubjectID.ValueString(),
		"subject_type": plan.SubjectType.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *NamespacePermissionResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state NamespacePermissionModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	respNP, err := r.client.NamespacePermissionService.GetNamespacePermission(ctx, &pb.GetNamespacePermissionRequest{
		Id: state.ID.ValueString(),
	})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("failed to read namespace permission", err.Error())
		return
	}

	diags := ConvertNamespacePermissionFromPB(&state, respNP.NamespacePermission)
	resp.Diagnostics.Append(diags...)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *NamespacePermissionResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan NamespacePermissionModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	pbNamespacePermission, diags := ConvertNamespacePermissionToPB(&plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.NamespacePermissionService.SetNamespacePermission(ctx, &pb.SetNamespacePermissionRequest{
		NamespacePermission: pbNamespacePermission,
	})
	if err != nil {
		resp.Diagnostics.AddError("failed to update namespace permission", err.Error())
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *NamespacePermissionResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var plan NamespacePermissionModel

	resp.Diagnostics.Append(req.State.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.NamespacePermissionService.DeleteNamespacePermission(ctx, &pb.DeleteNamespacePermissionRequest{
		Id: plan.ID.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("failed to delete namespace permission", err.Error())
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *NamespacePermissionResource) ImportState(_ context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	ImportStatePassthroughID(req, resp)
}
