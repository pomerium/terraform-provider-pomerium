package provider

import (
	"context"
	_ "embed"

	"github.com/google/uuid"
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

	client "github.com/pomerium/enterprise-client-go"
	"github.com/pomerium/enterprise-client-go/pb"
	"github.com/pomerium/sdk-go"
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

	resp.Diagnostics.Append(r.client.ByServerType(
		func(client sdk.CoreClient) {
			if plan.ID.IsNull() || plan.ID.IsUnknown() {
				plan.ID = types.StringValue(uuid.NewString())
			}

			namespacePermission := NewModelToCoreConverter(&resp.Diagnostics).NamespacePermission(plan)
			if resp.Diagnostics.HasError() {
				return
			}

			err := databrokerPut(ctx, client, RecordTypeNamespacePermission, plan.ID.ValueString(), namespacePermission)
			if err != nil {
				resp.Diagnostics.AddError("error creating namespace permission", err.Error())
				return
			}

			plan = NewCoreToModelConverter(&resp.Diagnostics).NamespacePermission(namespacePermission)
		},
		func(client *client.Client) {
			pbNamespacePermission := NewModelToEnterpriseConverter(&resp.Diagnostics).NamespacePermission(plan)
			if resp.Diagnostics.HasError() {
				return
			}

			setReq := &pb.SetNamespacePermissionRequest{
				NamespacePermission: pbNamespacePermission,
			}
			setRes, err := client.NamespacePermissionService.SetNamespacePermission(ctx, setReq)
			if err != nil {
				resp.Diagnostics.AddError("failed to create namespace permission", err.Error())
				return
			}

			plan.ID = types.StringValue(setRes.NamespacePermission.Id)
		},
		func(_ sdk.ZeroClient) {
			resp.Diagnostics.AddError("unsupported server type: zero", "unsupported server type: zero")
		})...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Trace(ctx, "Created a namespace permission", map[string]any{
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

	resp.Diagnostics.Append(r.client.ByServerType(
		func(client sdk.CoreClient) {
			data, err := databrokerGet(ctx, client, RecordTypeNamespacePermission, state.ID.ValueString())
			if status.Code(err) == codes.NotFound {
				resp.State.RemoveResource(ctx)
				return
			} else if err != nil {
				resp.Diagnostics.AddError("error reading namespace permission", err.Error())
				return
			}

			state = NewCoreToModelConverter(&resp.Diagnostics).NamespacePermission(data)
		},
		func(client *client.Client) {
			getReq := &pb.GetNamespacePermissionRequest{
				Id: state.ID.ValueString(),
			}
			getRes, err := client.NamespacePermissionService.GetNamespacePermission(ctx, getReq)
			if err != nil {
				if status.Code(err) == codes.NotFound {
					resp.State.RemoveResource(ctx)
					return
				}
				resp.Diagnostics.AddError("failed to read namespace permission", err.Error())
				return
			}

			state = NewEnterpriseToModelConverter(&resp.Diagnostics).NamespacePermission(getRes.GetNamespacePermission())
		},
		func(_ sdk.ZeroClient) {
			resp.Diagnostics.AddError("unsupported server type: zero", "unsupported server type: zero")
		})...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *NamespacePermissionResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan NamespacePermissionModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.client.ByServerType(
		func(client sdk.CoreClient) {
			namespacePermission := NewModelToCoreConverter(&resp.Diagnostics).NamespacePermission(plan)
			if resp.Diagnostics.HasError() {
				return
			}

			err := databrokerPut(ctx, client, RecordTypeNamespacePermission, plan.ID.ValueString(), namespacePermission)
			if err != nil {
				resp.Diagnostics.AddError("error updating namespace permission", err.Error())
				return
			}

			plan = NewCoreToModelConverter(&resp.Diagnostics).NamespacePermission(namespacePermission)
		},
		func(client *client.Client) {
			pbNamespacePermission := NewModelToEnterpriseConverter(&resp.Diagnostics).NamespacePermission(plan)
			if resp.Diagnostics.HasError() {
				return
			}

			setReq := &pb.SetNamespacePermissionRequest{
				NamespacePermission: pbNamespacePermission,
			}
			_, err := client.NamespacePermissionService.SetNamespacePermission(ctx, setReq)
			if err != nil {
				resp.Diagnostics.AddError("failed to update namespace permission", err.Error())
			}
		},
		func(_ sdk.ZeroClient) {
			resp.Diagnostics.AddError("unsupported server type: zero", "unsupported server type: zero")
		})...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *NamespacePermissionResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var plan NamespacePermissionModel

	resp.Diagnostics.Append(req.State.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.client.ByServerType(
		func(client sdk.CoreClient) {
			err := databrokerDelete(ctx, client, RecordTypeNamespace, plan.ID.ValueString())
			if err != nil {
				resp.Diagnostics.AddError("error deleting namespace permission", err.Error())
				return
			}
		},
		func(client *client.Client) {
			deleteReq := &pb.DeleteNamespacePermissionRequest{
				Id: plan.ID.ValueString(),
			}
			_, err := client.NamespacePermissionService.DeleteNamespacePermission(ctx, deleteReq)
			if err != nil {
				resp.Diagnostics.AddError("failed to delete namespace permission", err.Error())
			}
		},
		func(_ sdk.ZeroClient) {
			resp.Diagnostics.AddError("unsupported server type: zero", "unsupported server type: zero")
		})...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.State.RemoveResource(ctx)
}

func (r *NamespacePermissionResource) ImportState(_ context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	ImportStatePassthroughID(req, resp)
}
