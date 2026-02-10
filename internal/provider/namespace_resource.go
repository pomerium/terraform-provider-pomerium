package provider

import (
	"context"

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

// Ensure provider-defined types fully satisfy framework interfaces.
var (
	_ resource.Resource                = &NamespaceResource{}
	_ resource.ResourceWithImportState = &NamespaceResource{}
)

// NewNamespaceResource creates a new NamespaceResource.
func NewNamespaceResource() resource.Resource {
	return &NamespaceResource{}
}

// NamespaceResource defines the resource implementation.
type NamespaceResource struct {
	client *Client
}

// NamespaceResourceModel describes the resource data model.
type NamespaceResourceModel = NamespaceModel

func (r *NamespaceResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_namespace"
}

func (r *NamespaceResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Namespace for Pomerium.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Unique identifier for the namespace.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "Name of the namespace.",
				Required:    true,
			},
			"parent_id": schema.StringAttribute{
				Description: "ID of the parent namespace (optional).",
				Optional:    true,
			},
			"cluster_id": schema.StringAttribute{
				Description: "ID of the cluster (optional).",
				Computed:    true,
			},
		},
	}
}

func (r *NamespaceResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = ConfigureClient(req, resp)
}

func (r *NamespaceResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan NamespaceResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	pbNamespace, diags := ConvertNamespaceToPB(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	respNamespace, err := r.client.NamespaceService.SetNamespace(ctx, &pb.SetNamespaceRequest{
		Namespace: pbNamespace,
	})
	if err != nil {
		resp.Diagnostics.AddError("Error creating namespace", err.Error())
		return
	}

	plan.ID = types.StringValue(respNamespace.Namespace.Id)
	plan.ClusterID = types.StringPointerValue(respNamespace.Namespace.ClusterId)

	tflog.Trace(ctx, "Created a namespace", map[string]any{
		"id":   plan.ID.ValueString(),
		"name": plan.Name.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *NamespaceResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state NamespaceResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	respNamespace, err := r.client.NamespaceService.GetNamespace(ctx, &pb.GetNamespaceRequest{
		Id: state.ID.ValueString(),
	})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error reading namespace", err.Error())
		return
	}

	diags := ConvertNamespaceFromPB(&state, respNamespace.Namespace)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *NamespaceResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan NamespaceResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	pbNamespace, diags := ConvertNamespaceToPB(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.NamespaceService.SetNamespace(ctx, &pb.SetNamespaceRequest{
		Namespace: pbNamespace,
	})
	if err != nil {
		resp.Diagnostics.AddError("Error updating namespace", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *NamespaceResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state NamespaceResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.NamespaceService.DeleteNamespace(ctx, &pb.DeleteNamespaceRequest{
		Id: state.ID.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("Error deleting namespace", err.Error())
		return
	}

	resp.State.RemoveResource(ctx)
}

func (r *NamespaceResource) ImportState(_ context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	ImportStatePassthroughID(req, resp)
}
