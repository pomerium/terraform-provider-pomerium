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

	client "github.com/pomerium/enterprise-client-go"
	"github.com/pomerium/enterprise-client-go/pb"
	"github.com/pomerium/sdk-go"
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

	resp.Diagnostics.Append(r.client.ByServerType(
		func(_ sdk.CoreClient) {
			resp.Diagnostics.AddError("unsupported server type: core", "unsupported server type: core")
		},
		func(client *client.Client) {
			pbNamespace := NewModelToEnterpriseConverter(&resp.Diagnostics).Namespace(plan)
			if resp.Diagnostics.HasError() {
				return
			}

			setReq := &pb.SetNamespaceRequest{
				Namespace: pbNamespace,
			}
			setRes, err := client.NamespaceService.SetNamespace(ctx, setReq)
			if err != nil {
				resp.Diagnostics.AddError("Error creating namespace", err.Error())
				return
			}

			plan.ID = types.StringValue(setRes.Namespace.Id)
			plan.ClusterID = types.StringPointerValue(setRes.Namespace.ClusterId)
		},
		func(_ sdk.ZeroClient) {
			resp.Diagnostics.AddError("unsupported server type: zero", "unsupported server type: zero")
		})...)
	if resp.Diagnostics.HasError() {
		return
	}

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

	resp.Diagnostics.Append(r.client.ByServerType(
		func(_ sdk.CoreClient) {
			resp.Diagnostics.AddError("unsupported server type: core", "unsupported server type: core")
		},
		func(client *client.Client) {
			getReq := &pb.GetNamespaceRequest{
				Id: state.ID.ValueString(),
			}
			getRes, err := client.NamespaceService.GetNamespace(ctx, getReq)
			if err != nil {
				if status.Code(err) == codes.NotFound {
					resp.State.RemoveResource(ctx)
					return
				}
				resp.Diagnostics.AddError("Error reading namespace", err.Error())
				return
			}

			state = NewEnterpriseToModelConverter(&resp.Diagnostics).Namespace(getRes.GetNamespace())
		},
		func(_ sdk.ZeroClient) {
			resp.Diagnostics.AddError("unsupported server type: zero", "unsupported server type: zero")
		})...)
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

	resp.Diagnostics.Append(r.client.ByServerType(
		func(_ sdk.CoreClient) {
			resp.Diagnostics.AddError("unsupported server type: core", "unsupported server type: core")
		},
		func(client *client.Client) {
			pbNamespace := NewModelToEnterpriseConverter(&resp.Diagnostics).Namespace(plan)
			if resp.Diagnostics.HasError() {
				return
			}

			setReq := &pb.SetNamespaceRequest{
				Namespace: pbNamespace,
			}
			_, err := client.NamespaceService.SetNamespace(ctx, setReq)
			if err != nil {
				resp.Diagnostics.AddError("Error updating namespace", err.Error())
				return
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

func (r *NamespaceResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state NamespaceResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.client.ByServerType(
		func(_ sdk.CoreClient) {
			resp.Diagnostics.AddError("unsupported server type: core", "unsupported server type: core")
		},
		func(client *client.Client) {
			deleteReq := &pb.DeleteNamespaceRequest{
				Id: state.ID.ValueString(),
			}
			_, err := client.NamespaceService.DeleteNamespace(ctx, deleteReq)
			if err != nil {
				resp.Diagnostics.AddError("Error deleting namespace", err.Error())
				return
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

func (r *NamespaceResource) ImportState(_ context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	ImportStatePassthroughID(req, resp)
}
