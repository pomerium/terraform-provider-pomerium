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

type ClusterResourceModel = ClusterModel

// A ClusterResource manages clusters.
type ClusterResource struct {
	client *Client
}

// NewClusterResource creates a new clusters resource.
func NewClusterResource() resource.Resource {
	return &ClusterResource{}
}

func (r *ClusterResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cluster"
}

func (r *ClusterResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Cluster for Pomerium.",
		Attributes: map[string]schema.Attribute{
			"parent_namespace_id": schema.StringAttribute{
				Description: "Parent namespace of the cluster.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"namespace_id": schema.StringAttribute{
				Computed:    true,
				Description: "Namespace ID for the cluster.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Unique identifier for the cluster.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "Name for the cluster.",
				Required:    true,
			},
			"databroker_service_url": schema.StringAttribute{
				Description: "Databroker service url for the cluster.",
				Required:    true,
			},
			"shared_secret_b64": schema.StringAttribute{
				Description: "Shared secret for the cluster as base64.",
				Required:    true,
				Sensitive:   true,
			},
			"insecure_skip_verify": schema.BoolAttribute{
				Description: "Skip verification of TLS certificates for the cluster.",
				Optional:    true,
			},
			"override_certificate_name": schema.StringAttribute{
				Description: "Override the certificate name for TLS verification for the cluster.",
				Optional:    true,
			},
			"certificate_authority_b64": schema.StringAttribute{
				Description: "Certificate authority for the cluster as base64.",
				Optional:    true,
			},
			"certificate_authority_file": schema.StringAttribute{
				Description: "Certificate authority file for the cluster",
				Optional:    true,
			},
		},
	}
}

func (r *ClusterResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = ConfigureClient(req, resp)
}

func (r *ClusterResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ClusterResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.client.ByServerType(
		func(_ sdk.CoreClient) {
			resp.Diagnostics.AddError("unsupported server type: core", "unsupported server type: core")
		},
		func(client *client.Client) {
			pbCluster := NewModelToEnterpriseConverter(&resp.Diagnostics).Cluster(plan)
			if resp.Diagnostics.HasError() {
				return
			}

			addReq := &pb.AddClusterRequest{
				ParentNamespaceId: plan.ParentNamespaceID.ValueString(),
				Cluster:           pbCluster,
			}
			addRes, err := client.ClustersService.AddCluster(ctx, addReq)
			if err != nil {
				resp.Diagnostics.AddError("Error creating cluster", err.Error())
				return
			}

			plan.NamespaceID = types.StringValue(addRes.Namespace.Id)
			plan.ParentNamespaceID = types.StringValue(addRes.Namespace.ParentId)
			plan.ID = types.StringValue(addRes.Cluster.Id)
		},
		func(_ sdk.ZeroClient) {
			resp.Diagnostics.AddError("unsupported server type: zero", "unsupported server type: zero")
		})...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Trace(ctx, "Created a cluster", map[string]any{
		"id":   plan.ID.ValueString(),
		"name": plan.Name.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ClusterResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ClusterResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.client.ByServerType(
		func(_ sdk.CoreClient) {
			resp.Diagnostics.AddError("unsupported server type: core", "unsupported server type: core")
		},
		func(client *client.Client) {
			getReq := &pb.GetClusterRequest{
				Id: state.ID.ValueString(),
			}
			getRes, err := client.ClustersService.GetCluster(ctx, getReq)
			if err != nil {
				if status.Code(err) == codes.NotFound {
					resp.State.RemoveResource(ctx)
					return
				}
				resp.Diagnostics.AddError("Error reading cluster", err.Error())
				return
			}

			state = NewEnterpriseToModelConverter(&resp.Diagnostics).Cluster(getRes.GetCluster(), getRes.GetNamespace())
		},
		func(_ sdk.ZeroClient) {
			resp.Diagnostics.AddError("unsupported server type: zero", "unsupported server type: zero")
		})...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ClusterResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan ClusterResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.client.ByServerType(
		func(_ sdk.CoreClient) {
			resp.Diagnostics.AddError("unsupported server type: core", "unsupported server type: core")
		},
		func(client *client.Client) {
			pbCluster := NewModelToEnterpriseConverter(&resp.Diagnostics).Cluster(plan)
			if resp.Diagnostics.HasError() {
				return
			}

			updateReq := &pb.UpdateClusterRequest{
				Cluster: pbCluster,
			}
			updateRes, err := client.ClustersService.UpdateCluster(ctx, updateReq)
			if err != nil {
				resp.Diagnostics.AddError("Error updating cluster", err.Error())
				return
			}

			plan = NewEnterpriseToModelConverter(&resp.Diagnostics).Cluster(updateRes.GetCluster(), updateRes.GetNamespace())
		},
		func(_ sdk.ZeroClient) {
			resp.Diagnostics.AddError("unsupported server type: zero", "unsupported server type: zero")
		})...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ClusterResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ClusterResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.client.ByServerType(
		func(_ sdk.CoreClient) {
			resp.Diagnostics.AddError("unsupported server type: core", "unsupported server type: core")
		},
		func(client *client.Client) {
			deleteReq := &pb.DeleteClusterRequest{
				Id: state.ID.ValueString(),
			}
			_, err := client.ClustersService.DeleteCluster(ctx, deleteReq)
			if err != nil {
				resp.Diagnostics.AddError("Error deleting cluster", err.Error())
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
