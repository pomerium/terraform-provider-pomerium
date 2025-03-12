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
)

// NewClusterResource creates a new Resource for clusters.
func NewClusterResource() resource.Resource {
	return &ClusterResource{}
}

// ClusterResource defines the resource implementation of a cluster.
type ClusterResource struct {
	client *client.Client
}

// ClusterResourceModel describes the resource data model.
type ClusterResourceModel = ClusterModel

func (r *ClusterResource) Configure(
	_ context.Context,
	req resource.ConfigureRequest,
	resp *resource.ConfigureResponse,
) {
	r.client = ConfigureClient(req, resp)
}

func (r *ClusterResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var state ClusterResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	pbCluster, diags := ConvertClusterToPB(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	respAddCluster, err := r.client.ClusterService.AddCluster(ctx, &pb.AddClusterRequest{
		ParentNamespaceId: state.ParentNamespaceID.ValueString(),
		Cluster:           pbCluster,
	})
	if err != nil {
		resp.Diagnostics.AddError("Error creating cluster", err.Error())
		return
	}

	state.ID = types.StringValue(respAddCluster.Cluster.Id)
	state.NamespaceID = types.StringValue(respAddCluster.Namespace.Id)

	tflog.Trace(ctx, "Created a cluster", map[string]any{
		"id":   state.ID.ValueString(),
		"name": state.Name.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ClusterResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state ClusterResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.ClusterService.DeleteCluster(ctx, &pb.DeleteClusterRequest{
		Id: state.ID.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("Error deleting cluster", err.Error())
		return
	}

	resp.State.RemoveResource(ctx)
}

func (r *ClusterResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cluster"
}

func (r *ClusterResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state ClusterResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	respCluster, err := r.client.ClusterService.GetCluster(ctx, &pb.GetClusterRequest{
		Id: state.ID.ValueString(),
	})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error reading cluster", err.Error())
		return
	}

	diags := ConvertClusterFromPB(&state, respCluster.Cluster)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	state.NamespaceID = types.StringValue(respCluster.Namespace.Id)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ClusterResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Cluster for Pomerium.",
		Attributes: map[string]schema.Attribute{
			"parent_namespace_id": schema.StringAttribute{
				Description: "Parent namespace for the cluster.",
				Required:    true,
			},
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Unique identifier for the cluster.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "Name of the cluster.",
				Required:    true,
			},
			"databroker_service_url": schema.StringAttribute{
				Description: "Databroker Service URL of the cluster.",
				Required:    true,
			},
			"shared_secret_b64": schema.StringAttribute{
				Description: "Shared Secret of the cluster.",
				Required:    true,
			},
			"insecure_skip_verify": schema.BoolAttribute{
				Description: "Skips TLS verification on the cluster",
				Optional:    true,
			},
			"override_certificate_name": schema.StringAttribute{
				Description: "Override the certificate name of the cluster.",
				Optional:    true,
			},
			"certificate_authority": schema.StringAttribute{
				Description: "Certificate authority for the cluster connection.",
				Optional:    true,
			},
			"certificate_authority_file": schema.StringAttribute{
				Description: "Certificate authority file for the cluster connection.",
				Optional:    true,
			},

			"namespace_id": schema.StringAttribute{
				Computed:    true,
				Description: "Namespace id of the cluster.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *ClusterResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var state ClusterResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	pbCluster, diags := ConvertClusterToPB(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	respUpdateCluster, err := r.client.ClusterService.UpdateCluster(ctx, &pb.UpdateClusterRequest{
		Cluster: pbCluster,
	})
	if err != nil {
		resp.Diagnostics.AddError("Error updating cluster", err.Error())
		return
	}

	state.NamespaceID = types.StringValue(respUpdateCluster.Namespace.Id)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
