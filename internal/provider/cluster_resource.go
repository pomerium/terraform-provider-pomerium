package provider

import (
	"context"
	"fmt"

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

type ClusterResourceModel = ClusterModel

// A ClusterResource manages clusters.
type ClusterResource struct {
	client *client.Client
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

func (r *ClusterResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ClusterResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	c := newModelToConsoleConverter()
	pbCluster := c.Cluster(&plan)
	resp.Diagnostics.Append(c.diagnostics...)
	if resp.Diagnostics.HasError() {
		return
	}

	respCluster, err := r.client.ClustersService.AddCluster(ctx, &pb.AddClusterRequest{
		ParentNamespaceId: plan.ParentNamespaceID.ValueString(),
		Cluster:           pbCluster,
	})
	if err != nil {
		resp.Diagnostics.AddError("Error creating cluster", err.Error())
		return
	}

	plan.NamespaceID = types.StringValue(respCluster.Namespace.Id)
	plan.ParentNamespaceID = types.StringValue(respCluster.Namespace.ParentId)
	plan.ID = types.StringValue(respCluster.Cluster.Id)

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

	respCluster, err := r.client.ClustersService.GetCluster(ctx, &pb.GetClusterRequest{
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

	c := newConsoleToModelConverter()
	state = *c.Cluster(respCluster.Cluster, respCluster.Namespace)
	resp.Diagnostics.Append(c.diagnostics...)
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

	modelToConsole := newModelToConsoleConverter()
	pbCluster := modelToConsole.Cluster(&plan)
	resp.Diagnostics.Append(modelToConsole.diagnostics...)
	if resp.Diagnostics.HasError() {
		return
	}

	respCluster, err := r.client.ClustersService.UpdateCluster(ctx, &pb.UpdateClusterRequest{
		Cluster: pbCluster,
	})
	if err != nil {
		resp.Diagnostics.AddError("Error updating cluster", err.Error())
		return
	}

	consoleToModel := newConsoleToModelConverter()
	plan = *consoleToModel.Cluster(respCluster.Cluster, respCluster.Namespace)
	resp.Diagnostics.Append(consoleToModel.diagnostics...)
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

	_, err := r.client.ClustersService.DeleteCluster(ctx, &pb.DeleteClusterRequest{
		Id: state.ID.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("Error deleting cluster", err.Error())
		return
	}

	resp.State.RemoveResource(ctx)
}
