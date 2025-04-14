package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"

	client "github.com/pomerium/enterprise-client-go"
	"github.com/pomerium/enterprise-client-go/pb"
)

func getClusterDataSourceAttributes(idRequired bool) map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"parent_namespace_id": schema.StringAttribute{
			Computed:    true,
			Description: "Parent namespace of the cluster.",
		},
		"id": schema.StringAttribute{
			Required:    idRequired,
			Computed:    !idRequired,
			Description: "Unique identifier for the cluster.",
		},
		"name": schema.StringAttribute{
			Computed:    true,
			Description: "Name of the cluster.",
		},
		"databroker_service_url": schema.StringAttribute{
			Computed:    true,
			Description: "Databroker service URL of the cluster.",
		},
		"shared_secret_b64": schema.StringAttribute{
			Computed:    true,
			Description: "Shared secret of the cluster.",
			Sensitive:   true,
		},
		"insecure_skip_verify": schema.BoolAttribute{
			Computed:    true,
			Description: "Skip verification of TLS certificates for the cluster.",
		},
		"override_certificate_name": schema.StringAttribute{
			Computed:    true,
			Description: "Override the certificate name for TLS verification for the cluster.",
		},
		"certificate_authority_b64": schema.StringAttribute{
			Computed:    true,
			Description: "Certificate authority for the cluster as base64.",
		},
		"certificate_authority_file": schema.StringAttribute{
			Computed:    true,
			Description: "Certificate authority file for the cluster",
		},
	}
}

type ClusterDataSourceModel = ClusterModel

// A ClusterDataSource retrieves data about a cluster.
type ClusterDataSource struct {
	client *client.Client
}

// NewClusterDataSource creates a new cluster data source.
func NewClusterDataSource() datasource.DataSource {
	return &ClusterDataSource{}
}

func (*ClusterDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cluster"
}

func (*ClusterDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Cluster data source",
		Attributes:          getClusterDataSourceAttributes(true),
	}
}

func (d *ClusterDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *client.Client, got: %T.", req.ProviderData),
		)
		return
	}

	d.client = client
}

func (d *ClusterDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data ClusterDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	clusterResp, err := d.client.ClustersService.GetCluster(ctx, &pb.GetClusterRequest{
		Id: data.ID.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("Error reading cluster", err.Error())
		return
	}

	diags := ConvertClusterFromPB(&data, clusterResp.Cluster, clusterResp.Namespace)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
