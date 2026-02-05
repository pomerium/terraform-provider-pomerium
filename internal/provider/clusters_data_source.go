package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"

	"github.com/pomerium/enterprise-client-go/pb"
)

type ClustersDataSourceModel struct {
	Clusters []ClusterModel `tfsdk:"clusters"`
}

// A ClustersDataSource retrieves data about clusters.
type ClustersDataSource struct {
	client *Client
}

// NewClustersDataSource creates a new clusters data source.
func NewClustersDataSource() datasource.DataSource {
	return &ClustersDataSource{}
}

func (*ClustersDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_clusters"
}

func (*ClustersDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Clusters data source",
		Attributes: map[string]schema.Attribute{
			"clusters": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: getClusterDataSourceAttributes(false),
				},
			},
		},
	}
}

func (d *ClustersDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *Client, got: %T.", req.ProviderData),
		)
		return
	}

	d.client = client
}

func (d *ClustersDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data ClustersDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	clustersResp, err := d.client.ListClusters(ctx, &pb.ListClustersRequest{})
	if err != nil {
		resp.Diagnostics.AddError("Error reading clusters", err.Error())
		return
	}

	clusters := make([]ClusterModel, 0, len(clustersResp.Clusters))
	for _, cluster := range clustersResp.Clusters {
		c := newConsoleToModelConverter()
		clusterModel := c.Cluster(cluster, nil)
		if c.diagnostics.HasError() {
			resp.Diagnostics.Append(c.diagnostics...)
			return
		}
		clusters = append(clusters, *clusterModel)
	}

	data.Clusters = clusters
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
