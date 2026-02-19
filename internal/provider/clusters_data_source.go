package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"

	client "github.com/pomerium/enterprise-client-go"
	"github.com/pomerium/enterprise-client-go/pb"
	"github.com/pomerium/sdk-go"
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
	d.client = ConfigureClient(req, resp)
}

func (d *ClustersDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data ClustersDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(d.client.ByServerType(ctx,
		func(_ sdk.CoreClient) {
			resp.Diagnostics.AddError("unsupported server type: core", "unsupported server type: core")
		},
		func(client *client.Client) {
			listReq := &pb.ListClustersRequest{}
			listRes, err := client.ClustersService.ListClusters(ctx, listReq)
			if err != nil {
				resp.Diagnostics.AddError("Error reading clusters", err.Error())
				return
			}

			clusters := make([]ClusterModel, 0, len(listRes.Clusters))
			for _, cluster := range listRes.Clusters {
				clusterModel := NewEnterpriseToModelConverter(&resp.Diagnostics).Cluster(cluster, nil)
				if resp.Diagnostics.HasError() {
					return
				}
				clusters = append(clusters, clusterModel)
			}

			data.Clusters = clusters
		},
		func(_ sdk.ZeroClient) {
			resp.Diagnostics.AddError("unsupported server type: zero", "unsupported server type: zero")
		})...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
