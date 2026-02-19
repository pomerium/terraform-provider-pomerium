package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	client "github.com/pomerium/enterprise-client-go"
	"github.com/pomerium/enterprise-client-go/pb"
	"github.com/pomerium/sdk-go"
)

var _ datasource.DataSource = &NamespaceDataSource{}

func NewNamespaceDataSource() datasource.DataSource {
	return &NamespaceDataSource{}
}

type NamespaceDataSource struct {
	client *Client
}

func (d *NamespaceDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_namespace"
}

func (d *NamespaceDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Namespace for Pomerium.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Required:    true,
				Description: "Unique identifier for the namespace.",
			},
			"name": schema.StringAttribute{
				Computed:    true,
				Description: "Name of the namespace.",
			},
			"parent_id": schema.StringAttribute{
				Computed:    true,
				Description: "ID of the parent namespace.",
			},
			"cluster_id": schema.StringAttribute{
				Computed:    true,
				Optional:    true,
				Description: "ID of the cluster (optional).",
			},
		},
	}
}

func (d *NamespaceDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = ConfigureClient(req, resp)
}

func (d *NamespaceDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data NamespaceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(d.client.ByServerType(ctx,
		func() {
			data.ClusterID = types.StringNull()
			data.Name = types.StringNull()
			data.ParentID = types.StringNull()
		},
		func(client *client.Client) {
			getReq := &pb.GetNamespaceRequest{
				Id: data.ID.ValueString(),
			}
			getRes, err := client.NamespaceService.GetNamespace(ctx, getReq)
			if err != nil {
				resp.Diagnostics.AddError("Error reading namespace", err.Error())
				return
			}

			data = NewEnterpriseToModelConverter(&resp.Diagnostics).Namespace(getRes.GetNamespace())
		},
		func(_ sdk.ZeroClient) {
			resp.Diagnostics.AddError("unsupported server type: zero", "unsupported server type: zero")
		})...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
