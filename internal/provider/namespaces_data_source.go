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

var GlobalNamespaceID = "9d8dbd2c-8cce-4e66-9c1f-c490b4a07243"

var _ datasource.DataSource = &NamespacesDataSource{}

func NewNamespacesDataSource() datasource.DataSource {
	return &NamespacesDataSource{}
}

type NamespacesDataSource struct {
	client *Client
}

type NamespacesDataSourceModel struct {
	Namespaces []NamespaceModel `tfsdk:"namespaces"`
}

func (d *NamespacesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_namespaces"
}

func (d *NamespacesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "List all namespaces",

		Attributes: map[string]schema.Attribute{
			"namespaces": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
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
				},
			},
		},
	}
}

func (d *NamespacesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = ConfigureClient(req, resp)
}

func (d *NamespacesDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data NamespacesDataSourceModel

	resp.Diagnostics.Append(d.client.ByServerType(ctx,
		func() {
			found := false
			for _, n := range data.Namespaces {
				if n.ID.ValueString() == GlobalNamespaceID {
					found = true
				}
			}
			if !found {
				data.Namespaces = append(data.Namespaces, NamespaceModel{
					ClusterID: types.StringNull(),
					ID:        types.StringValue(GlobalNamespaceID),
					Name:      types.StringNull(),
					ParentID:  types.StringNull(),
				})
			}
		},
		func(client *client.Client) {
			listReq := &pb.ListNamespacesRequest{}
			listRes, err := client.NamespaceService.ListNamespaces(ctx, listReq)
			if err != nil {
				resp.Diagnostics.AddError("Error reading namespaces", err.Error())
				return
			}

			namespaces := make([]NamespaceModel, 0, len(listRes.Namespaces))
			for _, ns := range listRes.Namespaces {
				var namespace NamespaceModel
				namespace.ID = types.StringValue(ns.Id)
				namespace.Name = types.StringValue(ns.Name)
				if ns.ParentId != "" {
					namespace.ParentID = types.StringValue(ns.ParentId)
				} else {
					namespace.ParentID = types.StringNull()
				}
				namespaces = append(namespaces, namespace)
			}

			data.Namespaces = namespaces
		},
		func(_ sdk.ZeroClient) {
			resp.Diagnostics.AddError("unsupported server type: zero", "unsupported server type: zero")
		})...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
