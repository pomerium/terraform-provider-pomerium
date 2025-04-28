package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	client "github.com/pomerium/enterprise-client-go"
	"github.com/pomerium/enterprise-client-go/pb"
)

var _ datasource.DataSource = &NamespacesDataSource{}

func NewNamespacesDataSource() datasource.DataSource {
	return &NamespacesDataSource{}
}

type NamespacesDataSource struct {
	client *client.Client
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

	namespacesResp, err := d.client.NamespaceService.ListNamespaces(ctx, &pb.ListNamespacesRequest{})
	if err != nil {
		resp.Diagnostics.AddError("Error reading namespaces", err.Error())
		return
	}

	namespaces := make([]NamespaceModel, 0, len(namespacesResp.Namespaces))
	for _, ns := range namespacesResp.Namespaces {
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
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
