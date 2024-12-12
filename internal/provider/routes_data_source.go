package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	client "github.com/pomerium/enterprise-client-go"
	"github.com/pomerium/enterprise-client-go/pb"
)

var _ datasource.DataSource = &RoutesDataSource{}

func NewRoutesDataSource() datasource.DataSource {
	return &RoutesDataSource{}
}

type RoutesDataSource struct {
	client *client.Client
}

type RoutesDataSourceModel struct {
	Routes []RouteModel `tfsdk:"routes"`
}

func (d *RoutesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_routes"
}

func (d *RoutesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "List all routes",

		Attributes: map[string]schema.Attribute{
			"routes": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "Unique identifier for the route.",
						},
						"name": schema.StringAttribute{
							Computed:    true,
							Description: "Name of the route.",
						},
						"from": schema.StringAttribute{
							Computed:    true,
							Description: "From URL.",
						},
						"to": schema.ListAttribute{
							Computed:    true,
							ElementType: types.StringType,
							Description: "To URLs.",
						},
						"namespace_id": schema.StringAttribute{
							Computed:    true,
							Description: "ID of the namespace the route belongs to.",
						},
						"policies": schema.ListAttribute{
							Computed:    true,
							ElementType: types.StringType,
							Description: "List of policy IDs associated with the route.",
						},
					},
				},
			},
		},
	}
}

func (d *RoutesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *RoutesDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data RoutesDataSourceModel

	routesResp, err := d.client.RouteService.ListRoutes(ctx, &pb.ListRoutesRequest{})
	if err != nil {
		resp.Diagnostics.AddError("Error reading routes", err.Error())
		return
	}

	routes := make([]RouteModel, 0, len(routesResp.Routes))
	for _, route := range routesResp.Routes {
		var routeModel RouteModel
		diags := ConvertRouteFromPB(&routeModel, route)
		if diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}
		routes = append(routes, routeModel)
	}

	data.Routes = routes
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
