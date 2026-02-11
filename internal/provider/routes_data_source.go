package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &RoutesDataSource{}

func NewRoutesDataSource() datasource.DataSource {
	return &RoutesDataSource{}
}

type RoutesDataSource struct {
	client *Client
}

type RoutesDataSourceModel struct {
	NamespaceID types.String `tfsdk:"namespace_id"`
	Query       types.String `tfsdk:"query"`
	Offset      types.Int64  `tfsdk:"offset"`
	Limit       types.Int64  `tfsdk:"limit"`
	OrderBy     types.String `tfsdk:"order_by"`
	ClusterID   types.String `tfsdk:"cluster_id"`
	Routes      []RouteModel `tfsdk:"routes"`
	TotalCount  types.Int64  `tfsdk:"total_count"`
}

func (d *RoutesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_routes"
}

func (d *RoutesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "List all routes",
		Attributes: map[string]schema.Attribute{
			"namespace_id": schema.StringAttribute{
				Optional:    true,
				Description: "Namespace to list routes in.",
			},
			"query": schema.StringAttribute{
				Optional:    true,
				Description: "Query for routes.",
			},
			"offset": schema.Int64Attribute{
				Optional:    true,
				Description: "List offset.",
			},
			"limit": schema.Int64Attribute{
				Optional:    true,
				Description: "List limit.",
			},
			"order_by": schema.StringAttribute{
				Optional:    true,
				Description: "List order by.",
				Validators: []validator.String{
					stringvalidator.OneOf("newest", "oldest", "name", "from"),
				},
			},
			"cluster_id": schema.StringAttribute{
				Optional:    true,
				Description: "List routes belonging to cluster.",
			},
			"routes": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: getRouteDataSourceAttributes(false),
				},
			},
			"total_count": schema.Int64Attribute{
				Optional:    true,
				Description: "Total number of routes.",
			},
		},
	}
}

func (d *RoutesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = ConfigureClient(req, resp)
}

func (d *RoutesDataSource) Read(ctx context.Context, req datasource.ReadRequest, res *datasource.ReadResponse) {
	readDataSource(ctx, req, res,
		func(model *RoutesDataSourceModel) {
			listReq := newModelToCoreConverter(&res.Diagnostics).ListRoutesRequest(model)
			if res.Diagnostics.HasError() {
				return
			}

			listRes, err := d.client.shared.ListRoutes(ctx, listReq)
			if err != nil {
				res.Diagnostics.AddError("Error reading routes", err.Error())
				return
			}

			routes := make([]RouteModel, 0, len(listRes.Msg.GetRoutes()))
			for _, route := range listRes.Msg.GetRoutes() {
				coreToModel := newCoreToModelConverter(&res.Diagnostics)
				routeModel := coreToModel.Route(route, nil)
				if coreToModel.diagnostics.HasError() {
					return
				}
				routes = append(routes, *routeModel)
			}

			model.Routes = routes
			model.TotalCount = types.Int64Value(int64(listRes.Msg.GetTotalCount()))
		})
}
