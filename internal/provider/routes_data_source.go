package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
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
	Namespace  types.String `tfsdk:"namespace"`
	Query      types.String `tfsdk:"query"`
	Offset     types.Int64  `tfsdk:"offset"`
	Limit      types.Int64  `tfsdk:"limit"`
	OrderBy    types.String `tfsdk:"order_by"`
	Routes     []RouteModel `tfsdk:"routes"`
	TotalCount types.Int64  `tfsdk:"total_count"`
}

func (d *RoutesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_routes"
}

func (d *RoutesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "List all routes",
		Attributes: map[string]schema.Attribute{
			"namespace": schema.StringAttribute{
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

func (d *RoutesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data RoutesDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	listReq := &pb.ListRoutesRequest{
		Namespace: data.Namespace.ValueString(),
		Query:     data.Query.ValueStringPointer(),
		Offset:    data.Offset.ValueInt64Pointer(),
		Limit:     data.Limit.ValueInt64Pointer(),
		OrderBy:   data.OrderBy.ValueStringPointer(),
	}
	routesResp, err := d.client.RouteService.ListRoutes(ctx, listReq)
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
	data.TotalCount = types.Int64Value(routesResp.GetTotalCount())
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
