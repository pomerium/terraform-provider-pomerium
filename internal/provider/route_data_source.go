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

var _ datasource.DataSource = &RouteDataSource{}

func NewRouteDataSource() datasource.DataSource {
	return &RouteDataSource{}
}

type RouteDataSource struct {
	client *client.Client
}

type RouteDataSourceModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	From        types.String `tfsdk:"from"`
	To          types.List   `tfsdk:"to"`
	NamespaceID types.String `tfsdk:"namespace_id"`
	Policies    types.List   `tfsdk:"policies"`
}

func (d *RouteDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_route"
}

func (d *RouteDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Route data source",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Required:    true,
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
	}
}

func (d *RouteDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *RouteDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data RouteDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	routeResp, err := d.client.RouteService.GetRoute(ctx, &pb.GetRouteRequest{
		Id: data.ID.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("Error reading route", err.Error())
		return
	}

	diags := ConvertRouteFromPB(&RouteResourceModel{
		ID:          data.ID,
		Name:        data.Name,
		From:        data.From,
		To:          data.To,
		NamespaceID: data.NamespaceID,
		Policies:    data.Policies,
	}, routeResp.Route)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
