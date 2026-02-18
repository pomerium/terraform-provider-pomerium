package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	client "github.com/pomerium/enterprise-client-go"
	"github.com/pomerium/enterprise-client-go/pb"
	"github.com/pomerium/sdk-go"
)

var (
	_ datasource.DataSource              = &ExternalDataSourceDataSource{}
	_ datasource.DataSourceWithConfigure = &ExternalDataSourceDataSource{}
)

func NewExternalDataSourceDataSource() datasource.DataSource {
	return &ExternalDataSourceDataSource{}
}

// ExternalDataSourceDataSource defines the data source implementation.
type ExternalDataSourceDataSource struct {
	client *Client
}

// ExternalDataSourceDataSourceModel describes the data source data model.
type ExternalDataSourceDataSourceModel = ExternalDataSourceModel

func (d *ExternalDataSourceDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_external_data_source"
}

func (d *ExternalDataSourceDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "External Data Source for Pomerium.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Unique identifier for the external data source.",
				Required:    true,
			},
			"url": schema.StringAttribute{
				Description: "The URL to query for data.",
				Computed:    true,
			},
			"record_type": schema.StringAttribute{
				Description: "How the queried records will be stored in the databroker.",
				Computed:    true,
			},
			"foreign_key": schema.StringAttribute{
				Description: "The key referenced for policy evaluation. E.g. user.id.",
				Computed:    true,
			},
			"headers": schema.MapAttribute{
				ElementType: types.StringType,
				Description: "Request headers sent to the external data source.",
				Computed:    true,
			},
			"allow_insecure_tls": schema.BoolAttribute{
				Description: "Ignores TLS errors from the external data source.",
				Computed:    true,
			},
			"client_tls_key_id": schema.StringAttribute{
				Description: "The key pair used for TLS to the external data source.",
				Computed:    true,
			},
			"cluster_id": schema.StringAttribute{
				Description: "The cluster ID for the external data source.",
				Computed:    true,
			},
			"polling_min_delay": schema.StringAttribute{
				Description: "The minimum amount of time to wait before polling again.",
				Computed:    true,
				CustomType:  timetypes.GoDurationType{},
			},
			"polling_max_delay": schema.StringAttribute{
				Description: "The maximum amount of time to wait before polling again.",
				Computed:    true,
				CustomType:  timetypes.GoDurationType{},
			},
		},
	}
}

func (d *ExternalDataSourceDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = ConfigureClient(req, resp)
}

func (d *ExternalDataSourceDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state ExternalDataSourceDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(d.client.ByServerType(ctx,
		func() {
			resp.Diagnostics.AddError("external data source not found", "external data source not found")
		},
		func(client *client.Client) {
			getReq := &pb.GetExternalDataSourceRequest{
				Id: state.ID.ValueString(),
			}
			getRes, err := client.ExternalDataSourceService.GetExternalDataSource(ctx, getReq)
			if err != nil {
				if status.Code(err) == codes.NotFound {
					resp.Diagnostics.AddError("External Data Source not found", fmt.Sprintf("External Data Source with ID %s not found", state.ID.ValueString()))
					return
				}
				resp.Diagnostics.AddError("get external data source", err.Error())
				return
			}

			state = NewEnterpriseToModelConverter(&resp.Diagnostics).ExternalDataSource(getRes.GetExternalDataSource())
		},
		func(_ sdk.ZeroClient) {
			resp.Diagnostics.AddError("unsupported server type: zero", "unsupported server type: zero")
		})...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
