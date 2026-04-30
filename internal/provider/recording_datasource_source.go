package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	client "github.com/pomerium/enterprise-client-go"
	"github.com/pomerium/enterprise-client-go/pb"
	"github.com/pomerium/sdk-go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var _ interface {
	datasource.DataSource
	datasource.DataSourceWithConfigure
} = (*RecordingDataSourceDataSource)(nil)

func NewRecordingDatasource() datasource.DataSource {
	return new(RecordingDataSourceDataSource)
}

type RecordingDataSourceDataSource struct {
	client *Client
}

type RecordingDataSourceDataSourceModel = RecordingDataSourceModel

func (r *RecordingDataSourceDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	r.client = ConfigureClient(req, resp)
}

func (r *RecordingDataSourceDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_recording_data_source"
}

func (r *RecordingDataSourceDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Session Recording Blob Data Source for Pomerium enterprise",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Unique identifier (preferably human readable) for the recording data source",
			},
			"namespace": schema.StringAttribute{
				Required:    true,
				Description: "The pomerium namespace this recording datasource is associated with",
			},
			"bucket_uri": schema.StringAttribute{
				Computed:    true,
				Description: "The bucket configuration as a URI string. For example s3://my-bucket. See documentation for full examples",
			},
		},
	}
}

func (r *RecordingDataSourceDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state RecordingDataSourceDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if state.Name.IsUnknown() || state.Namespace.IsUnknown() {
		state.BucketURI = types.StringUnknown()
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
		return
	}

	resp.Diagnostics.Append(r.client.ByServerType(
		func(_ sdk.CoreClient) {
			recordingDataSourceNotSupportedByCore(&resp.Diagnostics)
		}, func(client *client.Client) {
			recordingDatasource := NewModelToEnterpriseConverter(&resp.Diagnostics).RecordingDataSource(state)
			getReq := &pb.GetDatasourceRequest{
				Name:      recordingDatasource.GetEntry().GetName(),
				Namespace: recordingDatasource.GetNamespace(),
			}
			getResp, err := client.SessionRecordingService.GetDatasource(ctx, getReq)
			if err != nil {
				if status.Code(err) == codes.NotFound {
					resp.Diagnostics.AddError(
						"recording datasource not found",
						fmt.Sprintf("recording datasource with %s/%s not found", recordingDatasource.GetNamespace(), recordingDatasource.GetEntry().GetName()),
					)
					return
				}
				resp.Diagnostics.AddError(
					"failed to get recording datasources",
					fmt.Sprintf(
						"failed to get recording datasource %s/%s : %s", recordingDatasource.GetNamespace(), recordingDatasource.GetEntry().GetName(), err.Error(),
					),
				)
				return
			}
			state = NewEnterpriseToModelConverter(&resp.Diagnostics).RecordingDatasource(getResp.GetDatasource())
		}, func(_ sdk.ZeroClient) {
			recordingDataSourceNotSupportedByZero(&resp.Diagnostics)
		})...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
