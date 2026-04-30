package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	client "github.com/pomerium/enterprise-client-go"
	"github.com/pomerium/enterprise-client-go/pb"
	"github.com/pomerium/sdk-go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/hashicorp/terraform-plugin-framework/resource"
)

func recordingDataSourceNotSupportedByCore(d *diag.Diagnostics) {
	d.AddError("unsupported server type: core", "recording data sources can be configured for enterprise only")
}

func recordingDataSourceNotSupportedByZero(d *diag.Diagnostics) {
	d.AddError("unsupported server type: zero", "recording data sources can be configured for enterprise only")
}

var _ interface {
	resource.Resource
	resource.ResourceWithImportState
	resource.ResourceWithModifyPlan
} = (*RecordingDataSourceResource)(nil)

func NewRecordingDatasourceResource() resource.Resource {
	return new(RecordingDataSourceResource)
}

type RecordingDataSourceResource struct {
	client *Client
}

type RecordingDataSourceResourceModel = RecordingDataSourceModel

func (r *RecordingDataSourceResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_recording_data_source"
}

func (r *RecordingDataSourceResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
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
				Required:    true,
				Description: "The bucket configuration as a URI string. For example s3://my-bucket. See documentation for full examples",
			},
		},
	}
}

func (r *RecordingDataSourceResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = ConfigureClient(req, resp)
}

func (r *RecordingDataSourceResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.State.Raw.IsNull() {
		return // create case
	}
	if req.Plan.Raw.IsNull() {
		return // destroy case
	}

	var state RecordingDataSourceModel
	var plan RecordingDataSourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	if resp.Diagnostics.HasError() {
		return
	}

	if state.BucketURI != plan.BucketURI {
		resp.Diagnostics.AddWarning(
			"session recording datasource bucket changed",
			"Changing the bucket may make previously recorded sessions unavailable from the enterprise UI",
		)
	}
}

func (r *RecordingDataSourceResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan RecordingDataSourceResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(
		r.client.ByServerType(
			func(_ sdk.CoreClient) {
				recordingDataSourceNotSupportedByCore(&resp.Diagnostics)
			}, func(client *client.Client) {
				recordingDatasource := NewModelToEnterpriseConverter(&resp.Diagnostics).RecordingDataSource(plan)

				createReq := &pb.CreateDatasourceRequest{
					Datasource: recordingDatasource,
				}

				_, err := client.SessionRecordingService.CreateDatasource(ctx, createReq)
				if err != nil {
					resp.Diagnostics.AddError("set recording data source", err.Error())
					return
				}
				plan = NewEnterpriseToModelConverter(&resp.Diagnostics).RecordingDatasource(
					recordingDatasource,
				)
			}, func(_ sdk.ZeroClient) {
				recordingDataSourceNotSupportedByZero(&resp.Diagnostics)
			},
		)...,
	)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Trace(ctx, "Created a recording datasource", map[string]any{
		"name":      plan.Name.ValueString(),
		"namespace": plan.Namespace.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *RecordingDataSourceResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state RecordingDataSourceDataSourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(r.client.ByServerType(
		func(_ sdk.CoreClient) {
			recordingDataSourceNotSupportedByCore(&resp.Diagnostics)
		},
		func(client *client.Client) {
			recordingDatasource := NewModelToEnterpriseConverter(&resp.Diagnostics).RecordingDataSource(state)
			getReq := &pb.GetDatasourceRequest{
				Name:      recordingDatasource.GetEntry().GetName(),
				Namespace: recordingDatasource.GetNamespace(),
			}
			getResp, err := client.SessionRecordingService.GetDatasource(ctx, getReq)
			if err != nil {
				if status.Code(err) == codes.NotFound {
					resp.State.RemoveResource(ctx)
					return
				}
				resp.Diagnostics.AddError(
					"failed to get recording datasources",
					fmt.Sprintf("failed to get recording datasources for %s/%s : %s", getReq.GetNamespace(), getReq.GetName(), err.Error()),
				)
				return
			}
			resp.Diagnostics.Append(resp.State.Set(ctx, NewEnterpriseToModelConverter(&resp.Diagnostics).RecordingDatasource(getResp.Datasource))...)
		},
		func(_ sdk.ZeroClient) {
			recordingDataSourceNotSupportedByZero(&resp.Diagnostics)
		},
	)...)
}

func (r *RecordingDataSourceResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan RecordingDataSourceDataSourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(r.client.ByServerType(
		func(_ sdk.CoreClient) {
			recordingDataSourceNotSupportedByCore(&resp.Diagnostics)
		},
		func(client *client.Client) {
			recordingDatasource := NewModelToEnterpriseConverter(&resp.Diagnostics).RecordingDataSource(plan)

			_, err := client.SessionRecordingService.GetDatasource(
				ctx,
				&pb.GetDatasourceRequest{
					Name:      recordingDatasource.GetEntry().GetName(),
					Namespace: recordingDatasource.GetNamespace(),
				},
			)
			if err != nil && status.Code(err) == codes.NotFound {
				createResp, err := client.SessionRecordingService.CreateDatasource(ctx, &pb.CreateDatasourceRequest{
					Datasource: recordingDatasource,
				})
				if err != nil {
					resp.Diagnostics.AddError(
						"failed to create datasource",
						fmt.Sprintf("failed to create datasource %s/%s: %s", recordingDatasource.GetNamespace(), recordingDatasource.GetNamespace(), err.Error()),
					)
					return
				}

				resp.Diagnostics.Append(resp.State.Set(ctx, NewEnterpriseToModelConverter(&resp.Diagnostics).RecordingDatasource(createResp.GetCreated()))...)
				return
			} else if err != nil {
				resp.Diagnostics.AddError("failed to fetch recording datasource", err.Error())
				return
			}

			// exists - delete then update.
			_, deleteErr := client.SessionRecordingService.DeleteDatasource(ctx, &pb.DeleteDatasourceRequest{
				Name:      recordingDatasource.GetEntry().GetName(),
				Namespace: recordingDatasource.GetNamespace(),
			})
			if deleteErr != nil {
				resp.Diagnostics.AddError("failed to delete session recording datasource while updating", deleteErr.Error())
				return
			}
			createResp, createErr := client.SessionRecordingService.CreateDatasource(ctx, &pb.CreateDatasourceRequest{
				Datasource: recordingDatasource,
			})
			if createErr != nil {
				resp.Diagnostics.AddError("failed to create new session recording datasource while updating", createErr.Error())
				return
			}
			resp.Diagnostics.Append(resp.State.Set(ctx, NewEnterpriseToModelConverter(&resp.Diagnostics).RecordingDatasource(createResp.GetCreated()))...)
		},
		func(_ sdk.ZeroClient) {
			recordingDataSourceNotSupportedByZero(&resp.Diagnostics)
		},
	)...)
}

func (r *RecordingDataSourceResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var plan RecordingDataSourceDataSourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(r.client.ByServerType(
		func(_ sdk.CoreClient) {
			recordingDataSourceNotSupportedByCore(&resp.Diagnostics)
		},
		func(client *client.Client) {
			recordingDatasource := NewModelToEnterpriseConverter(&resp.Diagnostics).RecordingDataSource(plan)
			delReq := &pb.DeleteDatasourceRequest{
				Name:      recordingDatasource.GetEntry().GetName(),
				Namespace: recordingDatasource.GetNamespace(),
			}
			_, err := client.SessionRecordingService.DeleteDatasource(ctx, delReq)
			if err != nil {
				resp.Diagnostics.AddError("delete recording datasource", err.Error())
				return
			}
		},
		func(_ sdk.ZeroClient) {
			recordingDataSourceNotSupportedByZero(&resp.Diagnostics)
		},
	)...)

	if resp.Diagnostics.HasError() {
		return
	}
	resp.State.RemoveResource(ctx)
}

func (r *RecordingDataSourceResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("name"), req, resp)
}
