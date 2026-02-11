package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/enterprise-client-go/pb"
)

var (
	_ resource.Resource                = &ExternalDataSourceResource{}
	_ resource.ResourceWithImportState = &ExternalDataSourceResource{}
)

func NewExternalDataSourceResource() resource.Resource {
	return &ExternalDataSourceResource{}
}

// ExternalDataSourceResource defines the resource implementation.
type ExternalDataSourceResource struct {
	client *Client
}

// ExternalDataSourceResourceModel describes the resource data model.
type ExternalDataSourceResourceModel = ExternalDataSourceModel

func (r *ExternalDataSourceResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_external_data_source"
}

func (r *ExternalDataSourceResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "External Data Source for Pomerium.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Unique identifier for the external data source.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"url": schema.StringAttribute{
				Description: "The URL to query for data.",
				Required:    true,
			},
			"record_type": schema.StringAttribute{
				Description: "How the queried records will be stored in the databroker.",
				Required:    true,
			},
			"foreign_key": schema.StringAttribute{
				Description: "The key referenced for policy evaluation. E.g. user.id.",
				Required:    true,
			},
			"headers": schema.MapAttribute{
				ElementType: types.StringType,
				Description: "Request headers sent to the external data source.",
				Optional:    true,
			},
			"allow_insecure_tls": schema.BoolAttribute{
				Description: "Ignores TLS errors from the external data source.",
				Optional:    true,
			},
			"client_tls_key_id": schema.StringAttribute{
				Description: "The key pair used for TLS to the external data source.",
				Optional:    true,
			},
			"cluster_id": schema.StringAttribute{
				Description: "The cluster ID for the external data source.",
				Optional:    true,
			},
			"polling_min_delay": schema.StringAttribute{
				Description: "The minimum amount of time to wait before polling again.",
				Optional:    true,
				CustomType:  timetypes.GoDurationType{},
			},
			"polling_max_delay": schema.StringAttribute{
				Description: "The maximum amount of time to wait before polling again.",
				Optional:    true,
				CustomType:  timetypes.GoDurationType{},
			},
		},
	}
}

func (r *ExternalDataSourceResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = ConfigureClient(req, resp)
}

func (r *ExternalDataSourceResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var model ExternalDataSourceResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &model)...)

	if resp.Diagnostics.HasError() {
		return
	}

	pbExternalDataSource, diags := ConvertExternalDataSourceToPB(ctx, &model)
	resp.Diagnostics.Append(diags...)
	if diags.HasError() {
		return
	}

	respExternalDataSource, err := r.client.SetExternalDataSource(ctx, &pb.SetExternalDataSourceRequest{
		ExternalDataSource: pbExternalDataSource,
	})
	if err != nil {
		resp.Diagnostics.AddError("set external data source", err.Error())
		return
	}

	diags = ConvertExternalDataSourceFromPB(&model, respExternalDataSource.ExternalDataSource)
	resp.Diagnostics.Append(diags...)
	if diags.HasError() {
		return
	}

	tflog.Trace(ctx, "Created an external data source", map[string]interface{}{
		"id": model.ID.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

func (r *ExternalDataSourceResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var model ExternalDataSourceResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}

	respExternalDataSource, err := r.client.GetExternalDataSource(ctx, &pb.GetExternalDataSourceRequest{
		Id: model.ID.ValueString(),
	})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("get external data source", err.Error())
		return
	}

	diags := ConvertExternalDataSourceFromPB(&model, respExternalDataSource.ExternalDataSource)
	resp.Diagnostics.Append(diags...)
	if diags.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

func (r *ExternalDataSourceResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var model ExternalDataSourceResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}

	pbExternalDataSource, diags := ConvertExternalDataSourceToPB(ctx, &model)
	resp.Diagnostics.Append(diags...)
	if diags.HasError() {
		return
	}

	respExternalDataSource, err := r.client.SetExternalDataSource(ctx, &pb.SetExternalDataSourceRequest{
		ExternalDataSource: pbExternalDataSource,
	})
	if err != nil {
		resp.Diagnostics.AddError("set external data source", err.Error())
		return
	}

	diags = ConvertExternalDataSourceFromPB(&model, respExternalDataSource.ExternalDataSource)
	resp.Diagnostics.Append(diags...)
	if diags.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

func (r *ExternalDataSourceResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data ExternalDataSourceResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.DeleteExternalDataSource(ctx, &pb.DeleteExternalDataSourceRequest{
		Id: data.ID.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("delete external data source", err.Error())
		return
	}

	resp.State.RemoveResource(ctx)
}

func (r *ExternalDataSourceResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
