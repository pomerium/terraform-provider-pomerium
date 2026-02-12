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

	client "github.com/pomerium/enterprise-client-go"
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
	var plan ExternalDataSourceResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.client.EnterpriseOnly(ctx, func(client *client.Client) {
		pbExternalDataSource, diags := ConvertExternalDataSourceToPB(ctx, &plan)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		createReq := &pb.SetExternalDataSourceRequest{
			ExternalDataSource: pbExternalDataSource,
		}
		createRes, err := client.ExternalDataSourceService.SetExternalDataSource(ctx, createReq)
		if err != nil {
			resp.Diagnostics.AddError("set external data source", err.Error())
			return
		}

		diags = ConvertExternalDataSourceFromPB(&plan, createRes.ExternalDataSource)
		resp.Diagnostics.Append(diags...)
	})...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Trace(ctx, "Created an external data source", map[string]any{
		"id": plan.ID.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ExternalDataSourceResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ExternalDataSourceResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.client.EnterpriseOnly(ctx, func(client *client.Client) {
		getReq := &pb.GetExternalDataSourceRequest{
			Id: state.ID.ValueString(),
		}
		getRes, err := client.ExternalDataSourceService.GetExternalDataSource(ctx, getReq)
		if err != nil {
			if status.Code(err) == codes.NotFound {
				resp.State.RemoveResource(ctx)
				return
			}
			resp.Diagnostics.AddError("get external data source", err.Error())
			return
		}

		diags := ConvertExternalDataSourceFromPB(&state, getRes.ExternalDataSource)
		resp.Diagnostics.Append(diags...)
	})...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ExternalDataSourceResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan ExternalDataSourceResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.client.EnterpriseOnly(ctx, func(client *client.Client) {
		pbExternalDataSource, diags := ConvertExternalDataSourceToPB(ctx, &plan)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		setReq := &pb.SetExternalDataSourceRequest{
			ExternalDataSource: pbExternalDataSource,
		}
		setRes, err := client.ExternalDataSourceService.SetExternalDataSource(ctx, setReq)
		if err != nil {
			resp.Diagnostics.AddError("set external data source", err.Error())
			return
		}

		diags = ConvertExternalDataSourceFromPB(&plan, setRes.ExternalDataSource)
		resp.Diagnostics.Append(diags...)
	})...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ExternalDataSourceResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data ExternalDataSourceResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.client.EnterpriseOnly(ctx, func(client *client.Client) {
		deleteReq := &pb.DeleteExternalDataSourceRequest{
			Id: data.ID.ValueString(),
		}
		_, err := client.ExternalDataSourceService.DeleteExternalDataSource(ctx, deleteReq)
		if err != nil {
			resp.Diagnostics.AddError("delete external data source", err.Error())
			return
		}
	})...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.State.RemoveResource(ctx)
}

func (r *ExternalDataSourceResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
