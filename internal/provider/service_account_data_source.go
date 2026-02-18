package provider

import (
	"context"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"

	client "github.com/pomerium/enterprise-client-go"
	"github.com/pomerium/enterprise-client-go/pb"
	"github.com/pomerium/sdk-go"
	"github.com/pomerium/sdk-go/proto/pomerium"
)

var _ datasource.DataSource = &ServiceAccountDataSource{}

func NewServiceAccountDataSource() datasource.DataSource {
	return &ServiceAccountDataSource{}
}

type ServiceAccountDataSource struct {
	client *Client
}

func (d *ServiceAccountDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_service_account"
}

func (d *ServiceAccountDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Service Account for Pomerium.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Required:    true,
				Description: "Unique identifier for the service account.",
			},
			"name": schema.StringAttribute{
				Computed:    true,
				Description: "Name of the service account.",
			},
			"namespace_id": schema.StringAttribute{
				Computed:    true,
				Description: "ID of the namespace the service account belongs to.",
			},
			"description": schema.StringAttribute{
				Computed:    true,
				Description: "Description of the service account.",
			},
			"user_id": schema.StringAttribute{
				Computed:    true,
				Description: "User ID associated with the service account.",
			},
			"expires_at": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp when the service account expires.",
			},
		},
	}
}

func (d *ServiceAccountDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = ConfigureClient(req, resp)
}

func (d *ServiceAccountDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data ServiceAccountModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(d.client.ConsolidatedOrLegacy(ctx,
		func(client sdk.Client) {
			getReq := connect.NewRequest(&pomerium.GetServiceAccountRequest{
				Id: data.ID.ValueString(),
			})
			getRes, err := client.GetServiceAccount(ctx, getReq)
			if err != nil {
				resp.Diagnostics.AddError("Error getting service account", err.Error())
				return
			}

			data = NewAPIToModelConverter(&resp.Diagnostics).ServiceAccount(getRes.Msg.ServiceAccount)
		},
		func(client *client.Client) {
			getReq := &pb.GetPomeriumServiceAccountRequest{
				Id: data.ID.ValueString(),
			}
			getRes, err := client.PomeriumServiceAccountService.GetPomeriumServiceAccount(ctx, getReq)
			if err != nil {
				resp.Diagnostics.AddError("Error reading service account", err.Error())
				return
			}

			data = NewEnterpriseToModelConverter(&resp.Diagnostics).ServiceAccount(getRes.GetServiceAccount())
		})...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
