package provider

import (
	"context"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	client "github.com/pomerium/enterprise-client-go"
	"github.com/pomerium/enterprise-client-go/pb"
	"github.com/pomerium/sdk-go"
)

var _ datasource.DataSource = &ServiceAccountsDataSource{}

func NewServiceAccountsDataSource() datasource.DataSource {
	return &ServiceAccountsDataSource{}
}

type ServiceAccountsDataSource struct {
	client *Client
}

type ServiceAccountsDataSourceModel struct {
	NamespaceID     types.String          `tfsdk:"namespace_id"`
	ServiceAccounts []ServiceAccountModel `tfsdk:"service_accounts"`
}

func (d *ServiceAccountsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_service_accounts"
}

func (d *ServiceAccountsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "List all service accounts",
		Attributes: map[string]schema.Attribute{
			"namespace_id": schema.StringAttribute{
				Optional:    true,
				Description: "Namespace of the service accounts.",
			},
			"service_accounts": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
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
				},
			},
		},
	}
}

func (d *ServiceAccountsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = ConfigureClient(req, resp)
}

func (d *ServiceAccountsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data ServiceAccountsDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(d.client.ConsolidatedOrLegacy(
		func(client sdk.Client) {
			listReq := connect.NewRequest(NewModelToAPIConverter(&resp.Diagnostics).ListServiceAccountsRequest(data))
			if resp.Diagnostics.HasError() {
				return
			}

			listRes, err := client.ListServiceAccounts(ctx, listReq)
			if err != nil {
				resp.Diagnostics.AddError("Error listing service accounts", err.Error())
				return
			}

			serviceAccounts := make([]ServiceAccountModel, 0, len(listRes.Msg.ServiceAccounts))
			for _, policy := range listRes.Msg.ServiceAccounts {
				policyModel := NewAPIToModelConverter(&resp.Diagnostics).ServiceAccount(policy)
				if resp.Diagnostics.HasError() {
					return
				}
				serviceAccounts = append(serviceAccounts, policyModel)
			}

			data.ServiceAccounts = serviceAccounts
		},
		func(client *client.Client) {
			listReq := &pb.ListPomeriumServiceAccountsRequest{
				Namespace: data.NamespaceID.ValueString(),
			}
			listRes, err := client.PomeriumServiceAccountService.ListPomeriumServiceAccounts(ctx, listReq)
			if err != nil {
				resp.Diagnostics.AddError("Error reading service accounts", err.Error())
				return
			}

			serviceAccounts := make([]ServiceAccountModel, 0, len(listRes.ServiceAccounts))
			for _, sa := range listRes.ServiceAccounts {
				saModel := NewEnterpriseToModelConverter(&resp.Diagnostics).ServiceAccount(sa)
				if resp.Diagnostics.HasError() {
					return
				}
				serviceAccounts = append(serviceAccounts, saModel)
			}

			data.ServiceAccounts = serviceAccounts
		})...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
