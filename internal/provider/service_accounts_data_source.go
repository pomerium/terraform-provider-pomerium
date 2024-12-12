package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"

	client "github.com/pomerium/enterprise-client-go"
	"github.com/pomerium/enterprise-client-go/pb"
)

var _ datasource.DataSource = &ServiceAccountsDataSource{}

func NewServiceAccountsDataSource() datasource.DataSource {
	return &ServiceAccountsDataSource{}
}

type ServiceAccountsDataSource struct {
	client *client.Client
}

type ServiceAccountsDataSourceModel struct {
	ServiceAccounts []ServiceAccountModel `tfsdk:"service_accounts"`
}

func (d *ServiceAccountsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_service_accounts"
}

func (d *ServiceAccountsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "List all service accounts",

		Attributes: map[string]schema.Attribute{
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

func (d *ServiceAccountsDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data ServiceAccountsDataSourceModel

	serviceAccountsResp, err := d.client.PomeriumServiceAccountService.ListPomeriumServiceAccounts(ctx, &pb.ListPomeriumServiceAccountsRequest{})
	if err != nil {
		resp.Diagnostics.AddError("Error reading service accounts", err.Error())
		return
	}

	serviceAccounts := make([]ServiceAccountModel, 0, len(serviceAccountsResp.ServiceAccounts))
	for _, sa := range serviceAccountsResp.ServiceAccounts {
		var saModel ServiceAccountModel
		diags := ConvertServiceAccountFromPB(&saModel, sa)
		if diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}
		serviceAccounts = append(serviceAccounts, saModel)
	}

	data.ServiceAccounts = serviceAccounts
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
