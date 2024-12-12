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

var _ datasource.DataSource = &ServiceAccountDataSource{}

func NewServiceAccountDataSource() datasource.DataSource {
	return &ServiceAccountDataSource{}
}

type ServiceAccountDataSource struct {
	client *client.Client
}

type ServiceAccountDataSourceModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	NamespaceID types.String `tfsdk:"namespace_id"`
	Description types.String `tfsdk:"description"`
	UserID      types.String `tfsdk:"user_id"`
	ExpiresAt   types.String `tfsdk:"expires_at"`
}

func (d *ServiceAccountDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_service_account"
}

func (d *ServiceAccountDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Service Account data source",

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

func (d *ServiceAccountDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data ServiceAccountDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	serviceAccountResp, err := d.client.PomeriumServiceAccountService.GetPomeriumServiceAccount(ctx, &pb.GetPomeriumServiceAccountRequest{
		Id: data.ID.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("Error reading service account", err.Error())
		return
	}

	diags := ConvertServiceAccountFromPB(&ServiceAccountResourceModel{
		ID:          data.ID,
		Name:        data.Name,
		NamespaceID: data.NamespaceID,
		Description: data.Description,
		UserID:      data.UserID,
		ExpiresAt:   data.ExpiresAt,
	}, serviceAccountResp.ServiceAccount)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
