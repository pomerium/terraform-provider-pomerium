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

var _ datasource.DataSource = &PolicyDataSource{}

func NewPolicyDataSource() datasource.DataSource {
	return &PolicyDataSource{}
}

type PolicyDataSource struct {
	client *client.Client
}

type PolicyDataSourceModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	NamespaceID types.String `tfsdk:"namespace_id"`
	PPL         types.String `tfsdk:"ppl"`
}

func (d *PolicyDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policy"
}

func (d *PolicyDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Policy data source",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Required:    true,
				Description: "Unique identifier for the policy.",
			},
			"name": schema.StringAttribute{
				Computed:    true,
				Description: "Name of the policy.",
			},
			"namespace_id": schema.StringAttribute{
				Computed:    true,
				Description: "ID of the namespace the policy belongs to.",
			},
			"ppl": schema.StringAttribute{
				Computed:    true,
				Description: "Policy Policy Language (PPL) string.",
			},
		},
	}
}

func (d *PolicyDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *PolicyDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data PolicyDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policyResp, err := d.client.PolicyService.GetPolicy(ctx, &pb.GetPolicyRequest{
		Id: data.ID.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("Error reading policy", err.Error())
		return
	}

	diags := ConvertPolicyFromPB(&PolicyResourceModel{
		ID:          data.ID,
		Name:        data.Name,
		NamespaceID: data.NamespaceID,
		PPL:         data.PPL,
	}, policyResp.Policy)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
