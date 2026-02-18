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
	"github.com/pomerium/sdk-go/proto/pomerium"
)

var _ datasource.DataSource = &PolicyDataSource{}

func NewPolicyDataSource() datasource.DataSource {
	return &PolicyDataSource{}
}

type PolicyDataSource struct {
	client *Client
}

func (d *PolicyDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policy"
}

func (d *PolicyDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Policy for Pomerium.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Required:    true,
				Description: "Unique identifier for the policy.",
			},
			"description": schema.StringAttribute{
				Computed:    true,
				Description: "Description of the policy.",
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
				CustomType:  PolicyLanguageType{},
			},
			"rego": schema.ListAttribute{
				Computed:    true,
				Description: "Rego policies.",
				ElementType: types.StringType,
			},
			"enforced": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the policy is enforced within the namespace hierarchy.",
			},
			"explanation": schema.StringAttribute{
				Computed:    true,
				Description: "Explanation of the policy.",
			},
			"remediation": schema.StringAttribute{
				Computed:    true,
				Description: "Remediation of the policy.",
			},
		},
	}
}

func (d *PolicyDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = ConfigureClient(req, resp)
}

func (d *PolicyDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data PolicyModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(d.client.ConsolidatedOrLegacy(ctx,
		func(client sdk.Client) {
			getReq := connect.NewRequest(&pomerium.GetPolicyRequest{
				Id: data.ID.ValueString(),
			})
			getRes, err := client.GetPolicy(ctx, getReq)
			if err != nil {
				resp.Diagnostics.AddError("Error getting policy", err.Error())
				return
			}

			data = NewAPIToModelConverter(&resp.Diagnostics).Policy(getRes.Msg.Policy)
		},
		func(client *client.Client) {
			getReq := &pb.GetPolicyRequest{
				Id: data.ID.ValueString(),
			}
			getRes, err := client.PolicyService.GetPolicy(ctx, getReq)
			if err != nil {
				resp.Diagnostics.AddError("Error reading policy", err.Error())
				return
			}

			data = NewEnterpriseToModelConverter(&resp.Diagnostics).Policy(getRes.GetPolicy())
		})...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
