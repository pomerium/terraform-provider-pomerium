package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pomerium/enterprise-client-go/pb"
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

	policyResp, err := d.client.PolicyService.GetPolicy(ctx, &pb.GetPolicyRequest{
		Id: data.ID.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("Error reading policy", err.Error())
		return
	}

	var out PolicyModel

	diags := ConvertPolicyFromPB(&out, policyResp.Policy)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &out)...)
}
