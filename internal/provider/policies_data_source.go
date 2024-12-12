package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"

	client "github.com/pomerium/enterprise-client-go"
	"github.com/pomerium/enterprise-client-go/pb"
)

var _ datasource.DataSource = &PoliciesDataSource{}

func NewPoliciesDataSource() datasource.DataSource {
	return &PoliciesDataSource{}
}

type PoliciesDataSource struct {
	client *client.Client
}

type PoliciesDataSourceModel struct {
	Policies []PolicyModel `tfsdk:"policies"`
}

func (d *PoliciesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policies"
}

func (d *PoliciesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "List all policies",

		Attributes: map[string]schema.Attribute{
			"policies": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
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
				},
			},
		},
	}
}

func (d *PoliciesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *PoliciesDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data PoliciesDataSourceModel

	policiesResp, err := d.client.PolicyService.ListPolicies(ctx, &pb.ListPoliciesRequest{})
	if err != nil {
		resp.Diagnostics.AddError("Error reading policies", err.Error())
		return
	}

	policies := make([]PolicyModel, 0, len(policiesResp.Policies))
	for _, policy := range policiesResp.Policies {
		var policyModel PolicyModel
		diags := ConvertPolicyFromPB(&policyModel, policy)
		if diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}
		policies = append(policies, policyModel)
	}

	data.Policies = policies
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
