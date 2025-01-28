package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

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
	Namespace  types.String  `tfsdk:"namespace"`
	Query      types.String  `tfsdk:"query"`
	Offset     types.Int64   `tfsdk:"offset"`
	Limit      types.Int64   `tfsdk:"limit"`
	OrderBy    types.String  `tfsdk:"order_by"`
	Policies   []PolicyModel `tfsdk:"policies"`
	TotalCount types.Int64   `tfsdk:"total_count"`
}

func (d *PoliciesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policies"
}

func (d *PoliciesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "List all policies",

		Attributes: map[string]schema.Attribute{
			"namespace": schema.StringAttribute{
				Optional:    true,
				Description: "Namespace to list policies in.",
			},
			"query": schema.StringAttribute{
				Optional:    true,
				Description: "Query for policies.",
			},
			"offset": schema.Int64Attribute{
				Optional:    true,
				Description: "List offset.",
			},
			"limit": schema.Int64Attribute{
				Optional:    true,
				Description: "List limit.",
			},
			"order_by": schema.StringAttribute{
				Optional:    true,
				Description: "List order by.",
				Validators: []validator.String{
					stringvalidator.OneOf("newest", "oldest", "name"),
				},
			},
			"policies": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
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
				},
			},
			"total_count": schema.Int64Attribute{
				Optional:    true,
				Description: "Total number of policies.",
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

func (d *PoliciesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data PoliciesDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	listReq := &pb.ListPoliciesRequest{
		Namespace: data.Namespace.ValueString(),
		Query:     data.Query.ValueStringPointer(),
		Offset:    data.Offset.ValueInt64Pointer(),
		Limit:     data.Limit.ValueInt64Pointer(),
		OrderBy:   data.OrderBy.ValueStringPointer(),
	}

	policiesResp, err := d.client.PolicyService.ListPolicies(ctx, listReq)
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
	data.TotalCount = types.Int64Value(policiesResp.GetTotalCount())
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
