package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	client "github.com/pomerium/enterprise-client-go"
	"github.com/pomerium/enterprise-client-go/pb"
)

// Ensure provider-defined types fully satisfy framework interfaces.
var (
	_ resource.Resource                = (*PolicyResource)(nil)
	_ resource.ResourceWithConfigure   = (*PolicyResource)(nil)
	_ resource.ResourceWithImportState = (*PolicyResource)(nil)
)

// NewPolicyResource creates a new PolicyResource.
func NewPolicyResource() resource.Resource {
	return &PolicyResource{}
}

// PolicyResource defines the resource implementation.
type PolicyResource struct {
	client *client.Client
}

// PolicyResourceModel describes the resource data model.
type PolicyResourceModel = PolicyModel

func (r *PolicyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policy"
}

func (r *PolicyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Policy for Pomerium.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Unique identifier for the policy.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"description": schema.StringAttribute{
				Description: "Description of the policy.",
				Optional:    true,
			},
			"name": schema.StringAttribute{
				Description: "Name of the policy.",
				Required:    true,
			},
			"namespace_id": schema.StringAttribute{
				Description: "ID of the namespace the policy belongs to.",
				Required:    true,
			},
			"ppl": schema.StringAttribute{
				Description: "Policy Policy Language (PPL) string.",
				Required:    true,
				CustomType:  PolicyLanguageType{},
			},
			"rego": schema.ListAttribute{
				Description: "Rego policies.",
				Optional:    true,
				ElementType: types.StringType,
			},
			"enforced": schema.BoolAttribute{
				Description: "Whether the policy is enforced within the namespace hierarchy.",
				Optional:    true,
			},
			"explanation": schema.StringAttribute{
				Description: "Explanation of the policy.",
				Optional:    true,
			},
			"remediation": schema.StringAttribute{
				Description: "Remediation of the policy.",
				Optional:    true,
			},
		},
	}
}

func (r *PolicyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	c, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Provider Data Type",
			fmt.Sprintf("Expected *client.Client, got: %T.", req.ProviderData),
		)
		return
	}

	r.client = c
}

func (r *PolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan PolicyResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	pbPolicy, diags := ConvertPolicyToPB(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	respPolicy, err := r.client.PolicyService.SetPolicy(ctx, &pb.SetPolicyRequest{
		Policy: pbPolicy,
	})
	if err != nil {
		resp.Diagnostics.AddError("Error creating policy", err.Error())
		return
	}

	plan.ID = types.StringValue(respPolicy.Policy.Id)

	tflog.Trace(ctx, "Created a policy", map[string]interface{}{
		"id":   plan.ID.ValueString(),
		"name": plan.Name.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *PolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state PolicyResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	respPolicy, err := r.client.PolicyService.GetPolicy(ctx, &pb.GetPolicyRequest{
		Id: state.ID.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("Error reading policy", err.Error())
		return
	}

	diags := ConvertPolicyFromPB(&state, respPolicy.Policy)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *PolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan PolicyResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	pbPolicy, diags := ConvertPolicyToPB(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.PolicyService.SetPolicy(ctx, &pb.SetPolicyRequest{
		Policy: pbPolicy,
	})
	if err != nil {
		resp.Diagnostics.AddError("Error updating policy", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *PolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state PolicyResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.PolicyService.DeletePolicy(ctx, &pb.DeletePolicyRequest{
		Id: state.ID.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("Error deleting policy", err.Error())
		return
	}

	resp.State.RemoveResource(ctx)
}

func (r *PolicyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import by ID
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
