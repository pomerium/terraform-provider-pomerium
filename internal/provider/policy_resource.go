package provider

import (
	"context"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	client "github.com/pomerium/enterprise-client-go"
	"github.com/pomerium/enterprise-client-go/pb"
	"github.com/pomerium/sdk-go"
	"github.com/pomerium/sdk-go/proto/pomerium"
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
	client *Client
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
				Computed:    true,
				Default:     stringdefault.StaticString(""),
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
				Computed:    true,
				Default:     booldefault.StaticBool(false),
			},
			"explanation": schema.StringAttribute{
				Description: "Explanation of the policy.",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString(""),
			},
			"remediation": schema.StringAttribute{
				Description: "Remediation of the policy.",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString(""),
			},
		},
	}
}

func (r *PolicyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = ConfigureClient(req, resp)
}

func (r *PolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan PolicyResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.client.ConsolidatedOrLegacy(ctx,
		func(client sdk.Client) {
			apiPolicy := NewModelToAPIConverter(&resp.Diagnostics).Policy(plan)
			if resp.Diagnostics.HasError() {
				return
			}

			createReq := connect.NewRequest(&pomerium.CreatePolicyRequest{
				Policy: apiPolicy,
			})
			createRes, err := client.CreatePolicy(ctx, createReq)
			if err != nil {
				resp.Diagnostics.AddError("Error creating policy", err.Error())
				return
			}

			plan = NewAPIToModelConverter(&resp.Diagnostics).Policy(createRes.Msg.Policy)
		},
		func(client *client.Client) {
			pbPolicy := NewModelToEnterpriseConverter(&resp.Diagnostics).Policy(plan)
			if resp.Diagnostics.HasError() {
				return
			}

			setReq := &pb.SetPolicyRequest{
				Policy: pbPolicy,
			}
			setRes, err := client.PolicyService.SetPolicy(ctx, setReq)
			if err != nil {
				resp.Diagnostics.AddError("Error creating policy", err.Error())
				return
			}

			plan.ID = types.StringValue(setRes.Policy.Id)
		})...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Trace(ctx, "Created a policy", map[string]any{
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

	resp.Diagnostics.Append(r.client.EnterpriseOnly(ctx, func(client *client.Client) {
		getReq := &pb.GetPolicyRequest{
			Id: state.ID.ValueString(),
		}
		getRes, err := client.PolicyService.GetPolicy(ctx, getReq)
		if err != nil {
			if status.Code(err) == codes.NotFound {
				resp.State.RemoveResource(ctx)
				return
			}
			resp.Diagnostics.AddError("Error reading policy", err.Error())
			return
		}

		state = NewEnterpriseToModelConverter(&resp.Diagnostics).Policy(getRes.GetPolicy())
	})...)
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

	resp.Diagnostics.Append(r.client.EnterpriseOnly(ctx, func(client *client.Client) {
		pbPolicy := NewModelToEnterpriseConverter(&resp.Diagnostics).Policy(plan)
		if resp.Diagnostics.HasError() {
			return
		}

		setReq := &pb.SetPolicyRequest{
			Policy: pbPolicy,
		}
		_, err := client.PolicyService.SetPolicy(ctx, setReq)
		if err != nil {
			resp.Diagnostics.AddError("Error updating policy", err.Error())
			return
		}
	})...)
	if resp.Diagnostics.HasError() {
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

	resp.Diagnostics.Append(r.client.EnterpriseOnly(ctx, func(client *client.Client) {
		deleteReq := &pb.DeletePolicyRequest{
			Id: state.ID.ValueString(),
		}
		_, err := client.PolicyService.DeletePolicy(ctx, deleteReq)
		if err != nil {
			resp.Diagnostics.AddError("Error deleting policy", err.Error())
			return
		}
	})...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.State.RemoveResource(ctx)
}

func (r *PolicyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import by ID
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
