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
	var state PolicyResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	modelToCore := newModelToCoreConverter()
	createReq := modelToCore.CreatePolicyRequest(&state)
	resp.Diagnostics.Append(modelToCore.diagnostics...)
	if resp.Diagnostics.HasError() {
		return
	}

	createRes, err := r.client.shared.CreatePolicy(ctx, createReq)
	if err != nil {
		resp.Diagnostics.AddError("Error creating policy", err.Error())
		return
	}

	coreToModel := newCoreToModelConverter()
	state = *coreToModel.Policy(createRes.Msg.GetPolicy())
	resp.Diagnostics.Append(coreToModel.diagnostics...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Trace(ctx, "Created a policy", map[string]interface{}{
		"id":   state.ID.ValueString(),
		"name": state.Name.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *PolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state PolicyResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	getRes, err := r.client.shared.GetPolicy(ctx, connect.NewRequest(&pomerium.GetPolicyRequest{
		Id: state.ID.ValueString(),
	}))
	if err != nil {
		if status.Code(err) == codes.NotFound {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error reading policy", err.Error())
		return
	}

	coreToModel := newCoreToModelConverter()
	state = *coreToModel.Policy(getRes.Msg.GetPolicy())
	resp.Diagnostics.Append(coreToModel.diagnostics...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *PolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var state PolicyResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	modelToCore := newModelToCoreConverter()
	updateReq := modelToCore.UpdatePolicyRequest(&state)
	resp.Diagnostics.Append(modelToCore.diagnostics...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateRes, err := r.client.shared.UpdatePolicy(ctx, updateReq)
	if err != nil {
		resp.Diagnostics.AddError("Error updating policy", err.Error())
		return
	}

	coreToModel := newCoreToModelConverter()
	state = *coreToModel.Policy(updateRes.Msg.GetPolicy())
	resp.Diagnostics.Append(coreToModel.diagnostics...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *PolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state PolicyResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.shared.DeletePolicy(ctx, connect.NewRequest(&pomerium.DeletePolicyRequest{
		Id: state.ID.ValueString(),
	}))
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
