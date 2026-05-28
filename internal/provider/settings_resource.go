package provider

import (
	"context"
	"time"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	client "github.com/pomerium/enterprise-client-go"
	"github.com/pomerium/enterprise-client-go/pb"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/sdk-go"
)

var _ interface {
	resource.Resource
	resource.ResourceWithImportState
	resource.ResourceWithModifyPlan
} = (*SettingsResource)(nil)

func NewSettingsResource() resource.Resource {
	return new(SettingsResource)
}

type SettingsResource struct {
	client *Client
}

func (r *SettingsResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_settings"
}

func (r *SettingsResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = SettingsResourceSchema
}

func (r *SettingsResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = ConfigureClient(req, resp)
}

func (r *SettingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan SettingsModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.client.ConsolidatedOrLegacy(
		func(client sdk.Client) {
			apiSettings := NewModelToAPIConverter(&resp.Diagnostics).Settings(plan)
			if resp.Diagnostics.HasError() {
				return
			}

			updateReq := newConnectRequest(&configpb.UpdateSettingsRequest{
				Settings: apiSettings,
			}, apiSettings)
			updateRes, err := client.UpdateSettings(ctx, updateReq)
			if err != nil {
				resp.Diagnostics.AddError("Error updating settings", err.Error())
				return
			}

			plan = NewAPIToModelConverter(&resp.Diagnostics).Settings(updateRes.Msg.Settings)
		},
		func(client *client.Client) {
			planSettings := NewModelToEnterpriseConverter(&resp.Diagnostics).Settings(plan)
			if resp.Diagnostics.HasError() {
				return
			}

			setReq := &pb.SetSettingsRequest{
				Settings: planSettings,
			}
			setRes, err := client.SettingsService.SetSettings(ctx, setReq)
			if err != nil {
				resp.Diagnostics.AddError("set settings", err.Error())
				return
			}

			plan = NewEnterpriseToModelConverter(&resp.Diagnostics).Settings(setRes.GetSettings(), plan.NamespaceID.ValueStringPointer())
		})...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *SettingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state SettingsModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.client.ConsolidatedOrLegacy(
		func(client sdk.Client) {
			getReq := connect.NewRequest(&configpb.GetSettingsRequest{
				For: &configpb.GetSettingsRequest_Id{
					Id: state.ID.ValueString(),
				},
			})
			getRes, err := client.GetSettings(ctx, getReq)
			if connect.CodeOf(err) == connect.CodeNotFound {
				resp.State.RemoveResource(ctx)
				return
			} else if err != nil {
				resp.Diagnostics.AddError("Error getting settings", err.Error())
				return
			}

			state = NewAPIToModelConverter(&resp.Diagnostics).Settings(getRes.Msg.Settings)
		},
		func(client *client.Client) {
			getReq := &pb.GetSettingsRequest{
				ClusterId: state.ClusterID.ValueStringPointer(),
			}
			getRes, err := client.SettingsService.GetSettings(ctx, getReq)
			if err != nil {
				resp.Diagnostics.AddError("get settings", err.Error())
				return
			}

			state = NewEnterpriseToModelConverter(&resp.Diagnostics).Settings(getRes.GetSettings(), state.NamespaceID.ValueStringPointer())
		})...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *SettingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan SettingsModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.client.ConsolidatedOrLegacy(
		func(client sdk.Client) {
			apiSettings := NewModelToAPIConverter(&resp.Diagnostics).Settings(plan)
			if resp.Diagnostics.HasError() {
				return
			}

			updateReq := newConnectRequest(&configpb.UpdateSettingsRequest{
				Settings: apiSettings,
			}, apiSettings)
			newConnectRequest(updateReq, apiSettings)
			updateRes, err := client.UpdateSettings(ctx, updateReq)
			if err != nil {
				resp.Diagnostics.AddError("Error updating settings", err.Error())
				return
			}

			plan = NewAPIToModelConverter(&resp.Diagnostics).Settings(updateRes.Msg.Settings)
		},
		func(client *client.Client) {
			planSettings := NewModelToEnterpriseConverter(&resp.Diagnostics).Settings(plan)
			if resp.Diagnostics.HasError() {
				return
			}

			setReq := &pb.SetSettingsRequest{
				Settings: planSettings,
			}
			setRes, err := client.SettingsService.SetSettings(ctx, setReq)
			if err != nil {
				resp.Diagnostics.AddError("set settings", err.Error())
				return
			}

			plan = NewEnterpriseToModelConverter(&resp.Diagnostics).Settings(setRes.GetSettings(), plan.NamespaceID.ValueStringPointer())
		})...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *SettingsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state SettingsModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.client.ConsolidatedOrLegacy(
		func(client sdk.Client) {
			apiSettings := NewModelToAPIConverter(&resp.Diagnostics).Settings(state)
			if resp.Diagnostics.HasError() {
				return
			}

			updateReq := newConnectRequest(&configpb.UpdateSettingsRequest{
				Settings: new(configpb.Settings),
			}, apiSettings)
			_, err := client.UpdateSettings(ctx, updateReq)
			if err != nil {
				resp.Diagnostics.AddError("Error updating settings", err.Error())
				return
			}
		},
		func(client *client.Client) {
			setReq := &pb.SetSettingsRequest{
				Settings: new(pb.Settings),
			}
			_, err := client.SettingsService.SetSettings(ctx, setReq)
			if err != nil {
				resp.Diagnostics.AddError("set settings", err.Error())
				return
			}
		})...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.State.RemoveResource(ctx)
}

func (r *SettingsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *SettingsResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// this is a deletion, nothing to do
	if req.Plan.Raw.IsNull() {
		return
	}

	var model SettingsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.client.ByServerType(
		func(_ sdk.CoreClient) {
			setSettingsDefaults(&model, false)
		},
		func(_ *client.Client) {
			setSettingsDefaults(&model, false)
		},
		func(_ sdk.ZeroClient) {
			setSettingsDefaults(&model, true)
		})...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.Plan.Set(ctx, model)...)
}

func setSettingsDefaults(model *SettingsModel, isZero bool) {
	if isZero {
		if model.Address.IsUnknown() {
			model.Address = types.StringValue(":443")
		}
		if model.AutoApplyChangesets.IsUnknown() {
			model.AutoApplyChangesets = types.BoolValue(true)
		}
		if model.Autocert.IsUnknown() {
			model.Autocert = types.BoolValue(false)
		}
		if model.CookieExpire.IsUnknown() {
			model.CookieExpire = timetypes.NewGoDurationValue(14 * time.Hour)
		}
		if model.CookieHTTPOnly.IsUnknown() {
			model.CookieHTTPOnly = types.BoolValue(true)
		}
		if model.CookieName.IsUnknown() {
			model.CookieName = types.StringValue("_pomerium")
		}
		if model.DefaultUpstreamTimeout.IsUnknown() {
			model.DefaultUpstreamTimeout = timetypes.NewGoDurationValue(30 * time.Second)
		}
		if model.DNSLookupFamily.IsUnknown() {
			model.DNSLookupFamily = types.StringValue("V4_PREFERRED")
		}
		if model.GRPCAddress.IsUnknown() {
			model.GRPCAddress = types.StringValue(":443")
		}
		if model.GRPCInsecure.IsUnknown() {
			model.GRPCInsecure = types.BoolValue(false)
		}
		if model.InsecureServer.IsUnknown() {
			model.InsecureServer = types.BoolValue(false)
		}
		if model.LogLevel.IsUnknown() {
			model.LogLevel = types.StringValue("info")
		}
		if model.MCPAllowedClientIDDomains.IsUnknown() {
			model.MCPAllowedClientIDDomains = types.SetValueMust(types.StringType, []attr.Value{types.StringValue("vscode.dev")})
		}
		if model.PassIdentityHeaders.IsUnknown() {
			model.PassIdentityHeaders = types.BoolValue(false)
		}
		if model.SkipXFFAppend.IsUnknown() {
			model.SkipXFFAppend = types.BoolNull()
		}
		if model.TimeoutIdle.IsUnknown() {
			model.TimeoutIdle = timetypes.NewGoDurationValue(5 * time.Minute)
		}
		if model.TimeoutRead.IsUnknown() {
			model.TimeoutRead = timetypes.NewGoDurationValue(30 * time.Second)
		}
		if model.TimeoutWrite.IsUnknown() {
			model.TimeoutWrite = timetypes.NewGoDurationNull()
		}
	} else {
		if model.Address.IsUnknown() {
			model.Address = types.StringNull()
		}
		if model.AutoApplyChangesets.IsUnknown() {
			model.AutoApplyChangesets = types.BoolNull()
		}
		if model.Autocert.IsUnknown() {
			model.Autocert = types.BoolValue(false)
		}
		if model.CookieExpire.IsUnknown() {
			model.CookieExpire = timetypes.NewGoDurationNull()
		}
		if model.CookieHTTPOnly.IsUnknown() {
			model.CookieHTTPOnly = types.BoolNull()
		}
		if model.CookieName.IsUnknown() {
			model.CookieName = types.StringNull()
		}
		if model.DefaultUpstreamTimeout.IsUnknown() {
			model.DefaultUpstreamTimeout = timetypes.NewGoDurationNull()
		}
		if model.DNSLookupFamily.IsUnknown() {
			model.DNSLookupFamily = types.StringNull()
		}
		if model.GRPCAddress.IsUnknown() {
			model.GRPCAddress = types.StringNull()
		}
		if model.GRPCInsecure.IsUnknown() {
			model.GRPCInsecure = types.BoolNull()
		}
		if model.InsecureServer.IsUnknown() {
			model.InsecureServer = types.BoolNull()
		}
		if model.LogLevel.IsUnknown() {
			model.LogLevel = types.StringNull()
		}
		if model.MCPAllowedClientIDDomains.IsUnknown() {
			model.MCPAllowedClientIDDomains = types.SetNull(types.StringType)
		}
		if model.PassIdentityHeaders.IsUnknown() {
			model.PassIdentityHeaders = types.BoolNull()
		}
		if model.SkipXFFAppend.IsUnknown() {
			model.SkipXFFAppend = types.BoolNull()
		}
		if model.TimeoutIdle.IsUnknown() {
			model.TimeoutIdle = timetypes.NewGoDurationNull()
		}
		if model.TimeoutRead.IsUnknown() {
			model.TimeoutRead = timetypes.NewGoDurationNull()
		}
		if model.TimeoutWrite.IsUnknown() {
			model.TimeoutWrite = timetypes.NewGoDurationNull()
		}
	}
}
