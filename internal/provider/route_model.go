package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/pomerium/enterprise-client-go/pb"
)

// RouteModel represents the shared model for route resources and data sources
type RouteModel struct {
	ID                               types.String         `tfsdk:"id"`
	Name                             types.String         `tfsdk:"name"`
	From                             types.String         `tfsdk:"from"`
	To                               types.List           `tfsdk:"to"`
	NamespaceID                      types.String         `tfsdk:"namespace_id"`
	Policies                         types.List           `tfsdk:"policies"`
	StatName                         types.String         `tfsdk:"stat_name"`
	Prefix                           types.String         `tfsdk:"prefix"`
	Path                             types.String         `tfsdk:"path"`
	Regex                            types.String         `tfsdk:"regex"`
	PrefixRewrite                    types.String         `tfsdk:"prefix_rewrite"`
	RegexRewritePattern              types.String         `tfsdk:"regex_rewrite_pattern"`
	RegexRewriteSubstitution         types.String         `tfsdk:"regex_rewrite_substitution"`
	HostRewrite                      types.String         `tfsdk:"host_rewrite"`
	HostRewriteHeader                types.String         `tfsdk:"host_rewrite_header"`
	HostPathRegexRewritePattern      types.String         `tfsdk:"host_path_regex_rewrite_pattern"`
	HostPathRegexRewriteSubstitution types.String         `tfsdk:"host_path_regex_rewrite_substitution"`
	RegexPriorityOrder               types.Int64          `tfsdk:"regex_priority_order"`
	Timeout                          timetypes.GoDuration `tfsdk:"timeout"`
	IdleTimeout                      timetypes.GoDuration `tfsdk:"idle_timeout"`
	AllowWebsockets                  types.Bool           `tfsdk:"allow_websockets"`
	AllowSPDY                        types.Bool           `tfsdk:"allow_spdy"`
	TLSSkipVerify                    types.Bool           `tfsdk:"tls_skip_verify"`
	TLSUpstreamServerName            types.String         `tfsdk:"tls_upstream_server_name"`
	TLSDownstreamServerName          types.String         `tfsdk:"tls_downstream_server_name"`
	TLSUpstreamAllowRenegotiation    types.Bool           `tfsdk:"tls_upstream_allow_renegotiation"`
	SetRequestHeaders                types.Map            `tfsdk:"set_request_headers"`
	RemoveRequestHeaders             types.List           `tfsdk:"remove_request_headers"`
	SetResponseHeaders               types.Map            `tfsdk:"set_response_headers"`
	PreserveHostHeader               types.Bool           `tfsdk:"preserve_host_header"`
	PassIdentityHeaders              types.Bool           `tfsdk:"pass_identity_headers"`
	KubernetesServiceAccountToken    types.String         `tfsdk:"kubernetes_service_account_token"`
	IDPClientID                      types.String         `tfsdk:"idp_client_id"`
	IDPClientSecret                  types.String         `tfsdk:"idp_client_secret"`
	ShowErrorDetails                 types.Bool           `tfsdk:"show_error_details"`
}

func ConvertRouteToPB(
	ctx context.Context,
	src *RouteResourceModel,
) (*pb.Route, diag.Diagnostics) {
	pbRoute := new(pb.Route)
	var diagnostics diag.Diagnostics

	pbRoute.Id = src.ID.ValueString()
	pbRoute.Name = src.Name.ValueString()
	pbRoute.From = src.From.ValueString()
	pbRoute.NamespaceId = src.NamespaceID.ValueString()
	pbRoute.StatName = src.StatName.ValueString()
	pbRoute.Prefix = src.Prefix.ValueStringPointer()
	pbRoute.Path = src.Path.ValueStringPointer()
	pbRoute.Regex = src.Regex.ValueStringPointer()
	pbRoute.PrefixRewrite = src.PrefixRewrite.ValueStringPointer()
	pbRoute.RegexRewritePattern = src.RegexRewritePattern.ValueStringPointer()
	pbRoute.RegexRewriteSubstitution = src.RegexRewriteSubstitution.ValueStringPointer()
	pbRoute.HostRewrite = src.HostRewrite.ValueStringPointer()
	pbRoute.HostRewriteHeader = src.HostRewriteHeader.ValueStringPointer()
	pbRoute.HostPathRegexRewritePattern = src.HostPathRegexRewritePattern.ValueStringPointer()
	pbRoute.HostPathRegexRewriteSubstitution = src.HostPathRegexRewriteSubstitution.ValueStringPointer()
	pbRoute.RegexPriorityOrder = src.RegexPriorityOrder.ValueInt64Pointer()
	ToDuration(&pbRoute.Timeout, src.Timeout, &diagnostics)
	ToDuration(&pbRoute.IdleTimeout, src.IdleTimeout, &diagnostics)
	pbRoute.AllowWebsockets = src.AllowWebsockets.ValueBoolPointer()
	pbRoute.AllowSpdy = src.AllowSPDY.ValueBoolPointer()
	pbRoute.TlsSkipVerify = src.TLSSkipVerify.ValueBoolPointer()
	pbRoute.TlsUpstreamServerName = src.TLSUpstreamServerName.ValueStringPointer()
	pbRoute.TlsDownstreamServerName = src.TLSDownstreamServerName.ValueStringPointer()
	pbRoute.TlsUpstreamAllowRenegotiation = src.TLSUpstreamAllowRenegotiation.ValueBoolPointer()
	ToStringMap(ctx, &pbRoute.SetRequestHeaders, src.SetRequestHeaders, &diagnostics)
	ToStringSlice(ctx, &pbRoute.RemoveRequestHeaders, src.RemoveRequestHeaders, &diagnostics)
	ToStringMap(ctx, &pbRoute.SetResponseHeaders, src.SetResponseHeaders, &diagnostics)
	pbRoute.PreserveHostHeader = src.PreserveHostHeader.ValueBoolPointer()
	pbRoute.PassIdentityHeaders = src.PassIdentityHeaders.ValueBoolPointer()
	pbRoute.KubernetesServiceAccountToken = src.KubernetesServiceAccountToken.ValueStringPointer()
	pbRoute.IdpClientId = src.IDPClientID.ValueStringPointer()
	pbRoute.IdpClientSecret = src.IDPClientSecret.ValueStringPointer()
	pbRoute.ShowErrorDetails = src.ShowErrorDetails.ValueBool()

	diags := src.To.ElementsAs(ctx, &pbRoute.To, false)
	diagnostics.Append(diags...)

	if !src.Policies.IsNull() {
		diags = src.Policies.ElementsAs(ctx, &pbRoute.PolicyIds, false)
		diagnostics.Append(diags...)
	}
	return pbRoute, diagnostics
}

func ConvertRouteFromPB(
	dst *RouteResourceModel,
	src *pb.Route,
) diag.Diagnostics {
	var diagnostics diag.Diagnostics

	dst.ID = types.StringValue(src.Id)
	dst.Name = types.StringValue(src.Name)
	dst.From = types.StringValue(src.From)
	dst.NamespaceID = types.StringValue(src.NamespaceId)

	toList := make([]attr.Value, len(src.To))
	for i, v := range src.To {
		toList[i] = types.StringValue(v)
	}
	dst.To = types.ListValueMust(types.StringType, toList)

	policiesList := make([]attr.Value, len(src.PolicyIds))
	for i, v := range src.PolicyIds {
		policiesList[i] = types.StringValue(v)
	}
	dst.Policies = types.ListValueMust(types.StringType, policiesList)

	dst.StatName = types.StringValue(src.StatName)
	dst.Prefix = types.StringPointerValue(src.Prefix)
	dst.Path = types.StringPointerValue(src.Path)
	dst.Regex = types.StringPointerValue(src.Regex)
	dst.PrefixRewrite = types.StringPointerValue(src.PrefixRewrite)
	dst.RegexRewritePattern = types.StringPointerValue(src.RegexRewritePattern)
	dst.RegexRewriteSubstitution = types.StringPointerValue(src.RegexRewriteSubstitution)
	dst.HostRewrite = types.StringPointerValue(src.HostRewrite)
	dst.HostRewriteHeader = types.StringPointerValue(src.HostRewriteHeader)
	dst.HostPathRegexRewritePattern = types.StringPointerValue(src.HostPathRegexRewritePattern)
	dst.HostPathRegexRewriteSubstitution = types.StringPointerValue(src.HostPathRegexRewriteSubstitution)
	dst.RegexPriorityOrder = types.Int64PointerValue(src.RegexPriorityOrder)
	dst.Timeout = FromDuration(src.Timeout)
	dst.IdleTimeout = FromDuration(src.IdleTimeout)
	dst.AllowWebsockets = types.BoolPointerValue(src.AllowWebsockets)
	dst.AllowSPDY = types.BoolPointerValue(src.AllowSpdy)
	dst.TLSSkipVerify = types.BoolPointerValue(src.TlsSkipVerify)
	dst.TLSUpstreamServerName = types.StringPointerValue(src.TlsUpstreamServerName)
	dst.TLSDownstreamServerName = types.StringPointerValue(src.TlsDownstreamServerName)
	dst.TLSUpstreamAllowRenegotiation = types.BoolPointerValue(src.TlsUpstreamAllowRenegotiation)
	dst.SetRequestHeaders = FromStringMap(src.SetRequestHeaders)
	dst.RemoveRequestHeaders = FromStringSlice(src.RemoveRequestHeaders)
	dst.SetResponseHeaders = FromStringMap(src.SetResponseHeaders)
	dst.PreserveHostHeader = types.BoolPointerValue(src.PreserveHostHeader)
	dst.PassIdentityHeaders = types.BoolPointerValue(src.PassIdentityHeaders)
	dst.KubernetesServiceAccountToken = types.StringPointerValue(src.KubernetesServiceAccountToken)
	dst.IDPClientID = types.StringPointerValue(src.IdpClientId)
	dst.IDPClientSecret = types.StringPointerValue(src.IdpClientSecret)
	dst.ShowErrorDetails = types.BoolValue(src.ShowErrorDetails)

	return diagnostics
}
