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
	AllowSPDY                                 types.Bool           `tfsdk:"allow_spdy"`
	AllowWebsockets                           types.Bool           `tfsdk:"allow_websockets"`
	BearerTokenFormat                         types.String         `tfsdk:"bearer_token_format"`
	Description                               types.String         `tfsdk:"description"`
	EnableGoogleCloudServerlessAuthentication types.Bool           `tfsdk:"enable_google_cloud_serverless_authentication"`
	From                                      types.String         `tfsdk:"from"`
	HostPathRegexRewritePattern               types.String         `tfsdk:"host_path_regex_rewrite_pattern"`
	HostPathRegexRewriteSubstitution          types.String         `tfsdk:"host_path_regex_rewrite_substitution"`
	HostRewrite                               types.String         `tfsdk:"host_rewrite"`
	HostRewriteHeader                         types.String         `tfsdk:"host_rewrite_header"`
	ID                                        types.String         `tfsdk:"id"`
	IdleTimeout                               timetypes.GoDuration `tfsdk:"idle_timeout"`
	IDPAccessTokenAllowedAudiences            types.Set            `tfsdk:"idp_access_token_allowed_audiences"`
	IDPClientID                               types.String         `tfsdk:"idp_client_id"`
	IDPClientSecret                           types.String         `tfsdk:"idp_client_secret"`
	JWTGroupsFilter                           types.Object         `tfsdk:"jwt_groups_filter"`
	JWTIssuerFormat                           types.String         `tfsdk:"jwt_issuer_format"`
	KubernetesServiceAccountToken             types.String         `tfsdk:"kubernetes_service_account_token"`
	KubernetesServiceAccountTokenFile         types.String         `tfsdk:"kubernetes_service_account_token_file"`
	LogoURL                                   types.String         `tfsdk:"logo_url"`
	Name                                      types.String         `tfsdk:"name"`
	NamespaceID                               types.String         `tfsdk:"namespace_id"`
	PassIdentityHeaders                       types.Bool           `tfsdk:"pass_identity_headers"`
	Path                                      types.String         `tfsdk:"path"`
	Policies                                  types.Set            `tfsdk:"policies"`
	Prefix                                    types.String         `tfsdk:"prefix"`
	PrefixRewrite                             types.String         `tfsdk:"prefix_rewrite"`
	PreserveHostHeader                        types.Bool           `tfsdk:"preserve_host_header"`
	Regex                                     types.String         `tfsdk:"regex"`
	RegexPriorityOrder                        types.Int64          `tfsdk:"regex_priority_order"`
	RegexRewritePattern                       types.String         `tfsdk:"regex_rewrite_pattern"`
	RegexRewriteSubstitution                  types.String         `tfsdk:"regex_rewrite_substitution"`
	RemoveRequestHeaders                      types.Set            `tfsdk:"remove_request_headers"`
	RewriteResponseHeaders                    types.Set            `tfsdk:"rewrite_response_headers"`
	SetRequestHeaders                         types.Map            `tfsdk:"set_request_headers"`
	SetResponseHeaders                        types.Map            `tfsdk:"set_response_headers"`
	ShowErrorDetails                          types.Bool           `tfsdk:"show_error_details"`
	StatName                                  types.String         `tfsdk:"stat_name"`
	Timeout                                   timetypes.GoDuration `tfsdk:"timeout"`
	TLSClientKeyPairID                        types.String         `tfsdk:"tls_client_key_pair_id"`
	TLSCustomCAKeyPairID                      types.String         `tfsdk:"tls_custom_ca_key_pair_id"`
	TLSDownstreamServerName                   types.String         `tfsdk:"tls_downstream_server_name"`
	TLSSkipVerify                             types.Bool           `tfsdk:"tls_skip_verify"`
	TLSUpstreamAllowRenegotiation             types.Bool           `tfsdk:"tls_upstream_allow_renegotiation"`
	TLSUpstreamServerName                     types.String         `tfsdk:"tls_upstream_server_name"`
	To                                        types.Set            `tfsdk:"to"`
}

var rewriteHeaderAttrTypes = map[string]attr.Type{
	"header": types.StringType,
	"value":  types.StringType,
	"prefix": types.StringType,
}

// RewriteHeaderAttrTypes returns the attribute type map for rewrite headers
func RewriteHeaderAttrTypes() map[string]attr.Type {
	return rewriteHeaderAttrTypes
}

func rewriteHeadersToPB(src types.Set) []*pb.RouteRewriteHeader {
	if (src).IsNull() {
		return nil
	}

	headers := make([]*pb.RouteRewriteHeader, 0)
	elements := src.Elements()
	for _, element := range elements {
		obj := element.(types.Object)
		prefixAttr := obj.Attributes()["prefix"].(types.String)

		header := &pb.RouteRewriteHeader{
			Header: obj.Attributes()["header"].(types.String).ValueString(),
			Value:  obj.Attributes()["value"].(types.String).ValueString(),
		}

		if !prefixAttr.IsNull() && prefixAttr.ValueString() != "" {
			header.Matcher = &pb.RouteRewriteHeader_Prefix{Prefix: prefixAttr.ValueString()}
		}

		headers = append(headers, header)
	}
	return headers
}

func rewriteHeadersFromPB(headers []*pb.RouteRewriteHeader) types.Set {
	if len(headers) == 0 {
		return types.SetNull(RewriteHeaderObjectType())
	}

	elements := make([]attr.Value, 0, len(headers))
	for _, header := range headers {
		prefix := header.GetPrefix()
		prefixValue := types.StringNull()
		if prefix != "" {
			prefixValue = types.StringValue(prefix)
		}

		attrs := map[string]attr.Value{
			"header": types.StringValue(header.Header),
			"value":  types.StringValue(header.Value),
			"prefix": prefixValue,
		}
		obj, _ := types.ObjectValue(rewriteHeaderAttrTypes, attrs)
		elements = append(elements, obj)
	}
	result, _ := types.SetValue(RewriteHeaderObjectType(), elements)
	return result
}

func RewriteHeaderObjectType() attr.Type {
	return types.ObjectType{AttrTypes: rewriteHeaderAttrTypes}
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
	ToStringSliceFromSet(ctx, &pbRoute.RemoveRequestHeaders, src.RemoveRequestHeaders, &diagnostics)
	ToStringMap(ctx, &pbRoute.SetResponseHeaders, src.SetResponseHeaders, &diagnostics)
	pbRoute.PreserveHostHeader = src.PreserveHostHeader.ValueBoolPointer()
	pbRoute.PassIdentityHeaders = src.PassIdentityHeaders.ValueBoolPointer()
	pbRoute.KubernetesServiceAccountToken = src.KubernetesServiceAccountToken.ValueStringPointer()
	pbRoute.IdpClientId = src.IDPClientID.ValueStringPointer()
	pbRoute.IdpClientSecret = src.IDPClientSecret.ValueStringPointer()
	pbRoute.ShowErrorDetails = src.ShowErrorDetails.ValueBool()
	JWTGroupsFilterToPB(ctx, &pbRoute.JwtGroupsFilter, src.JWTGroupsFilter, &diagnostics)
	ToStringSliceFromSet(ctx, &pbRoute.To, src.To, &diagnostics)
	ToStringSliceFromSet(ctx, &pbRoute.PolicyIds, src.Policies, &diagnostics)
	pbRoute.TlsClientKeyPairId = src.TLSClientKeyPairID.ValueStringPointer()
	pbRoute.TlsCustomCaKeyPairId = src.TLSCustomCAKeyPairID.ValueStringPointer()
	pbRoute.Description = src.Description.ValueStringPointer()
	pbRoute.LogoUrl = src.LogoURL.ValueStringPointer()
	if !src.EnableGoogleCloudServerlessAuthentication.IsNull() {
		pbRoute.EnableGoogleCloudServerlessAuthentication = src.EnableGoogleCloudServerlessAuthentication.ValueBool()
	}
	pbRoute.KubernetesServiceAccountTokenFile = src.KubernetesServiceAccountTokenFile.ValueStringPointer()
	EnumValueToPBWithDefault(&pbRoute.JwtIssuerFormat, src.JWTIssuerFormat, pb.IssuerFormat_IssuerHostOnly, &diagnostics)
	pbRoute.RewriteResponseHeaders = rewriteHeadersToPB(src.RewriteResponseHeaders)
	pbRoute.BearerTokenFormat = ToBearerTokenFormat(src.BearerTokenFormat)
	ToRouteStringList(ctx, &pbRoute.IdpAccessTokenAllowedAudiences, src.IDPAccessTokenAllowedAudiences, &diagnostics)
	pbRoute.OriginatorId = originatorID

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
	dst.To = FromStringSliceToSet(src.To)
	dst.Policies = FromStringSliceToSet(StringSliceExclude(src.PolicyIds, src.EnforcedPolicyIds))
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
	dst.RemoveRequestHeaders = FromStringSliceToSet(src.RemoveRequestHeaders)
	dst.SetResponseHeaders = FromStringMap(src.SetResponseHeaders)
	dst.PreserveHostHeader = types.BoolPointerValue(src.PreserveHostHeader)
	dst.PassIdentityHeaders = types.BoolPointerValue(src.PassIdentityHeaders)
	dst.KubernetesServiceAccountToken = types.StringPointerValue(src.KubernetesServiceAccountToken)
	dst.IDPClientID = types.StringPointerValue(src.IdpClientId)
	dst.IDPClientSecret = types.StringPointerValue(src.IdpClientSecret)
	dst.ShowErrorDetails = types.BoolValue(src.ShowErrorDetails)
	JWTGroupsFilterFromPB(&dst.JWTGroupsFilter, src.JwtGroupsFilter)
	dst.TLSClientKeyPairID = types.StringPointerValue(src.TlsClientKeyPairId)
	dst.TLSCustomCAKeyPairID = types.StringPointerValue(src.TlsCustomCaKeyPairId)
	dst.Description = types.StringPointerValue(src.Description)
	dst.LogoURL = types.StringPointerValue(src.LogoUrl)
	dst.EnableGoogleCloudServerlessAuthentication = types.BoolNull()
	if src.EnableGoogleCloudServerlessAuthentication {
		dst.EnableGoogleCloudServerlessAuthentication = types.BoolValue(true)
	}
	dst.KubernetesServiceAccountTokenFile = types.StringPointerValue(src.KubernetesServiceAccountTokenFile)
	dst.JWTIssuerFormat = EnumValueFromPB(src.JwtIssuerFormat)
	dst.RewriteResponseHeaders = rewriteHeadersFromPB(src.RewriteResponseHeaders)
	dst.BearerTokenFormat = FromBearerTokenFormat(src.BearerTokenFormat)
	dst.IDPAccessTokenAllowedAudiences = FromStringList(src.IdpAccessTokenAllowedAudiences)
	return diagnostics
}
