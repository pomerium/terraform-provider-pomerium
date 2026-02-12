package provider

import (
	"encoding/base64"

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
	CircuitBreakerThresholds                  types.Object         `tfsdk:"circuit_breaker_thresholds"`
	DependsOnHosts                            types.Set            `tfsdk:"depends_on_hosts"`
	Description                               types.String         `tfsdk:"description"`
	EnableGoogleCloudServerlessAuthentication types.Bool           `tfsdk:"enable_google_cloud_serverless_authentication"`
	From                                      types.String         `tfsdk:"from"`
	HealthChecks                              types.Set            `tfsdk:"health_checks"`
	HealthyPanicThreshold                     types.Int32          `tfsdk:"healthy_panic_threshold"`
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
	LoadBalancingPolicy                       types.String         `tfsdk:"load_balancing_policy"`
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

// Type definitions for health check objects
func HealthCheckPayloadObjectType() types.ObjectType {
	return types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"text":       types.StringType,
			"binary_b64": types.StringType,
		},
	}
}

func Int64RangeObjectType() types.ObjectType {
	return types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"start": types.Int64Type,
			"end":   types.Int64Type,
		},
	}
}

func HTTPHealthCheckObjectType() types.ObjectType {
	return types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"host":               types.StringType,
			"path":               types.StringType,
			"expected_statuses":  types.SetType{ElemType: Int64RangeObjectType()},
			"retriable_statuses": types.SetType{ElemType: Int64RangeObjectType()},
			"codec_client_type":  types.StringType,
		},
	}
}

func TCPHealthCheckObjectType() types.ObjectType {
	return types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"send":    HealthCheckPayloadObjectType(),
			"receive": types.SetType{ElemType: HealthCheckPayloadObjectType()},
		},
	}
}

func GrpcHealthCheckObjectType() types.ObjectType {
	return types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"service_name": types.StringType,
			"authority":    types.StringType,
		},
	}
}

func HealthCheckObjectType() types.ObjectType {
	return types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"timeout":                 timetypes.GoDurationType{},
			"interval":                timetypes.GoDurationType{},
			"initial_jitter":          timetypes.GoDurationType{},
			"interval_jitter":         timetypes.GoDurationType{},
			"interval_jitter_percent": types.Int64Type,
			"unhealthy_threshold":     types.Int64Type,
			"healthy_threshold":       types.Int64Type,
			"http_health_check":       HTTPHealthCheckObjectType(),
			"tcp_health_check":        TCPHealthCheckObjectType(),
			"grpc_health_check":       GrpcHealthCheckObjectType(),
		},
	}
}

// Convert health check payload between Terraform and protobuf
func payloadFromPB(payload *pb.HealthCheck_Payload) (types.Object, diag.Diagnostics) {
	var diags diag.Diagnostics

	if payload == nil {
		return types.ObjectNull(HealthCheckPayloadObjectType().AttrTypes), diags
	}

	attrs := map[string]attr.Value{
		"text":       types.StringNull(),
		"binary_b64": types.StringNull(),
	}

	switch p := payload.GetPayload().(type) {
	case *pb.HealthCheck_Payload_Text:
		attrs["text"] = types.StringValue(p.Text)
	case *pb.HealthCheck_Payload_Binary:
		attrs["binary_b64"] = types.StringValue(base64.StdEncoding.EncodeToString(p.Binary))
	}

	return types.ObjectValue(HealthCheckPayloadObjectType().AttrTypes, attrs)
}

func payloadToPB(obj types.Object) (*pb.HealthCheck_Payload, diag.Diagnostics) {
	var diags diag.Diagnostics

	if obj.IsNull() {
		return nil, diags
	}

	attrs := obj.Attributes()
	payload := &pb.HealthCheck_Payload{}

	text := attrs["text"].(types.String)
	binaryB64 := attrs["binary_b64"].(types.String)

	if !text.IsNull() {
		payload.Payload = &pb.HealthCheck_Payload_Text{
			Text: text.ValueString(),
		}
	} else if !binaryB64.IsNull() {
		binaryData, err := base64.StdEncoding.DecodeString(binaryB64.ValueString())
		if err != nil {
			diags.AddError("Invalid base64 data", "Could not decode base64 binary payload: "+err.Error())
			return nil, diags
		}
		payload.Payload = &pb.HealthCheck_Payload_Binary{
			Binary: binaryData,
		}
	}

	return payload, diags
}

// Convert Int64Range between Terraform and protobuf
func int64RangeFromPB(r *pb.Int64Range) (types.Object, diag.Diagnostics) {
	var diags diag.Diagnostics

	if r == nil {
		return types.ObjectNull(Int64RangeObjectType().AttrTypes), diags
	}

	attrs := map[string]attr.Value{
		"start": types.Int64Value(r.Start),
		"end":   types.Int64Value(r.End),
	}

	return types.ObjectValue(Int64RangeObjectType().AttrTypes, attrs)
}

func int64RangeToPB(obj types.Object) (*pb.Int64Range, diag.Diagnostics) {
	var diags diag.Diagnostics

	if obj.IsNull() {
		return nil, diags
	}

	attrs := obj.Attributes()
	r := &pb.Int64Range{
		Start: attrs["start"].(types.Int64).ValueInt64(),
		End:   attrs["end"].(types.Int64).ValueInt64(),
	}

	return r, diags
}
