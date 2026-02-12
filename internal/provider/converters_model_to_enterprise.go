package provider

import (
	"context"
	"encoding/base64"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	enterprise "github.com/pomerium/enterprise-client-go/pb"
)

type ModelToEnterpriseConverter struct {
	diagnostics *diag.Diagnostics
}

func NewModelToEnterpriseConverter(diagnostics *diag.Diagnostics) *ModelToEnterpriseConverter {
	return &ModelToEnterpriseConverter{
		diagnostics: diagnostics,
	}
}

func (c *ModelToEnterpriseConverter) BytesFromBase64(p path.Path, src types.String) []byte {
	if src.IsNull() || src.IsUnknown() || src.ValueString() == "" {
		return nil
	}

	dst, err := base64.StdEncoding.DecodeString(src.ValueString())
	if err != nil {
		appendAttributeDiagnostics(c.diagnostics, p, diag.NewErrorDiagnostic("invalid base64 string", err.Error()))
		return nil
	}

	return dst
}

func (c *ModelToEnterpriseConverter) CircuitBreakerThresholds(src types.Object) *enterprise.CircuitBreakerThresholds {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	attrs := src.Attributes()
	maxConnectionPools, _ := attrs["max_connection_pools"].(types.Int64)
	maxConnections, _ := attrs["max_connections"].(types.Int64)
	maxPendingRequests, _ := attrs["max_pending_requests"].(types.Int64)
	maxRequests, _ := attrs["max_requests"].(types.Int64)
	maxRetries, _ := attrs["max_retries"].(types.Int64)

	return &enterprise.CircuitBreakerThresholds{
		MaxConnectionPools: c.NullableUint32(maxConnectionPools),
		MaxConnections:     c.NullableUint32(maxConnections),
		MaxPendingRequests: c.NullableUint32(maxPendingRequests),
		MaxRequests:        c.NullableUint32(maxRequests),
		MaxRetries:         c.NullableUint32(maxRetries),
	}
}

func (c *ModelToEnterpriseConverter) Cluster(src ClusterModel) *enterprise.Cluster {
	return &enterprise.Cluster{
		CertificateAuthority:     c.BytesFromBase64(path.Root("certificate_authority_b64"), src.CertificateAuthorityB64),
		CertificateAuthorityFile: c.NullableString(src.CertificateAuthorityFile),
		CreatedAt:                nil,
		DatabrokerServiceUrl:     src.DatabrokerServiceURL.ValueString(),
		DeletedAt:                nil,
		Id:                       src.ID.ValueString(),
		InsecureSkipVerify:       c.NullableBool(src.InsecureSkipVerify),
		ModifiedAt:               nil,
		Name:                     src.Name.ValueString(),
		OriginatorId:             OriginatorID,
		OverrideCertificateName:  c.NullableString(src.OverrideCertificateName),
		SharedSecret:             c.BytesFromBase64(path.Root("shared_secret_b64"), src.SharedSecretB64),
	}
}

func (c *ModelToEnterpriseConverter) CreateKeyPairRequest(src KeyPairModel) *enterprise.CreateKeyPairRequest {
	return &enterprise.CreateKeyPairRequest{
		Certificate:  []byte(src.Certificate.ValueString()),
		Format:       enterprise.Format_PEM,
		Id:           nil, // generated
		Key:          []byte(src.Key.ValueString()),
		Name:         src.Name.ValueString(),
		NamespaceId:  src.NamespaceID.ValueString(),
		OriginatorId: OriginatorID,
	}
}

func (c *ModelToEnterpriseConverter) Duration(p path.Path, src timetypes.GoDuration) *durationpb.Duration {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	dur, diagnostics := src.ValueGoDuration()
	appendAttributeDiagnostics(c.diagnostics, p, diagnostics...)
	return durationpb.New(dur)
}

func (c *ModelToEnterpriseConverter) ExternalDataSource(src ExternalDataSourceModel) *enterprise.ExternalDataSource {
	return &enterprise.ExternalDataSource{
		AllowInsecureTls: src.AllowInsecureTLS.ValueBoolPointer(),
		ClientTlsKeyId:   src.ClientTLSKeyID.ValueStringPointer(),
		ClusterId:        src.ClusterID.ValueStringPointer(),
		ForeignKey:       src.ForeignKey.ValueString(),
		Headers:          c.StringMap(path.Root("headers"), src.Headers),
		Id:               src.ID.ValueString(),
		OriginatorId:     OriginatorID,
		PollingMaxDelay:  c.Duration(path.Root("polling_max_delay"), src.PollingMaxDelay),
		PollingMinDelay:  c.Duration(path.Root("polling_min_delay"), src.PollingMinDelay),
		RecordType:       src.RecordType.ValueString(),
		Url:              src.URL.ValueString(),
	}
}

func (c *ModelToEnterpriseConverter) JWTGroupsFilter(src types.Object) *enterprise.JwtGroupsFilter {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}
	var obj struct {
		Groups       []string `tfsdk:"groups"`
		InferFromPpl *bool    `tfsdk:"infer_from_ppl"`
	}
	c.diagnostics.Append(src.As(context.Background(), &obj, basetypes.ObjectAsOptions{
		UnhandledNullAsEmpty:    true,
		UnhandledUnknownAsEmpty: false,
	})...)
	return &enterprise.JwtGroupsFilter{
		Groups:       obj.Groups,
		InferFromPpl: obj.InferFromPpl,
	}
}

func (c *ModelToEnterpriseConverter) Namespace(src NamespaceModel) *enterprise.Namespace {
	return &enterprise.Namespace{
		ClusterId:    c.NullableString(src.ClusterID),
		CreatedAt:    nil, // not supported
		DeletedAt:    nil, // not supported
		Id:           src.ID.ValueString(),
		ModifiedAt:   nil, // not supported
		Name:         src.Name.ValueString(),
		OriginatorId: OriginatorID,
		ParentId:     *c.NullableString(src.ParentID),
		PolicyCount:  0, // not supported
		RouteCount:   0, // not supported
	}
}

func (c *ModelToEnterpriseConverter) NamespacePermission(src NamespacePermissionModel) *enterprise.NamespacePermission {
	return &enterprise.NamespacePermission{
		CreatedAt:     nil, // not supported
		Id:            src.ID.ValueString(),
		ModifiedAt:    nil, // not supported
		NamespaceId:   src.NamespaceID.ValueString(),
		NamespaceName: "", // not supported
		OriginatorId:  OriginatorID,
		Role:          src.Role.ValueString(),
		SubjectId:     src.SubjectID.ValueString(),
		SubjectType:   src.SubjectType.ValueString(),
	}
}

func (c *ModelToEnterpriseConverter) NullableBool(src types.Bool) *bool {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}
	return src.ValueBoolPointer()
}

func (c *ModelToEnterpriseConverter) NullableString(src types.String) *string {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}
	return src.ValueStringPointer()
}

func (c *ModelToEnterpriseConverter) NullableUint32(src types.Int64) *uint32 {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}
	return proto.Uint32(uint32(src.ValueInt64()))
}

func (c *ModelToEnterpriseConverter) Policy(src PolicyModel) *enterprise.Policy {
	return &enterprise.Policy{
		AllowedDomains:   nil, // not supported
		AllowedIdpClaims: nil, // not supported
		AllowedUsers:     nil, // not supported
		CreatedAt:        nil, // not supported
		DeletedAt:        nil, // not supported
		Description:      src.Description.ValueString(),
		Enforced:         src.Enforced.ValueBool(),
		Explanation:      src.Explanation.ValueString(),
		Id:               src.ID.ValueString(),
		ModifiedAt:       nil, // not supported
		Name:             src.Name.ValueString(),
		NamespaceId:      src.NamespaceID.ValueString(),
		NamespaceName:    "", // not supported
		OriginatorId:     OriginatorID,
		Ppl:              string(src.PPL.PolicyJSON),
		Rego:             c.StringSliceFromList(path.Root("rego"), src.Rego),
		Remediation:      src.Remediation.ValueString(),
		Routes:           nil, // not supported
	}
}

func (c *ModelToEnterpriseConverter) Route(src RouteModel) *enterprise.Route {
	dst := new(enterprise.Route)

	dst.Id = src.ID.ValueString()
	dst.Name = src.Name.ValueString()
	dst.From = src.From.ValueString()
	dst.NamespaceId = src.NamespaceID.ValueString()
	dst.StatName = src.StatName.ValueString()
	dst.Prefix = src.Prefix.ValueStringPointer()
	dst.Path = src.Path.ValueStringPointer()
	dst.Regex = src.Regex.ValueStringPointer()
	dst.PrefixRewrite = src.PrefixRewrite.ValueStringPointer()
	dst.RegexRewritePattern = src.RegexRewritePattern.ValueStringPointer()
	dst.RegexRewriteSubstitution = src.RegexRewriteSubstitution.ValueStringPointer()
	dst.HostRewrite = src.HostRewrite.ValueStringPointer()
	dst.HostRewriteHeader = src.HostRewriteHeader.ValueStringPointer()
	dst.HostPathRegexRewritePattern = src.HostPathRegexRewritePattern.ValueStringPointer()
	dst.HostPathRegexRewriteSubstitution = src.HostPathRegexRewriteSubstitution.ValueStringPointer()
	dst.RegexPriorityOrder = src.RegexPriorityOrder.ValueInt64Pointer()
	dst.Timeout = c.Duration(path.Root("timeout"), src.Timeout)
	dst.IdleTimeout = c.Duration(path.Root("idle_timeout"), src.IdleTimeout)
	dst.AllowWebsockets = src.AllowWebsockets.ValueBoolPointer()
	dst.AllowSpdy = src.AllowSPDY.ValueBoolPointer()
	dst.TlsSkipVerify = src.TLSSkipVerify.ValueBoolPointer()
	dst.TlsUpstreamServerName = src.TLSUpstreamServerName.ValueStringPointer()
	dst.TlsDownstreamServerName = src.TLSDownstreamServerName.ValueStringPointer()
	dst.TlsUpstreamAllowRenegotiation = src.TLSUpstreamAllowRenegotiation.ValueBoolPointer()
	dst.SetRequestHeaders = c.StringMap(path.Root("set_request_headers"), src.SetRequestHeaders)
	dst.RemoveRequestHeaders = c.StringSliceFromSet(path.Root("remove_request_headers"), src.RemoveRequestHeaders)
	dst.SetResponseHeaders = c.StringMap(path.Root("set_response_headers"), src.SetResponseHeaders)
	dst.PreserveHostHeader = src.PreserveHostHeader.ValueBoolPointer()
	dst.PassIdentityHeaders = src.PassIdentityHeaders.ValueBoolPointer()
	dst.KubernetesServiceAccountToken = src.KubernetesServiceAccountToken.ValueStringPointer()
	dst.IdpClientId = src.IDPClientID.ValueStringPointer()
	dst.IdpClientSecret = src.IDPClientSecret.ValueStringPointer()
	dst.ShowErrorDetails = src.ShowErrorDetails.ValueBool()
	dst.JwtGroupsFilter = c.JWTGroupsFilter(src.JWTGroupsFilter)
	dst.To = c.StringSliceFromSet(path.Root("to"), src.To)
	dst.PolicyIds = c.StringSliceFromSet(path.Root("policies"), src.Policies)
	dst.TlsClientKeyPairId = src.TLSClientKeyPairID.ValueStringPointer()
	dst.TlsCustomCaKeyPairId = src.TLSCustomCAKeyPairID.ValueStringPointer()
	dst.Description = src.Description.ValueStringPointer()
	dst.LogoUrl = src.LogoURL.ValueStringPointer()
	if !src.EnableGoogleCloudServerlessAuthentication.IsNull() {
		dst.EnableGoogleCloudServerlessAuthentication = src.EnableGoogleCloudServerlessAuthentication.ValueBool()
	}
	dst.KubernetesServiceAccountTokenFile = src.KubernetesServiceAccountTokenFile.ValueStringPointer()
	dst.JwtIssuerFormat = ToIssuerFormat(src.JWTIssuerFormat, c.diagnostics)
	dst.RewriteResponseHeaders = rewriteHeadersToPB(src.RewriteResponseHeaders)
	dst.BearerTokenFormat = ToBearerTokenFormat(src.BearerTokenFormat)
	dst.IdpAccessTokenAllowedAudiences = c.RouteStringList(path.Root("idp_access_token_allowed_audiences"), src.IDPAccessTokenAllowedAudiences)
	dst.OriginatorId = OriginatorID
	OptionalEnumValueToPB(&dst.LoadBalancingPolicy, src.LoadBalancingPolicy, "LOAD_BALANCING_POLICY", c.diagnostics)
	healthChecksToPB(&dst.HealthChecks, src.HealthChecks, c.diagnostics)
	dst.DependsOn = c.StringSliceFromSet(path.Root("depends_on"), src.DependsOnHosts)
	dst.CircuitBreakerThresholds = c.CircuitBreakerThresholds(src.CircuitBreakerThresholds)
	dst.HealthyPanicThreshold = src.HealthyPanicThreshold.ValueInt32Pointer()

	return dst
}

func (c *ModelToEnterpriseConverter) RouteStringList(p path.Path, src types.Set) *enterprise.Route_StringList {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}
	var values []string
	appendAttributeDiagnostics(c.diagnostics, p, src.ElementsAs(context.Background(), &values, false)...)
	return &enterprise.Route_StringList{Values: values}
}

func (c *ModelToEnterpriseConverter) ServiceAccount(src ServiceAccountModel) *enterprise.PomeriumServiceAccount {
	return &enterprise.PomeriumServiceAccount{
		AccessedAt:   nil, // not supported
		Description:  c.NullableString(src.Description),
		ExpiresAt:    c.Timestamp(path.Root("expires_at"), src.ExpiresAt),
		Id:           src.ID.ValueString(),
		IssuedAt:     nil, // not supported
		NamespaceId:  zeroToNil(src.NamespaceID.ValueString()),
		OriginatorId: proto.String(OriginatorID),
		UserId:       src.Name.ValueString(),
	}
}

func (c *ModelToEnterpriseConverter) StringMap(p path.Path, src types.Map) map[string]string {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	dst := make(map[string]string)
	appendAttributeDiagnostics(c.diagnostics, p, src.ElementsAs(context.Background(), &dst, false)...)
	return dst
}

func (c *ModelToEnterpriseConverter) StringSliceFromList(p path.Path, src types.List) []string {
	var dst []string
	appendAttributeDiagnostics(c.diagnostics, p, src.ElementsAs(context.Background(), &dst, false)...)
	return dst
}

func (c *ModelToEnterpriseConverter) StringSliceFromSet(p path.Path, src types.Set) []string {
	var dst []string
	appendAttributeDiagnostics(c.diagnostics, p, src.ElementsAs(context.Background(), &dst, false)...)
	return dst
}

func (c *ModelToEnterpriseConverter) Timestamp(p path.Path, src types.String) *timestamppb.Timestamp {
	if src.IsNull() || src.IsUnknown() || src.ValueString() == "" {
		return nil
	}

	tm, err := time.Parse(time.RFC1123, src.ValueString())
	if err != nil {
		appendAttributeDiagnostics(c.diagnostics, p, diag.NewErrorDiagnostic("error parsing timestamp", err.Error()))
		return nil
	}

	return timestamppb.New(tm)
}

func (c *ModelToEnterpriseConverter) UpdateKeyPairRequest(src KeyPairModel) *enterprise.UpdateKeyPairRequest {
	return &enterprise.UpdateKeyPairRequest{
		Certificate:  []byte(src.Certificate.ValueString()),
		Format:       enterprise.Format_PEM.Enum(),
		Id:           src.ID.ValueString(),
		Key:          []byte(src.Key.ValueString()),
		Name:         c.NullableString(src.Name),
		OriginatorId: OriginatorID,
	}
}
