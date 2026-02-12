package provider

import (
	"encoding/base64"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"google.golang.org/protobuf/types/known/timestamppb"

	enterprise "github.com/pomerium/enterprise-client-go/pb"
)

type EnterpriseToModelConverter struct {
	diagnostics *diag.Diagnostics
}

func NewEnterpriseToModelConverter(diagnostics *diag.Diagnostics) *EnterpriseToModelConverter {
	return &EnterpriseToModelConverter{
		diagnostics: diagnostics,
	}
}

func (c *EnterpriseToModelConverter) Base64String(src []byte) types.String {
	if len(src) == 0 {
		return types.StringNull()
	}
	return types.StringValue(base64.StdEncoding.EncodeToString(src))
}

func (c *EnterpriseToModelConverter) CircuitBreakerThresholds(src *enterprise.CircuitBreakerThresholds) types.Object {
	if src == nil {
		return types.ObjectNull(CircuitBreakerThresholdsAttributes)
	}

	dst, diagnostics := types.ObjectValue(CircuitBreakerThresholdsAttributes, map[string]attr.Value{
		"max_connections":      Int64PointerValue(src.MaxConnections),
		"max_pending_requests": Int64PointerValue(src.MaxPendingRequests),
		"max_requests":         Int64PointerValue(src.MaxRequests),
		"max_retries":          Int64PointerValue(src.MaxRetries),
		"max_connection_pools": Int64PointerValue(src.MaxConnectionPools),
	})
	c.diagnostics.Append(diagnostics...)
	return dst
}

func (c *EnterpriseToModelConverter) Cluster(src *enterprise.Cluster, namespace *enterprise.Namespace) ClusterModel {
	return ClusterModel{
		CertificateAuthorityB64:  c.Base64String(src.CertificateAuthority),
		CertificateAuthorityFile: types.StringPointerValue(src.CertificateAuthorityFile),
		DatabrokerServiceURL:     types.StringValue(src.DatabrokerServiceUrl),
		ID:                       types.StringValue(src.Id),
		InsecureSkipVerify:       types.BoolPointerValue(src.InsecureSkipVerify),
		Name:                     types.StringValue(src.Name),
		NamespaceID:              types.StringPointerValue(zeroToNil(namespace.GetId())),
		OverrideCertificateName:  types.StringPointerValue(src.OverrideCertificateName),
		ParentNamespaceID:        types.StringPointerValue(zeroToNil(namespace.GetParentId())),
		SharedSecretB64:          c.Base64String(src.SharedSecret),
	}
}

func (c *EnterpriseToModelConverter) ExternalDataSource(src *enterprise.ExternalDataSource) ExternalDataSourceModel {
	return ExternalDataSourceModel{
		AllowInsecureTLS: types.BoolPointerValue(src.AllowInsecureTls),
		ClientTLSKeyID:   types.StringPointerValue(src.ClientTlsKeyId),
		ClusterID:        types.StringPointerValue(src.ClusterId),
		ForeignKey:       types.StringValue(src.ForeignKey),
		Headers:          FromStringMap(src.Headers),
		ID:               types.StringValue(src.Id),
		PollingMaxDelay:  FromDuration(src.PollingMaxDelay),
		PollingMinDelay:  FromDuration(src.PollingMinDelay),
		RecordType:       types.StringValue(src.RecordType),
		URL:              types.StringValue(src.Url),
	}
}

func (c *EnterpriseToModelConverter) JWTGroupsFilter(src *enterprise.JwtGroupsFilter) types.Object {
	if src == nil {
		return types.ObjectNull(JWTGroupsFilterSchemaAttributes)
	}

	attrs := make(map[string]attr.Value)
	if src.Groups == nil {
		attrs["groups"] = types.SetNull(types.StringType)
	} else {
		var vals []attr.Value
		for _, v := range src.Groups {
			vals = append(vals, types.StringValue(v))
		}
		attrs["groups"] = types.SetValueMust(types.StringType, vals)
	}

	attrs["infer_from_ppl"] = types.BoolPointerValue(src.InferFromPpl)

	return types.ObjectValueMust(JWTGroupsFilterSchemaAttributes, attrs)
}

func (c *EnterpriseToModelConverter) Namespace(src *enterprise.Namespace) NamespaceModel {
	return NamespaceModel{
		ClusterID: types.StringPointerValue(src.ClusterId),
		ID:        types.StringValue(src.Id),
		Name:      types.StringValue(src.Name),
		ParentID:  types.StringPointerValue(zeroToNil(src.ParentId)),
	}
}

func (c *EnterpriseToModelConverter) NamespacePermission(src *enterprise.NamespacePermission) NamespacePermissionModel {
	return NamespacePermissionModel{
		ID:          types.StringValue(src.Id),
		NamespaceID: types.StringValue(src.NamespaceId),
		Role:        types.StringValue(src.Role),
		SubjectID:   types.StringValue(src.SubjectId),
		SubjectType: types.StringValue(src.SubjectType),
	}
}

func (c *EnterpriseToModelConverter) Policy(src *enterprise.Policy) PolicyModel {
	ppl, err := PolicyLanguageType{}.Parse(types.StringValue(src.Ppl))
	if err != nil {
		c.diagnostics.AddError("error parsing ppl", err.Error())
	}

	return PolicyModel{
		Description: types.StringValue(src.Description),
		Enforced:    types.BoolValue(src.Enforced),
		Explanation: types.StringValue(src.Explanation),
		ID:          types.StringValue(src.Id),
		Name:        types.StringValue(src.Name),
		NamespaceID: types.StringValue(src.NamespaceId),
		PPL:         ppl,
		Rego:        FromStringSliceToList(src.Rego),
		Remediation: types.StringValue(src.Remediation),
	}
}

func (c *EnterpriseToModelConverter) Route(src *enterprise.Route) RouteModel {
	dst := RouteModel{}

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
	dst.JWTGroupsFilter = c.JWTGroupsFilter(src.JwtGroupsFilter)
	dst.TLSClientKeyPairID = types.StringPointerValue(src.TlsClientKeyPairId)
	dst.TLSCustomCAKeyPairID = types.StringPointerValue(src.TlsCustomCaKeyPairId)
	dst.Description = types.StringPointerValue(src.Description)
	dst.LogoURL = types.StringPointerValue(src.LogoUrl)
	dst.EnableGoogleCloudServerlessAuthentication = types.BoolNull()
	if src.EnableGoogleCloudServerlessAuthentication {
		dst.EnableGoogleCloudServerlessAuthentication = types.BoolValue(true)
	}
	dst.KubernetesServiceAccountTokenFile = types.StringPointerValue(src.KubernetesServiceAccountTokenFile)
	dst.JWTIssuerFormat = FromIssuerFormat(src.JwtIssuerFormat)
	dst.RewriteResponseHeaders = rewriteHeadersFromPB(src.RewriteResponseHeaders)
	dst.BearerTokenFormat = FromBearerTokenFormat(src.BearerTokenFormat)
	dst.IDPAccessTokenAllowedAudiences = FromStringList(src.IdpAccessTokenAllowedAudiences)
	dst.LoadBalancingPolicy = OptionalEnumValueFromPB(src.LoadBalancingPolicy, "LOAD_BALANCING_POLICY")
	healthChecksFromPB(&dst.HealthChecks, src.HealthChecks, c.diagnostics)
	dst.DependsOnHosts = FromStringSliceToSet(src.DependsOn)
	dst.CircuitBreakerThresholds = c.CircuitBreakerThresholds(src.CircuitBreakerThresholds)
	dst.HealthyPanicThreshold = types.Int32PointerValue(src.HealthyPanicThreshold)

	return dst
}

func (c *EnterpriseToModelConverter) ServiceAccount(src *enterprise.PomeriumServiceAccount) ServiceAccountModel {
	return ServiceAccountModel{
		Description: types.StringPointerValue(src.Description),
		ExpiresAt:   c.Timestamp(src.ExpiresAt),
		ID:          types.StringValue(src.Id),
		Name:        types.StringValue(strings.TrimSuffix(src.GetUserId(), "@"+src.GetNamespaceId()+".pomerium")),
		NamespaceID: types.StringPointerValue(src.NamespaceId),
		UserID:      types.StringValue(src.UserId),
	}
}

func (c *EnterpriseToModelConverter) Timestamp(src *timestamppb.Timestamp) types.String {
	if src == nil || src.AsTime().IsZero() {
		return types.StringNull()
	}

	return types.StringValue(src.AsTime().Format(time.RFC3339))
}
