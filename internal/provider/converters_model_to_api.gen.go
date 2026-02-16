package provider

import (
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pomerium/sdk-go/proto/pomerium"
)

func (c *ModelToAPIConverter) BearerTokenFormat(p path.Path, src types.String) *pomerium.BearerTokenFormat {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	switch strings.ToLower(src.ValueString()) {
	case "default":
		return pomerium.BearerTokenFormat(1).Enum()
	case "idp_access_token":
		return pomerium.BearerTokenFormat(2).Enum()
	case "idp_identity_token":
		return pomerium.BearerTokenFormat(3).Enum()
	default:
		c.diagnostics.AddAttributeError(p, "unknown BearerTokenFormat", fmt.Sprintf("unknown BearerTokenFormat: %s", src.ValueString()))
		return nil
	}
}

func (c *ModelToAPIConverter) CodecType(p path.Path, src types.String) *pomerium.CodecType {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	switch strings.ToLower(src.ValueString()) {
	case "auto":
		return pomerium.CodecType(0).Enum()
	case "http1":
		return pomerium.CodecType(1).Enum()
	case "http2":
		return pomerium.CodecType(2).Enum()
	case "http3":
		return pomerium.CodecType(3).Enum()
	default:
		c.diagnostics.AddAttributeError(p, "unknown CodecType", fmt.Sprintf("unknown CodecType: %s", src.ValueString()))
		return nil
	}
}

func (c *ModelToAPIConverter) HealthCheckCodecClientType(p path.Path, src types.String) *pomerium.HealthCheck_CodecClientType {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	switch strings.ToLower(src.ValueString()) {
	case "http1":
		return pomerium.HealthCheck_CodecClientType(0).Enum()
	case "http2":
		return pomerium.HealthCheck_CodecClientType(1).Enum()
	case "http3":
		return pomerium.HealthCheck_CodecClientType(2).Enum()
	default:
		c.diagnostics.AddAttributeError(p, "unknown HealthCheck_CodecClientType", fmt.Sprintf("unknown HealthCheck_CodecClientType: %s", src.ValueString()))
		return nil
	}
}

func (c *ModelToAPIConverter) HealthCheckHealthStatus(p path.Path, src types.String) *pomerium.HealthCheck_HealthStatus {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	switch strings.ToLower(src.ValueString()) {
	case "healthy":
		return pomerium.HealthCheck_HealthStatus(1).Enum()
	case "unhealthy":
		return pomerium.HealthCheck_HealthStatus(2).Enum()
	case "draining":
		return pomerium.HealthCheck_HealthStatus(3).Enum()
	case "timeout":
		return pomerium.HealthCheck_HealthStatus(4).Enum()
	case "degraded":
		return pomerium.HealthCheck_HealthStatus(5).Enum()
	default:
		c.diagnostics.AddAttributeError(p, "unknown HealthCheck_HealthStatus", fmt.Sprintf("unknown HealthCheck_HealthStatus: %s", src.ValueString()))
		return nil
	}
}

func (c *ModelToAPIConverter) IssuerFormat(p path.Path, src types.String) *pomerium.IssuerFormat {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	switch strings.ToLower(src.ValueString()) {
	case "issuerhostonly":
		return pomerium.IssuerFormat(0).Enum()
	case "issueruri":
		return pomerium.IssuerFormat(1).Enum()
	default:
		c.diagnostics.AddAttributeError(p, "unknown IssuerFormat", fmt.Sprintf("unknown IssuerFormat: %s", src.ValueString()))
		return nil
	}
}

func (c *ModelToAPIConverter) KeyPairOrigin(p path.Path, src types.String) *pomerium.KeyPairOrigin {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	switch strings.ToLower(src.ValueString()) {
	case "user":
		return pomerium.KeyPairOrigin(1).Enum()
	case "system":
		return pomerium.KeyPairOrigin(2).Enum()
	default:
		c.diagnostics.AddAttributeError(p, "unknown KeyPairOrigin", fmt.Sprintf("unknown KeyPairOrigin: %s", src.ValueString()))
		return nil
	}
}

func (c *ModelToAPIConverter) KeyPairStatus(p path.Path, src types.String) *pomerium.KeyPairStatus {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	switch strings.ToLower(src.ValueString()) {
	case "ready":
		return pomerium.KeyPairStatus(1).Enum()
	case "pending":
		return pomerium.KeyPairStatus(2).Enum()
	default:
		c.diagnostics.AddAttributeError(p, "unknown KeyPairStatus", fmt.Sprintf("unknown KeyPairStatus: %s", src.ValueString()))
		return nil
	}
}

func (c *ModelToAPIConverter) LoadBalancingPolicy(p path.Path, src types.String) *pomerium.LoadBalancingPolicy {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	switch strings.ToLower(src.ValueString()) {
	case "round_robin":
		return pomerium.LoadBalancingPolicy(1).Enum()
	case "maglev":
		return pomerium.LoadBalancingPolicy(2).Enum()
	case "random":
		return pomerium.LoadBalancingPolicy(3).Enum()
	case "ring_hash":
		return pomerium.LoadBalancingPolicy(4).Enum()
	case "least_request":
		return pomerium.LoadBalancingPolicy(5).Enum()
	default:
		c.diagnostics.AddAttributeError(p, "unknown LoadBalancingPolicy", fmt.Sprintf("unknown LoadBalancingPolicy: %s", src.ValueString()))
		return nil
	}
}

func (c *ModelToAPIConverter) MtlsEnforcementMode(p path.Path, src types.String) *pomerium.MtlsEnforcementMode {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	switch strings.ToLower(src.ValueString()) {
	case "policy":
		return pomerium.MtlsEnforcementMode(1).Enum()
	case "policy_with_default_deny":
		return pomerium.MtlsEnforcementMode(2).Enum()
	case "reject_connection":
		return pomerium.MtlsEnforcementMode(3).Enum()
	default:
		c.diagnostics.AddAttributeError(p, "unknown MtlsEnforcementMode", fmt.Sprintf("unknown MtlsEnforcementMode: %s", src.ValueString()))
		return nil
	}
}

func (c *ModelToAPIConverter) OAuth2AuthStyle(p path.Path, src types.String) *pomerium.OAuth2AuthStyle {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	switch strings.ToLower(src.ValueString()) {
	case "oauth2_auth_style_unspecified":
		return pomerium.OAuth2AuthStyle(0).Enum()
	case "oauth2_auth_style_in_params":
		return pomerium.OAuth2AuthStyle(1).Enum()
	case "oauth2_auth_style_in_header":
		return pomerium.OAuth2AuthStyle(2).Enum()
	default:
		c.diagnostics.AddAttributeError(p, "unknown OAuth2AuthStyle", fmt.Sprintf("unknown OAuth2AuthStyle: %s", src.ValueString()))
		return nil
	}
}

func (c *ModelToAPIConverter) SANMatcherSANType(p path.Path, src types.String) *pomerium.SANMatcher_SANType {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	switch strings.ToLower(src.ValueString()) {
	case "email":
		return pomerium.SANMatcher_SANType(1).Enum()
	case "dns":
		return pomerium.SANMatcher_SANType(2).Enum()
	case "uri":
		return pomerium.SANMatcher_SANType(3).Enum()
	case "ip_address":
		return pomerium.SANMatcher_SANType(4).Enum()
	case "user_principal_name":
		return pomerium.SANMatcher_SANType(5).Enum()
	default:
		c.diagnostics.AddAttributeError(p, "unknown SANMatcher_SANType", fmt.Sprintf("unknown SANMatcher_SANType: %s", src.ValueString()))
		return nil
	}
}

func (c *ModelToAPIConverter) ServerType(p path.Path, src types.String) *pomerium.ServerType {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	switch strings.ToLower(src.ValueString()) {
	case "core":
		return pomerium.ServerType(1).Enum()
	case "enterprise":
		return pomerium.ServerType(2).Enum()
	case "zero":
		return pomerium.ServerType(3).Enum()
	default:
		c.diagnostics.AddAttributeError(p, "unknown ServerType", fmt.Sprintf("unknown ServerType: %s", src.ValueString()))
		return nil
	}
}
