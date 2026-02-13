package provider

import (
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pomerium/enterprise-client-go/pb"
)

func (c *ModelToEnterpriseConverter) BearerTokenFormat(p path.Path, src types.String) *pb.BearerTokenFormat {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	switch strings.ToLower(src.ValueString()) {
	case "default":
		return pb.BearerTokenFormat(1).Enum()
	case "idp_access_token":
		return pb.BearerTokenFormat(2).Enum()
	case "idp_identity_token":
		return pb.BearerTokenFormat(3).Enum()
	default:
		c.diagnostics.AddAttributeError(p, "unknown BearerTokenFormat", fmt.Sprintf("unknown BearerTokenFormat: %s", src.ValueString()))
		return nil
	}
}

func (c *ModelToEnterpriseConverter) CodecClientType(p path.Path, src types.String) *pb.CodecClientType {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	switch strings.ToLower(src.ValueString()) {
	case "http1":
		return pb.CodecClientType(0).Enum()
	case "http2":
		return pb.CodecClientType(1).Enum()
	case "http3":
		return pb.CodecClientType(2).Enum()
	default:
		c.diagnostics.AddAttributeError(p, "unknown CodecClientType", fmt.Sprintf("unknown CodecClientType: %s", src.ValueString()))
		return nil
	}
}

func (c *ModelToEnterpriseConverter) CodecType(p path.Path, src types.String) *pb.CodecType {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	switch strings.ToLower(src.ValueString()) {
	case "auto":
		return pb.CodecType(1).Enum()
	case "http1":
		return pb.CodecType(2).Enum()
	case "http2":
		return pb.CodecType(3).Enum()
	case "http3":
		return pb.CodecType(4).Enum()
	default:
		c.diagnostics.AddAttributeError(p, "unknown CodecType", fmt.Sprintf("unknown CodecType: %s", src.ValueString()))
		return nil
	}
}

func (c *ModelToEnterpriseConverter) DeviceKind(p path.Path, src types.String) *pb.DeviceKind {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	switch strings.ToLower(src.ValueString()) {
	case "fido_u2f":
		return pb.DeviceKind(1).Enum()
	case "android":
		return pb.DeviceKind(2).Enum()
	case "apple":
		return pb.DeviceKind(3).Enum()
	case "tpm":
		return pb.DeviceKind(4).Enum()
	case "windows":
		return pb.DeviceKind(5).Enum()
	default:
		c.diagnostics.AddAttributeError(p, "unknown DeviceKind", fmt.Sprintf("unknown DeviceKind: %s", src.ValueString()))
		return nil
	}
}

func (c *ModelToEnterpriseConverter) Format(p path.Path, src types.String) *pb.Format {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	switch strings.ToLower(src.ValueString()) {
	case "pem":
		return pb.Format(1).Enum()
	default:
		c.diagnostics.AddAttributeError(p, "unknown Format", fmt.Sprintf("unknown Format: %s", src.ValueString()))
		return nil
	}
}

func (c *ModelToEnterpriseConverter) IssuerFormat(p path.Path, src types.String) *pb.IssuerFormat {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	switch strings.ToLower(src.ValueString()) {
	case "issuerhostonly":
		return pb.IssuerFormat(0).Enum()
	case "issueruri":
		return pb.IssuerFormat(1).Enum()
	default:
		c.diagnostics.AddAttributeError(p, "unknown IssuerFormat", fmt.Sprintf("unknown IssuerFormat: %s", src.ValueString()))
		return nil
	}
}

func (c *ModelToEnterpriseConverter) LoadBalancingPolicy(p path.Path, src types.String) *pb.LoadBalancingPolicy {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	switch strings.ToLower(src.ValueString()) {
	case "round_robin":
		return pb.LoadBalancingPolicy(1).Enum()
	case "maglev":
		return pb.LoadBalancingPolicy(2).Enum()
	case "random":
		return pb.LoadBalancingPolicy(3).Enum()
	case "ring_hash":
		return pb.LoadBalancingPolicy(4).Enum()
	case "least_request":
		return pb.LoadBalancingPolicy(5).Enum()
	default:
		c.diagnostics.AddAttributeError(p, "unknown LoadBalancingPolicy", fmt.Sprintf("unknown LoadBalancingPolicy: %s", src.ValueString()))
		return nil
	}
}

func (c *ModelToEnterpriseConverter) OAuth2AuthStyle(p path.Path, src types.String) *pb.OAuth2AuthStyle {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	switch strings.ToLower(src.ValueString()) {
	case "oauth2_auth_style_unspecified":
		return pb.OAuth2AuthStyle(0).Enum()
	case "oauth2_auth_style_in_params":
		return pb.OAuth2AuthStyle(1).Enum()
	case "oauth2_auth_style_in_header":
		return pb.OAuth2AuthStyle(2).Enum()
	default:
		c.diagnostics.AddAttributeError(p, "unknown OAuth2AuthStyle", fmt.Sprintf("unknown OAuth2AuthStyle: %s", src.ValueString()))
		return nil
	}
}

func (c *ModelToEnterpriseConverter) PublicKeyAlgorithm(p path.Path, src types.String) *pb.PublicKeyAlgorithm {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	switch strings.ToLower(src.ValueString()) {
	case "pka_unknown_do_not_use":
		return pb.PublicKeyAlgorithm(0).Enum()
	case "rsa":
		return pb.PublicKeyAlgorithm(1).Enum()
	case "dsa":
		return pb.PublicKeyAlgorithm(2).Enum()
	case "ecdsa":
		return pb.PublicKeyAlgorithm(3).Enum()
	case "ed25519":
		return pb.PublicKeyAlgorithm(4).Enum()
	default:
		c.diagnostics.AddAttributeError(p, "unknown PublicKeyAlgorithm", fmt.Sprintf("unknown PublicKeyAlgorithm: %s", src.ValueString()))
		return nil
	}
}

func (c *ModelToEnterpriseConverter) RedirectActionRedirectResponseCode(p path.Path, src types.String) *pb.RedirectAction_RedirectResponseCode {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	switch strings.ToLower(src.ValueString()) {
	case "moved_permanently":
		return pb.RedirectAction_RedirectResponseCode(0).Enum()
	case "found":
		return pb.RedirectAction_RedirectResponseCode(1).Enum()
	case "see_other":
		return pb.RedirectAction_RedirectResponseCode(2).Enum()
	case "temporary_redirect":
		return pb.RedirectAction_RedirectResponseCode(3).Enum()
	case "permanent_redirect":
		return pb.RedirectAction_RedirectResponseCode(4).Enum()
	default:
		c.diagnostics.AddAttributeError(p, "unknown RedirectAction_RedirectResponseCode", fmt.Sprintf("unknown RedirectAction_RedirectResponseCode: %s", src.ValueString()))
		return nil
	}
}

func (c *ModelToEnterpriseConverter) WebAuthnOptionsAttestationConveyancePreference(p path.Path, src types.String) *pb.WebAuthnOptions_AttestationConveyancePreference {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	switch strings.ToLower(src.ValueString()) {
	case "none":
		return pb.WebAuthnOptions_AttestationConveyancePreference(0).Enum()
	case "indirect":
		return pb.WebAuthnOptions_AttestationConveyancePreference(1).Enum()
	case "direct":
		return pb.WebAuthnOptions_AttestationConveyancePreference(2).Enum()
	case "enterprise":
		return pb.WebAuthnOptions_AttestationConveyancePreference(3).Enum()
	default:
		c.diagnostics.AddAttributeError(p, "unknown WebAuthnOptions_AttestationConveyancePreference", fmt.Sprintf("unknown WebAuthnOptions_AttestationConveyancePreference: %s", src.ValueString()))
		return nil
	}
}

func (c *ModelToEnterpriseConverter) WebAuthnOptionsAuthenticatorAttachment(p path.Path, src types.String) *pb.WebAuthnOptions_AuthenticatorAttachment {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	switch strings.ToLower(src.ValueString()) {
	case "platform":
		return pb.WebAuthnOptions_AuthenticatorAttachment(0).Enum()
	case "cross_platform":
		return pb.WebAuthnOptions_AuthenticatorAttachment(2).Enum()
	default:
		c.diagnostics.AddAttributeError(p, "unknown WebAuthnOptions_AuthenticatorAttachment", fmt.Sprintf("unknown WebAuthnOptions_AuthenticatorAttachment: %s", src.ValueString()))
		return nil
	}
}

func (c *ModelToEnterpriseConverter) WebAuthnOptionsPublicKeyCredentialType(p path.Path, src types.String) *pb.WebAuthnOptions_PublicKeyCredentialType {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	switch strings.ToLower(src.ValueString()) {
	case "public_key":
		return pb.WebAuthnOptions_PublicKeyCredentialType(0).Enum()
	default:
		c.diagnostics.AddAttributeError(p, "unknown WebAuthnOptions_PublicKeyCredentialType", fmt.Sprintf("unknown WebAuthnOptions_PublicKeyCredentialType: %s", src.ValueString()))
		return nil
	}
}

func (c *ModelToEnterpriseConverter) WebAuthnOptionsResidentKeyRequirement(p path.Path, src types.String) *pb.WebAuthnOptions_ResidentKeyRequirement {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	switch strings.ToLower(src.ValueString()) {
	case "resident_key_discouraged":
		return pb.WebAuthnOptions_ResidentKeyRequirement(0).Enum()
	case "resident_key_preferred":
		return pb.WebAuthnOptions_ResidentKeyRequirement(1).Enum()
	case "resident_key_required":
		return pb.WebAuthnOptions_ResidentKeyRequirement(2).Enum()
	default:
		c.diagnostics.AddAttributeError(p, "unknown WebAuthnOptions_ResidentKeyRequirement", fmt.Sprintf("unknown WebAuthnOptions_ResidentKeyRequirement: %s", src.ValueString()))
		return nil
	}
}

func (c *ModelToEnterpriseConverter) WebAuthnOptionsUserVerificationRequirement(p path.Path, src types.String) *pb.WebAuthnOptions_UserVerificationRequirement {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	switch strings.ToLower(src.ValueString()) {
	case "user_verification_discouraged":
		return pb.WebAuthnOptions_UserVerificationRequirement(0).Enum()
	case "user_verification_preferred":
		return pb.WebAuthnOptions_UserVerificationRequirement(1).Enum()
	case "user_verification_required":
		return pb.WebAuthnOptions_UserVerificationRequirement(2).Enum()
	default:
		c.diagnostics.AddAttributeError(p, "unknown WebAuthnOptions_UserVerificationRequirement", fmt.Sprintf("unknown WebAuthnOptions_UserVerificationRequirement: %s", src.ValueString()))
		return nil
	}
}
