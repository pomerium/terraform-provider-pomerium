package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pomerium/enterprise-client-go/pb"
)

func (c *EnterpriseToModelConverter) BearerTokenFormat(src *pb.BearerTokenFormat) types.String {
	if src == nil {
		return types.StringNull()
	}

	switch src.Number() {
	case 1:
		return types.StringValue("default")
	case 2:
		return types.StringValue("idp_access_token")
	case 3:
		return types.StringValue("idp_identity_token")
	default:
		return types.StringNull()
	}
}

func (c *EnterpriseToModelConverter) CodecClientType(src *pb.CodecClientType) types.String {
	if src == nil {
		return types.StringNull()
	}

	switch src.Number() {
	case 0:
		return types.StringValue("http1")
	case 1:
		return types.StringValue("http2")
	case 2:
		return types.StringValue("http3")
	default:
		return types.StringNull()
	}
}

func (c *EnterpriseToModelConverter) CodecType(src *pb.CodecType) types.String {
	if src == nil {
		return types.StringNull()
	}

	switch src.Number() {
	case 1:
		return types.StringValue("auto")
	case 2:
		return types.StringValue("http1")
	case 3:
		return types.StringValue("http2")
	case 4:
		return types.StringValue("http3")
	default:
		return types.StringNull()
	}
}

func (c *EnterpriseToModelConverter) DeviceKind(src *pb.DeviceKind) types.String {
	if src == nil {
		return types.StringNull()
	}

	switch src.Number() {
	case 1:
		return types.StringValue("fido_u2f")
	case 2:
		return types.StringValue("android")
	case 3:
		return types.StringValue("apple")
	case 4:
		return types.StringValue("tpm")
	case 5:
		return types.StringValue("windows")
	default:
		return types.StringNull()
	}
}

func (c *EnterpriseToModelConverter) Format(src *pb.Format) types.String {
	if src == nil {
		return types.StringNull()
	}

	switch src.Number() {
	case 1:
		return types.StringValue("pem")
	default:
		return types.StringNull()
	}
}

func (c *EnterpriseToModelConverter) IssuerFormat(src *pb.IssuerFormat) types.String {
	if src == nil {
		return types.StringNull()
	}

	switch src.Number() {
	case 0:
		return types.StringValue("IssuerHostOnly")
	case 1:
		return types.StringValue("IssuerURI")
	default:
		return types.StringNull()
	}
}

func (c *EnterpriseToModelConverter) LoadBalancingPolicy(src *pb.LoadBalancingPolicy) types.String {
	if src == nil {
		return types.StringNull()
	}

	switch src.Number() {
	case 1:
		return types.StringValue("round_robin")
	case 2:
		return types.StringValue("maglev")
	case 3:
		return types.StringValue("random")
	case 4:
		return types.StringValue("ring_hash")
	case 5:
		return types.StringValue("least_request")
	default:
		return types.StringNull()
	}
}

func (c *EnterpriseToModelConverter) OAuth2AuthStyle(src *pb.OAuth2AuthStyle) types.String {
	if src == nil {
		return types.StringNull()
	}

	switch src.Number() {
	case 0:
		return types.StringValue("oauth2_auth_style_unspecified")
	case 1:
		return types.StringValue("oauth2_auth_style_in_params")
	case 2:
		return types.StringValue("oauth2_auth_style_in_header")
	default:
		return types.StringNull()
	}
}

func (c *EnterpriseToModelConverter) PublicKeyAlgorithm(src *pb.PublicKeyAlgorithm) types.String {
	if src == nil {
		return types.StringNull()
	}

	switch src.Number() {
	case 0:
		return types.StringValue("pka_unknown_do_not_use")
	case 1:
		return types.StringValue("rsa")
	case 2:
		return types.StringValue("dsa")
	case 3:
		return types.StringValue("ecdsa")
	case 4:
		return types.StringValue("ed25519")
	default:
		return types.StringNull()
	}
}

func (c *EnterpriseToModelConverter) RedirectActionRedirectResponseCode(src *pb.RedirectAction_RedirectResponseCode) types.String {
	if src == nil {
		return types.StringNull()
	}

	switch src.Number() {
	case 0:
		return types.StringValue("moved_permanently")
	case 1:
		return types.StringValue("found")
	case 2:
		return types.StringValue("see_other")
	case 3:
		return types.StringValue("temporary_redirect")
	case 4:
		return types.StringValue("permanent_redirect")
	default:
		return types.StringNull()
	}
}

func (c *EnterpriseToModelConverter) WebAuthnOptionsAttestationConveyancePreference(src *pb.WebAuthnOptions_AttestationConveyancePreference) types.String {
	if src == nil {
		return types.StringNull()
	}

	switch src.Number() {
	case 0:
		return types.StringValue("none")
	case 1:
		return types.StringValue("indirect")
	case 2:
		return types.StringValue("direct")
	case 3:
		return types.StringValue("enterprise")
	default:
		return types.StringNull()
	}
}

func (c *EnterpriseToModelConverter) WebAuthnOptionsAuthenticatorAttachment(src *pb.WebAuthnOptions_AuthenticatorAttachment) types.String {
	if src == nil {
		return types.StringNull()
	}

	switch src.Number() {
	case 0:
		return types.StringValue("platform")
	case 2:
		return types.StringValue("cross_platform")
	default:
		return types.StringNull()
	}
}

func (c *EnterpriseToModelConverter) WebAuthnOptionsPublicKeyCredentialType(src *pb.WebAuthnOptions_PublicKeyCredentialType) types.String {
	if src == nil {
		return types.StringNull()
	}

	switch src.Number() {
	case 0:
		return types.StringValue("public_key")
	default:
		return types.StringNull()
	}
}

func (c *EnterpriseToModelConverter) WebAuthnOptionsResidentKeyRequirement(src *pb.WebAuthnOptions_ResidentKeyRequirement) types.String {
	if src == nil {
		return types.StringNull()
	}

	switch src.Number() {
	case 0:
		return types.StringValue("resident_key_discouraged")
	case 1:
		return types.StringValue("resident_key_preferred")
	case 2:
		return types.StringValue("resident_key_required")
	default:
		return types.StringNull()
	}
}

func (c *EnterpriseToModelConverter) WebAuthnOptionsUserVerificationRequirement(src *pb.WebAuthnOptions_UserVerificationRequirement) types.String {
	if src == nil {
		return types.StringNull()
	}

	switch src.Number() {
	case 0:
		return types.StringValue("user_verification_discouraged")
	case 1:
		return types.StringValue("user_verification_preferred")
	case 2:
		return types.StringValue("user_verification_required")
	default:
		return types.StringNull()
	}
}
