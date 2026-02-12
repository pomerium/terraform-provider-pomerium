package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/enterprise-client-go/pb"
)

type (
	// Auth0Options are the options used for Auth0.
	Auth0Options struct {
		ClientID     types.String `tfsdk:"client_id"`
		ClientSecret types.String `tfsdk:"client_secret"`
		Domain       types.String `tfsdk:"domain"`
	}

	// AzureOptions are the options used for Azure.
	AzureOptions struct {
		ClientID     types.String `tfsdk:"client_id"`
		ClientSecret types.String `tfsdk:"client_secret"`
		DirectoryID  types.String `tfsdk:"directory_id"`
	}

	// BlobOptions are the options used for Blob.
	BlobOptions struct {
		Source types.String `tfsdk:"source"`
	}

	// CognitoOptions are the options used for Cognito.
	CognitoOptions struct {
		AccessKeyID     types.String `tfsdk:"access_key_id"`
		Region          types.String `tfsdk:"region"`
		SecretAccessKey types.String `tfsdk:"secret_access_key"`
		SessionToken    types.String `tfsdk:"session_token"`
		UserPoolID      types.String `tfsdk:"user_pool_id"`
	}

	// GitHubOptions are the options used for GitHub.
	GitHubOptions struct {
		Username            types.String `tfsdk:"username"`
		PersonalAccessToken types.String `tfsdk:"personal_access_token"`
	}

	// GitLabOptions are the options used for GitLab.
	GitLabOptions struct {
		PrivateToken types.String `tfsdk:"private_token"`
	}

	// GoogleOptions are the options used for Google.
	GoogleOptions struct {
		ImpersonateUser types.String `tfsdk:"impersonate_user"`
		JSONKey         types.String `tfsdk:"json_key"`
		URL             types.String `tfsdk:"url"`
	}

	// OktaOptions are the options used for Okta.
	OktaOptions struct {
		APIKey types.String `tfsdk:"api_key"`
		URL    types.String `tfsdk:"url"`
	}

	// OneLoginOptions are the options used for OneLogin.
	OneLoginOptions struct {
		ClientID     types.String `tfsdk:"client_id"`
		ClientSecret types.String `tfsdk:"client_secret"`
	}

	// PingOptions are the options used for Ping.
	PingOptions struct {
		ClientID      types.String `tfsdk:"client_id"`
		ClientSecret  types.String `tfsdk:"client_secret"`
		EnvironmentID types.String `tfsdk:"environment_id"`
	}
)

func IdentityProviderSettingsFromPB(
	dst *SettingsModel,
	src *pb.Settings,
	diags *diag.Diagnostics,
) {
	if src.IdentityProvider == nil {
		return
	}
	switch *src.IdentityProvider {
	case "auth0":
		PBStructToTF[Auth0Options](&dst.IdentityProviderAuth0, src.IdentityProviderOptions, diags)
	case "azure":
		PBStructToTF[AzureOptions](&dst.IdentityProviderAzure, src.IdentityProviderOptions, diags)
	case "blob":
		PBStructToTF[BlobOptions](&dst.IdentityProviderBlob, src.IdentityProviderOptions, diags)
	case "cognito":
		PBStructToTF[CognitoOptions](&dst.IdentityProviderCognito, src.IdentityProviderOptions, diags)
	case "github":
		PBStructToTF[GitHubOptions](&dst.IdentityProviderGitHub, src.IdentityProviderOptions, diags)
	case "gitlab":
		PBStructToTF[GitLabOptions](&dst.IdentityProviderGitLab, src.IdentityProviderOptions, diags)
	case "google":
		PBStructToTF[GoogleOptions](&dst.IdentityProviderGoogle, src.IdentityProviderOptions, diags)
	case "okta":
		PBStructToTF[OktaOptions](&dst.IdentityProviderOkta, src.IdentityProviderOptions, diags)
	case "onelogin":
		PBStructToTF[OneLoginOptions](&dst.IdentityProviderOneLogin, src.IdentityProviderOptions, diags)
	case "ping":
		PBStructToTF[PingOptions](&dst.IdentityProviderPing, src.IdentityProviderOptions, diags)
	default:
		diags.AddError("invalid identity provider", fmt.Sprintf("unknown identity provider %q", *src.IdentityProvider))
	}
}

func idpOptionsFromStruct[T any](
	diagnostics *diag.Diagnostics,
	src *structpb.Struct,
) types.Object {
	var obj types.Object
	PBStructToTF[T](&obj, src, diagnostics)
	return obj
}

func idpOptionsToStruct[T any](
	diagnostics *diag.Diagnostics,
	src types.Object,
) *structpb.Struct {
	var v T
	diagnostics.Append(src.As(context.Background(), &v, basetypes.ObjectAsOptions{
		UnhandledNullAsEmpty:    false,
		UnhandledUnknownAsEmpty: false,
	})...)
	if diagnostics.HasError() {
		return nil
	}
	s, err := GoStructToPB(v)
	if err != nil {
		diagnostics.AddError("failed to convert idp settings", fmt.Sprintf("type %T: %s", v, err))
	}
	return s
}
