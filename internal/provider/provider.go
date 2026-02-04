package provider

import (
	"context"
	"crypto/tls"
	_ "embed" // embed is used to embed the provider description
	"net/url"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ provider.Provider              = &PomeriumProvider{}
	_ provider.ProviderWithFunctions = &PomeriumProvider{}

	//go:embed help/provider.md
	providerDescription string
)

// PomeriumProvider defines the provider implementation.
type PomeriumProvider struct {
	// version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance
	// testing.
	version string
}

// PomeriumProviderModel describes the provider data model.
type PomeriumProviderModel struct {
	APIURL                types.String `tfsdk:"api_url"`
	ServiceAccountToken   types.String `tfsdk:"service_account_token"`
	SharedSecretB64       types.String `tfsdk:"shared_secret_b64"`
	TLSInsecureSkipVerify types.Bool   `tfsdk:"tls_insecure_skip_verify"`
}

func (p *PomeriumProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "pomerium"
	resp.Version = p.version
}

func (p *PomeriumProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: providerDescription,
		Attributes: map[string]schema.Attribute{
			"api_url": schema.StringAttribute{
				MarkdownDescription: "Pomerium Enterprise API URL",
				Required:            true,
			},
			"service_account_token": schema.StringAttribute{
				MarkdownDescription: "Pomerium Enterprise Service Account Token",
				Optional:            true,
				Sensitive:           true,
				Validators: []validator.String{
					stringvalidator.ExactlyOneOf(path.Expressions{
						path.MatchRoot("service_account_token"),
						path.MatchRoot("shared_secret_b64"),
					}...),
				},
			},
			"shared_secret_b64": schema.StringAttribute{
				MarkdownDescription: "Pomerium Shared Secret (base64 encoded)",
				Optional:            true,
				Sensitive:           true,
			},
			"tls_insecure_skip_verify": schema.BoolAttribute{
				MarkdownDescription: "Skip TLS server certificate verification (for testing only)",
				Optional:            true,
			},
		},
	}
}

func (p *PomeriumProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data PomeriumProviderModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	if data.APIURL.IsNull() {
		resp.Diagnostics.AddError("api_url is required", "api_url is required")
		return
	}

	apiURL, err := url.Parse(data.APIURL.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("failed to parse api_url", err.Error())
		return
	}

	tlsConfig := &tls.Config{InsecureSkipVerify: data.TLSInsecureSkipVerify.ValueBool()}
	var token string
	if !data.ServiceAccountToken.IsNull() {
		token = data.ServiceAccountToken.ValueString()
		if token == "" {
			resp.Diagnostics.AddError("service_account_token is empty", "service_account_token is empty")
			return
		}
	} else if !data.SharedSecretB64.IsNull() {
		token, err = GenerateBootstrapServiceAccountToken(data.SharedSecretB64.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("failed to decode shared_secret_b64", err.Error())
			return
		}
	} else {
		resp.Diagnostics.AddError("service_account_token or shared_secret_b64 is required", "service_account_token or shared_secret_b64 is required")
		return
	}

	resp.ResourceData = NewClient(apiURL.String(), token, tlsConfig)
	resp.DataSourceData = resp.ResourceData
}

func (p *PomeriumProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewClusterResource,
		NewExternalDataSourceResource,
		NewKeyChainResource,
		NewNamespacePermissionResource,
		NewNamespaceResource,
		NewPolicyResource,
		NewRouteResource,
		NewServiceAccountResource,
		NewSettingsResource,
	}
}

func (p *PomeriumProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewClusterDataSource,
		NewClustersDataSource,
		NewExternalDataSourceDataSource,
		NewNamespaceDataSource,
		NewNamespacesDataSource,
		NewPoliciesDataSource,
		NewPolicyDataSource,
		NewRouteDataSource,
		NewRoutesDataSource,
		NewServiceAccountDataSource,
		NewServiceAccountsDataSource,
	}
}

func (p *PomeriumProvider) Functions(_ context.Context) []func() function.Function {
	return []func() function.Function{}
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &PomeriumProvider{
			version: version,
		}
	}
}
