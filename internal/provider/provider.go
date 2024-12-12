package provider

import (
	"context"
	"crypto/tls"
	"net"
	"net/url"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	client "github.com/pomerium/enterprise-client-go"
)

var (
	_ provider.Provider              = &PomeriumProvider{}
	_ provider.ProviderWithFunctions = &PomeriumProvider{}
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
		Attributes: map[string]schema.Attribute{
			"api_url": schema.StringAttribute{
				MarkdownDescription: "Pomerium Enterprise API URL",
				Required:            true,
			},
			"service_account_token": schema.StringAttribute{
				MarkdownDescription: "Pomerium Enterprise Service Account Token",
				Optional:            true,
				Sensitive:           true,
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
	host, port := apiURL.Hostname(), apiURL.Port()
	if host == "" {
		resp.Diagnostics.AddError("api_url is missing hostname", "api_url is missing hostname")
		return
	}
	if port == "" {
		port = "443"
	}

	tlsConfig := &tls.Config{InsecureSkipVerify: data.TLSInsecureSkipVerify.ValueBool()}
	var token string
	if !data.ServiceAccountToken.IsNull() {
		token = data.ServiceAccountToken.ValueString()
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
	c, err := client.NewClient(ctx, net.JoinHostPort(host, port), token, client.WithTlsConfig(tlsConfig))
	if err != nil {
		resp.Diagnostics.AddError("failed to create Pomerium Enterprise API client", err.Error())
		return
	}

	resp.ResourceData = c
}

func (p *PomeriumProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewNamespaceResource,
		NewRouteResource,
		NewPolicyResource,
		NewServiceAccountResource,
	}
}

func (p *PomeriumProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewServiceAccountDataSource,
		NewServiceAccountsDataSource,
		NewRouteDataSource,
		NewRoutesDataSource,
		NewNamespaceDataSource,
		NewNamespacesDataSource,
		NewPolicyDataSource,
		NewPoliciesDataSource,
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
