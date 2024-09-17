// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

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

// Ensure ScaffoldingProvider satisfies various provider interfaces.
var _ provider.Provider = &PomeriumProvider{}
var _ provider.ProviderWithFunctions = &PomeriumProvider{}

// PomeriumProvider defines the provider implementation.
type PomeriumProvider struct {
	// version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance
	// testing.
	version string
}

// PomeriumProviderModel describes the provider data model.
type PomeriumProviderModel struct {
	ApiURL                types.String `tfsdk:"api_url"`
	ServiceAccountToken   types.String `tfsdk:"service_account_token"`
	TLSInsecureSkipVerify types.Bool   `tfsdk:"tls_insecure_skip_verify"`
}

func (p *PomeriumProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "pomerium"
	resp.Version = p.version
}

func (p *PomeriumProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"api_url": schema.StringAttribute{
				MarkdownDescription: "Pomerium Enterprise API URL",
				Required:            true,
			},
			"service_account_token": schema.StringAttribute{
				MarkdownDescription: "Pomerium Enterprise Service Account Token",
				Required:            true,
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

	if data.ApiURL.IsNull() {
		resp.Diagnostics.AddError("api_url is required", "api_url is required")
		return
	}

	apiURL, err := url.Parse(data.ApiURL.ValueString())
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

	if data.ServiceAccountToken.IsNull() {
		resp.Diagnostics.AddError("service_account_token is required", "service_account_token is required")
		return
	}

	tlsConfig := &tls.Config{InsecureSkipVerify: data.TLSInsecureSkipVerify.ValueBool()}
	c, err := client.NewClient(ctx, net.JoinHostPort(host, port), data.ServiceAccountToken.ValueString(), client.WithTlsConfig(tlsConfig))
	if err != nil {
		resp.Diagnostics.AddError("failed to create Pomerium Enterprise API client", err.Error())
		return
	}

	resp.ResourceData = c
}

func (p *PomeriumProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewNamespaceResource,
		NewRouteResource,
		NewPolicyResource,
	}
}

func (p *PomeriumProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{}
}

func (p *PomeriumProvider) Functions(ctx context.Context) []func() function.Function {
	return []func() function.Function{}
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &PomeriumProvider{
			version: version,
		}
	}
}
