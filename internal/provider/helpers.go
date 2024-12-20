package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	client "github.com/pomerium/enterprise-client-go"
)

// ConfigureClient is a helper to configure resources and data sources with the API client
func ConfigureClient(req any, resp any) *client.Client {
	// First validate the response type
	var diagnostics diag.Diagnostics
	switch resp.(type) {
	case *datasource.ConfigureResponse, *resource.ConfigureResponse:
		// valid types
	default:
		panic(fmt.Sprintf("unexpected response type: %T", resp))
	}

	// Get provider data based on request type
	var providerData any
	switch r := req.(type) {
	case datasource.ConfigureRequest:
		providerData = r.ProviderData
	case resource.ConfigureRequest:
		providerData = r.ProviderData
	default:
		panic(fmt.Sprintf("unexpected request type: %T", req))
	}

	if providerData == nil {
		diagnostics.AddWarning(
			"Unconfigured Provider",
			"Provider has not been configured, resources may not work correctly",
		)
		setDiagnostics(resp, diagnostics)
		return nil
	}

	client, ok := providerData.(*client.Client)
	if !ok {
		diagnostics.AddError(
			"Unexpected Provider Type",
			fmt.Sprintf("Expected *client.Client, got: %T", providerData),
		)
		setDiagnostics(resp, diagnostics)
		return nil
	}

	return client
}

// helper function to set diagnostics on the response
func setDiagnostics(resp any, diagnostics diag.Diagnostics) {
	switch r := resp.(type) {
	case *datasource.ConfigureResponse:
		r.Diagnostics.Append(diagnostics...)
	case *resource.ConfigureResponse:
		r.Diagnostics.Append(diagnostics...)
	}
}

// ImportStatePassthroughID is a helper that implements the common import state pattern
func ImportStatePassthroughID(req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(context.Background(), path.Root("id"), req.ID)...)
}
