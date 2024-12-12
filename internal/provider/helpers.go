package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	client "github.com/pomerium/enterprise-client-go"
)

// ConfigureClient is a helper to configure resources and data sources with the API client
func ConfigureClient(req any, resp any) *client.Client {
	var providerData any
	switch r := req.(type) {
	case datasource.ConfigureRequest:
		providerData = r.ProviderData
	case resource.ConfigureRequest:
		providerData = r.ProviderData
	}

	if providerData == nil {
		return nil
	}

	client, ok := providerData.(*client.Client)
	if !ok {
		switch r := resp.(type) {
		case *datasource.ConfigureResponse:
			r.Diagnostics.AddError(
				"Unexpected Data Source Configure Type",
				fmt.Sprintf("Expected *client.Client, got: %T.", providerData),
			)
		case *resource.ConfigureResponse:
			r.Diagnostics.AddError(
				"Unexpected Resource Configure Type",
				fmt.Sprintf("Expected *client.Client, got: %T.", providerData),
			)
		}
		return nil
	}

	return client
}

// ImportStatePassthroughID is a helper that implements the common import state pattern
func ImportStatePassthroughID(req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(context.TODO(), path.Root("id"), req, resp)
}
