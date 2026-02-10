package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// ConfigureClient is a helper to configure resources and data sources with the API client
func ConfigureClient(req any, resp any) *Client {
	var providerData any
	switch r := req.(type) {
	case datasource.ConfigureRequest:
		providerData = r.ProviderData
	case resource.ConfigureRequest:
		providerData = r.ProviderData
	default:
		panic("unexpected req type: " + fmt.Sprintf("%T", req))
	}

	var diag *diag.Diagnostics
	switch r := resp.(type) {
	case *datasource.ConfigureResponse:
		diag = &r.Diagnostics
	case *resource.ConfigureResponse:
		diag = &r.Diagnostics
	default:
		panic("unexpected resp type: " + fmt.Sprintf("%T", resp))
	}

	if providerData == nil {
		return nil
	}

	client, ok := providerData.(*Client)
	if !ok {
		diag.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *Client, got: %T.", providerData),
		)
		return nil
	}

	return client
}

// ImportStatePassthroughID is a helper that implements the common import state pattern
func ImportStatePassthroughID(req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(context.Background(), path.Root("id"), req.ID)...)
}
