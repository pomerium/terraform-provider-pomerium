package provider_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	client "github.com/pomerium/enterprise-client-go"
	"github.com/pomerium/enterprise-terraform-provider/internal/provider"
	"github.com/stretchr/testify/assert"
)

func TestConfigureClient(t *testing.T) {
	t.Parallel()

	mockClient := &client.Client{}

	tests := []struct {
		name           string
		req            any
		resp           any
		expectedClient *client.Client
		expectError    bool
	}{
		{
			name: "valid datasource request",
			req: datasource.ConfigureRequest{
				ProviderData: mockClient,
			},
			resp:           &datasource.ConfigureResponse{},
			expectedClient: mockClient,
			expectError:    false,
		},
		{
			name: "valid resource request",
			req: resource.ConfigureRequest{
				ProviderData: mockClient,
			},
			resp:           &resource.ConfigureResponse{},
			expectedClient: mockClient,
			expectError:    false,
		},
		{
			name: "nil provider data",
			req: datasource.ConfigureRequest{
				ProviderData: nil,
			},
			resp:           &datasource.ConfigureResponse{},
			expectedClient: nil,
			expectError:    false,
		},
		{
			name: "invalid provider data type - datasource",
			req: datasource.ConfigureRequest{
				ProviderData: "invalid",
			},
			resp:           &datasource.ConfigureResponse{},
			expectedClient: nil,
			expectError:    true,
		},
		{
			name: "invalid provider data type - resource",
			req: resource.ConfigureRequest{
				ProviderData: "invalid",
			},
			resp:           &resource.ConfigureResponse{},
			expectedClient: nil,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := provider.ConfigureClient(tt.req, tt.resp)
			assert.Equal(t, tt.expectedClient, client)

			switch resp := tt.resp.(type) {
			case *datasource.ConfigureResponse:
				assert.Equal(t, tt.expectError, resp.Diagnostics.HasError())
			case *resource.ConfigureResponse:
				assert.Equal(t, tt.expectError, resp.Diagnostics.HasError())
			}
		})
	}
}

func TestImportStatePassthroughID(t *testing.T) {
	t.Parallel()

	req := resource.ImportStateRequest{
		ID: "test-id",
	}
	resp := &resource.ImportStateResponse{}

	provider.ImportStatePassthroughID(req, resp)
	assert.False(t, resp.Diagnostics.HasError())
}
