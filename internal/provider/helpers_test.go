package provider_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/stretchr/testify/assert"

	"github.com/pomerium/enterprise-terraform-provider/internal/provider"
)

func TestConfigureClient(t *testing.T) {
	t.Parallel()

	mockClient := &provider.Client{}

	tests := []struct {
		name           string
		req            any
		resp           any
		expectedClient *provider.Client
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

// helper function to create pointers
func ptr[T any](v T) *T {
	return &v
}
