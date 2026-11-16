package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/sdk-go"
)

// notFoundCoreClient is a core databroker client whose Get always returns NotFound.
type notFoundCoreClient struct {
	sdk.CoreClient
}

func (notFoundCoreClient) Get(context.Context, *databrokerpb.GetRequest, ...grpc.CallOption) (*databrokerpb.GetResponse, error) {
	return nil, status.Error(codes.NotFound, "not found")
}

// newNotFoundClient returns a Client for the given server type whose APIs
// respond to every lookup with a not found error.
func newNotFoundClient(t *testing.T, st serverType) *Client {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// zero resources exchange a token and look up the organization
		// before the resource itself
		switch r.URL.Path {
		case "/api/v0/token":
			_, _ = w.Write([]byte(`{"expiresInSeconds":"3600","idToken":"token"}`))
			return
		case "/api/v0/organizations":
			_, _ = w.Write([]byte(`[{"id":"org-1"}]`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"not_found","message":"not found"}`))
	}))
	t.Cleanup(srv.Close)

	return &Client{
		consolidated:  sdk.NewClient(sdk.WithURL(srv.URL), sdk.WithHTTPClient(srv.Client())),
		getServerType: func() (serverType, error) { return st, nil },
		getCoreClient: func() (sdk.CoreClient, error) { return notFoundCoreClient{}, nil },
		getZeroClient: func() (sdk.ZeroClient, error) {
			return sdk.NewZeroClient(sdk.WithURL(srv.URL), sdk.WithHTTPClient(srv.Client()))
		},
	}
}

// TestResourceReadNotFoundRemovesState verifies that when a resource has been
// deleted outside of Terraform, Read removes it from state so that Terraform
// plans to recreate it, rather than restoring the prior state.
func TestResourceReadNotFoundRemovesState(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		serverType serverType
		resource   func(*Client) resource.Resource
	}{
		{"cluster", serverTypeCore, func(c *Client) resource.Resource { return &ClusterResource{client: c} }},
		{"cluster_zero", serverTypeZero, func(c *Client) resource.Resource { return &ClusterResource{client: c} }},
		{"external_data_source", serverTypeCore, func(c *Client) resource.Resource { return &ExternalDataSourceResource{client: c} }},
		{"key_pair", serverTypeZero, func(c *Client) resource.Resource { return &KeyPairResource{client: c} }},
		{"namespace", serverTypeCore, func(c *Client) resource.Resource { return &NamespaceResource{client: c} }},
		{"namespace_permission", serverTypeCore, func(c *Client) resource.Resource { return &NamespacePermissionResource{client: c} }},
		{"policy", serverTypeZero, func(c *Client) resource.Resource { return &PolicyResource{client: c} }},
		{"route", serverTypeZero, func(c *Client) resource.Resource { return &RouteResource{client: c} }},
		{"service_account", serverTypeZero, func(c *Client) resource.Resource { return &ServiceAccountResource{client: c} }},
		{"settings", serverTypeZero, func(c *Client) resource.Resource { return &SettingsResource{client: c} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			r := tc.resource(newNotFoundClient(t, tc.serverType))

			var schemaResp resource.SchemaResponse
			r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
			require.False(t, schemaResp.Diagnostics.HasError(), "%v", schemaResp.Diagnostics)

			state := tfsdk.State{
				Schema: schemaResp.Schema,
				Raw:    tftypes.NewValue(schemaResp.Schema.Type().TerraformType(ctx), nil),
			}
			diags := state.SetAttribute(ctx, path.Root("id"), "deleted-out-of-band")
			require.False(t, diags.HasError(), "%v", diags)

			req := resource.ReadRequest{State: state}
			resp := resource.ReadResponse{State: state}
			r.Read(ctx, req, &resp)

			require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
			require.True(t, resp.State.Raw.IsNull(), "expected resource to be removed from state")
		})
	}
}
