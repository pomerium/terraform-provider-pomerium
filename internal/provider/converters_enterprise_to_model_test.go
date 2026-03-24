package provider_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/enterprise-client-go/pb"
	"github.com/pomerium/enterprise-terraform-provider/internal/provider"
)

func TestEnterpriseToModelConverter(t *testing.T) {
	t.Parallel()

	t.Run("CircuitBreakerThresholds", func(t *testing.T) {
		t.Parallel()

		for _, tc := range []struct {
			src    *pb.CircuitBreakerThresholds
			expect types.Object
		}{
			{nil, types.ObjectNull(provider.CircuitBreakerThresholdsObjectType().AttrTypes)},
			{&pb.CircuitBreakerThresholds{
				MaxConnections: proto.Uint32(1),
			}, types.ObjectValueMust(provider.CircuitBreakerThresholdsObjectType().AttrTypes, map[string]attr.Value{
				"max_connections":      types.Int64Value(1),
				"max_pending_requests": types.Int64Null(),
				"max_requests":         types.Int64Null(),
				"max_retries":          types.Int64Null(),
				"max_connection_pools": types.Int64Null(),
			})},
			{&pb.CircuitBreakerThresholds{
				MaxPendingRequests: proto.Uint32(2),
				MaxRequests:        proto.Uint32(3),
				MaxRetries:         proto.Uint32(4),
				MaxConnectionPools: proto.Uint32(5),
			}, types.ObjectValueMust(provider.CircuitBreakerThresholdsObjectType().AttrTypes, map[string]attr.Value{
				"max_connections":      types.Int64Null(),
				"max_pending_requests": types.Int64Value(2),
				"max_requests":         types.Int64Value(3),
				"max_retries":          types.Int64Value(4),
				"max_connection_pools": types.Int64Value(5),
			})},
		} {
			var diagnostics diag.Diagnostics
			actual := provider.NewEnterpriseToModelConverter(&diagnostics).CircuitBreakerThresholds(tc.src)
			assert.Empty(t, diagnostics)
			assert.Equal(t, tc.expect, actual)
		}
	})
	t.Run("Route", func(t *testing.T) {
		t.Parallel()
		t.Run("MCP", func(t *testing.T) {
			t.Parallel()
			t.Run("Client", func(t *testing.T) {
				t.Parallel()
				var diagnostics diag.Diagnostics
				expect := types.ObjectValueMust(provider.RouteMCPObjectType().AttrTypes, map[string]attr.Value{
					"client": types.ObjectValueMust(provider.RouteMCPClientObjectType().AttrTypes, map[string]attr.Value{}),
					"server": types.ObjectNull(provider.RouteMCPServerObjectType().AttrTypes),
				})
				actual := provider.NewEnterpriseToModelConverter(&diagnostics).RouteMCP(&pb.MCP{
					Mode: &pb.MCP_Client{
						Client: &pb.MCPClient{},
					},
				})
				assert.Empty(t, diagnostics)
				assert.Empty(t, cmp.Diff(expect, actual))
			})
			t.Run("Server", func(t *testing.T) {
				t.Parallel()
				var diagnostics diag.Diagnostics
				expect := types.ObjectValueMust(provider.RouteMCPObjectType().AttrTypes, map[string]attr.Value{
					"client": types.ObjectNull(provider.RouteMCPClientObjectType().AttrTypes),
					"server": types.ObjectValueMust(provider.RouteMCPServerObjectType().AttrTypes, map[string]attr.Value{
						"authorization_server_url": types.StringValue("AUTHORIZATION_SERVER_URL"),
						"max_request_bytes":        types.Int64Value(1234),
						"path":                     types.StringValue("PATH"),
						"upstream_oauth2": types.ObjectValueMust(provider.RouteMCPServerUpstreamOAuth2ObjectType().AttrTypes, map[string]attr.Value{
							"authorization_url_params": types.MapValueMust(types.StringType, map[string]attr.Value{
								"x": types.StringValue("y"),
							}),
							"client_id":     types.StringValue("CLIENT_ID"),
							"client_secret": types.StringValue("CLIENT_SECRET"),
							"oauth2_endpoint": types.ObjectValueMust(provider.RouteMCPServerUpstreamOAuth2OAuth2EndpointObjectType().AttrTypes, map[string]attr.Value{
								"auth_style": types.StringValue("in_header"),
								"auth_url":   types.StringValue("AUTH_URL"),
								"token_url":  types.StringValue("TOKEN_URL"),
							}),
							"scopes": types.SetValueMust(types.StringType, []attr.Value{
								types.StringValue("SCOPE1"),
								types.StringValue("SCOPE2"),
							}),
						}),
					}),
				})
				actual := provider.NewEnterpriseToModelConverter(&diagnostics).RouteMCP(&pb.MCP{
					Mode: &pb.MCP_Server{
						Server: &pb.MCPServer{
							AuthorizationServerUrl: new("AUTHORIZATION_SERVER_URL"),
							MaxRequestBytes:        new(uint32(1234)),
							Path:                   new("PATH"),
							UpstreamOauth2: &pb.UpstreamOAuth2{
								AuthorizationUrlParams: map[string]string{"x": "y"},
								ClientId:               "CLIENT_ID",
								ClientSecret:           "CLIENT_SECRET",
								Oauth2Endpoint: &pb.OAuth2Endpoint{
									AuthStyle: pb.OAuth2AuthStyle_OAUTH2_AUTH_STYLE_IN_HEADER.Enum(),
									AuthUrl:   "AUTH_URL",
									TokenUrl:  "TOKEN_URL",
								},
								Scopes: []string{"SCOPE1", "SCOPE2"},
							},
						},
					},
				})
				assert.Empty(t, diagnostics)
				assert.Empty(t, cmp.Diff(expect, actual))
			})
		})
	})
}
