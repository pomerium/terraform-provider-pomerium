package provider_test

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"

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
		t.Run("IdentityProviders", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			actual := provider.NewEnterpriseToModelConverter(&diagnostics).Route(&pb.Route{
				IdentityProviders: []string{"IDP1", "IDP2"},
			})
			assert.Empty(t, diagnostics)
			assert.Equal(t, types.SetValueMust(types.StringType, []attr.Value{
				types.StringValue("IDP1"), types.StringValue("IDP2"),
			}), actual.IdentityProviders)
		})
		t.Run("SessionRecording", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			expect := &provider.RouteSessionRecordingModel{
				Enabled: types.BoolValue(true),
			}
			actual := provider.NewEnterpriseToModelConverter(&diagnostics).RouteSessionRecording(&pb.SessionRecording{
				Enabled: new(true),
			})
			assert.Empty(t, diagnostics)
			assert.Empty(t, cmp.Diff(expect, actual))
		})
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
	t.Run("ServiceAccount", func(t *testing.T) {
		t.Parallel()
		var diagnostics diag.Diagnostics
		expect := provider.ServiceAccountModel{
			Description: types.StringValue("DESCRIPTION"),
			ExpiresAt:   types.StringValue("2026-01-01T16:00:00Z"),
			ID:          types.StringValue("ID"),
			Name:        types.StringValue("NAME"),
			NamespaceID: types.StringValue("NAMESPACE_ID"),
			UserID:      types.StringValue("NAME@NAMESPACE_ID.pomerium"),
		}
		actual := provider.NewEnterpriseToModelConverter(&diagnostics).ServiceAccount(&pb.PomeriumServiceAccount{
			Description: new("DESCRIPTION"),
			ExpiresAt:   timestamppb.New(time.Date(2026, 1, 1, 16, 0, 0, 0, time.UTC)),
			Id:          "ID",
			NamespaceId: new("NAMESPACE_ID"),
			UserId:      "NAME@NAMESPACE_ID.pomerium",
		})
		assert.Empty(t, diagnostics)
		assert.Empty(t, cmp.Diff(expect, actual))
	})
	t.Run("Settings", func(t *testing.T) {
		t.Parallel()
		t.Run("empty", func(t *testing.T) {
			t.Parallel()
			expected := provider.SettingsModel{
				AccessLogFields:                types.SetNull(types.StringType),
				AllowUpgrades:                  types.SetNull(types.StringType),
				AuthorizeLogFields:             types.SetNull(types.StringType),
				EnvoyDynamicExtensions:         types.SetNull(types.StringType),
				ID:                             types.StringValue(""),
				IdentityProviders:              types.MapNull(provider.IdentityProviderObjectType()),
				IDPAccessTokenAllowedAudiences: types.SetNull(types.StringType),
				JWTClaimsHeaders:               types.MapNull(types.StringType),
				MCPAllowedAsMetadataDomains:    types.SetNull(types.StringType),
				MCPAllowedClientIDDomains:      types.SetNull(types.StringType),
				OtelExporterOtlpHeaders:        types.SetNull(types.StringType),
				OtelExporterOtlpTracesHeaders:  types.SetNull(types.StringType),
				OtelResourceAttributes:         types.SetNull(types.StringType),
				RequestParams:                  types.MapNull(types.StringType),
				Scopes:                         types.SetNull(types.StringType),
				SetResponseHeaders:             types.MapNull(types.StringType),
				SSHHostKeyFiles:                types.SetNull(types.StringType),
				SSHHostKeys:                    types.SetNull(types.StringType),
			}
			var diagnostics diag.Diagnostics
			actual := provider.NewEnterpriseToModelConverter(&diagnostics).Settings(&pb.Settings{}, nil)
			assert.Empty(t, diagnostics)
			if diff := cmp.Diff(expected, actual, protocmp.Transform()); diff != "" {
				t.Errorf("unexpected difference: %s", diff)
			}
		})
		t.Run("IdentityProviders", func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			actual := provider.NewEnterpriseToModelConverter(&diagnostics).Settings(&pb.Settings{
				IdentityProviders: map[string]*pb.IdentityProvider{
					"idp1": {
						Issuer:        "https://issuer1.example.com",
						JwksUrl:       "https://issuer1.example.com/.well-known/jwks.json",
						SupportedAlgs: []string{"RS256", "ES256"},
						Audiences:     []string{"AUDIENCE1"},
					},
					"idp2": {
						Issuer:    "https://issuer2.example.com",
						Audiences: []string{"AUDIENCE2"},
					},
				},
			}, nil)
			assert.Empty(t, diagnostics)
			assert.Equal(t, types.MapValueMust(provider.IdentityProviderObjectType(), map[string]attr.Value{
				"idp1": types.ObjectValueMust(provider.IdentityProviderObjectType().AttrTypes, map[string]attr.Value{
					"issuer":         types.StringValue("https://issuer1.example.com"),
					"jwks_url":       types.StringValue("https://issuer1.example.com/.well-known/jwks.json"),
					"supported_algs": types.SetValueMust(types.StringType, []attr.Value{types.StringValue("RS256"), types.StringValue("ES256")}),
					"audiences":      types.SetValueMust(types.StringType, []attr.Value{types.StringValue("AUDIENCE1")}),
				}),
				"idp2": types.ObjectValueMust(provider.IdentityProviderObjectType().AttrTypes, map[string]attr.Value{
					"issuer":         types.StringValue("https://issuer2.example.com"),
					"jwks_url":       types.StringValue(""),
					"supported_algs": types.SetNull(types.StringType),
					"audiences":      types.SetValueMust(types.StringType, []attr.Value{types.StringValue("AUDIENCE2")}),
				}),
			}), actual.IdentityProviders)
		})
	})
	t.Run("RecordingDataSource", func(t *testing.T) {
		t.Parallel()

		for _, tc := range []struct {
			name   string
			src    *pb.Datasource
			expect provider.RecordingDataSourceModel
		}{
			{
				name: "all set",
				src: &pb.Datasource{
					Namespace: "default",
					Entry: &pb.DatasourceEntry{
						Name:      "ds-a",
						BucketURI: "s3://bucket",
					},
				},
				expect: provider.RecordingDataSourceModel{
					Name:      types.StringValue("ds-a"),
					Namespace: types.StringValue("default"),
					BucketURI: types.StringValue("s3://bucket"),
				},
			},
			{
				name: "empty values",
				src:  &pb.Datasource{},
				expect: provider.RecordingDataSourceModel{
					Name:      types.StringValue(""),
					Namespace: types.StringValue(""),
					BucketURI: types.StringValue(""),
				},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				var diagnostics diag.Diagnostics
				actual := provider.NewEnterpriseToModelConverter(&diagnostics).RecordingDatasource(tc.src)
				assert.Empty(t, diagnostics)
				assert.Empty(t, cmp.Diff(tc.expect, actual))
			})
		}
	})
}
