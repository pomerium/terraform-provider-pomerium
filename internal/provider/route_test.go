package provider_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/pomerium/enterprise-client-go/pb"
	"github.com/pomerium/enterprise-terraform-provider/internal/provider"
)

func TestConvertRoute(t *testing.T) {
	t.Parallel()

	t.Run("pb to model", func(t *testing.T) {
		t.Parallel()

		input := &pb.Route{
			Id:                  "route-id",
			Name:                "route-name",
			From:                "from",
			To:                  []string{"to1", "to2"},
			Prefix:              P("/api"),
			Path:                P("/v1"),
			PassIdentityHeaders: P(true),
			SetRequestHeaders: map[string]string{
				"X-Custom": "value",
			},
			RemoveRequestHeaders: []string{"Remove-Me"},
			NamespaceId:          "namespace-1",
			StatName:             "stats-name",
			PolicyIds:            []string{"policy-1", "policy-2"},
			RewriteResponseHeaders: []*pb.RouteRewriteHeader{
				{
					Header:  "header-1",
					Matcher: &pb.RouteRewriteHeader_Prefix{Prefix: "prefix-1"},
					Value:   "value-1",
				},
			},
			SetResponseHeaders: map[string]string{
				"X-Response": "value",
			},
			ShowErrorDetails: true,
			Description:      P("route description"),
			LogoUrl:          P("https://example.com/logo.png"),
			EnableGoogleCloudServerlessAuthentication: true,
			TlsCustomCaKeyPairId:                      P("custom-ca-1"),
			KubernetesServiceAccountTokenFile:         P("/path/to/token"),
			JwtIssuerFormat:                           pb.IssuerFormat_IssuerURI,
			BearerTokenFormat:                         pb.BearerTokenFormat_BEARER_TOKEN_FORMAT_IDP_ACCESS_TOKEN.Enum(),
			IdpAccessTokenAllowedAudiences:            &pb.Route_StringList{Values: []string{"a", "b", "c"}},
		}

		var actual provider.RouteResourceModel
		diag := provider.ConvertRouteFromPB(&actual, input)
		require.False(t, diag.HasError(), diag.Errors())

		expected := provider.RouteResourceModel{
			ID:                  types.StringValue("route-id"),
			Name:                types.StringValue("route-name"),
			From:                types.StringValue("from"),
			Prefix:              types.StringValue("/api"),
			Path:                types.StringValue("/v1"),
			PassIdentityHeaders: types.BoolValue(true),
			To: types.SetValueMust(types.StringType, []attr.Value{
				types.StringValue("to1"),
				types.StringValue("to2"),
			}),
			SetRequestHeaders: types.MapValueMust(
				types.StringType,
				map[string]attr.Value{
					"X-Custom": types.StringValue("value"),
				},
			),
			RemoveRequestHeaders: types.SetValueMust(
				types.StringType,
				[]attr.Value{types.StringValue("Remove-Me")},
			),
			NamespaceID: types.StringValue("namespace-1"),
			StatName:    types.StringValue("stats-name"),
			Policies: types.SetValueMust(types.StringType, []attr.Value{
				types.StringValue("policy-1"),
				types.StringValue("policy-2"),
			}),
			RewriteResponseHeaders: types.SetValueMust(
				provider.RewriteHeaderObjectType(),
				[]attr.Value{
					types.ObjectValueMust(
						provider.RewriteHeaderAttrTypes(),
						map[string]attr.Value{
							"header": types.StringValue("header-1"),
							"prefix": types.StringValue("prefix-1"),
							"value":  types.StringValue("value-1"),
						},
					),
				},
			),
			SetResponseHeaders: types.MapValueMust(
				types.StringType,
				map[string]attr.Value{
					"X-Response": types.StringValue("value"),
				},
			),
			ShowErrorDetails: types.BoolValue(true),
			Description:      types.StringValue("route description"),
			LogoURL:          types.StringValue("https://example.com/logo.png"),
			EnableGoogleCloudServerlessAuthentication: types.BoolValue(true),
			TLSCustomCAKeyPairID:                      types.StringValue("custom-ca-1"),
			KubernetesServiceAccountTokenFile:         types.StringValue("/path/to/token"),
			JWTIssuerFormat:                           types.StringValue("IssuerURI"),
			BearerTokenFormat:                         types.StringValue("idp_access_token"),
			IDPAccessTokenAllowedAudiences: types.SetValueMust(types.StringType, []attr.Value{
				types.StringValue("a"), types.StringValue("b"), types.StringValue("c"),
			}),
		}

		if diff := cmp.Diff(expected, actual); diff != "" {
			t.Errorf("unexpected difference: %s", diff)
		}
	})

	t.Run("model to pb", func(t *testing.T) {
		t.Parallel()

		input := provider.RouteResourceModel{
			ID:   types.StringValue("route-id"),
			Name: types.StringValue("route-name"),
			From: types.StringValue("from"),
			To: types.SetValueMust(types.StringType, []attr.Value{
				types.StringValue("to1"),
				types.StringValue("to2"),
			}),
			Prefix:              types.StringValue("/api"),
			Path:                types.StringValue("/v1"),
			PassIdentityHeaders: types.BoolValue(true),
			SetRequestHeaders: types.MapValueMust(
				types.StringType,
				map[string]attr.Value{
					"X-Custom": types.StringValue("value"),
				},
			),
			RemoveRequestHeaders: types.SetValueMust(
				types.StringType,
				[]attr.Value{types.StringValue("Remove-Me")},
			),
			NamespaceID: types.StringValue("namespace-1"),
			StatName:    types.StringValue("stats-name"),
			Policies: types.SetValueMust(types.StringType, []attr.Value{
				types.StringValue("policy-1"),
				types.StringValue("policy-2"),
			}),
			SetResponseHeaders: types.MapValueMust(
				types.StringType,
				map[string]attr.Value{
					"X-Response": types.StringValue("value"),
				},
			),
			ShowErrorDetails: types.BoolValue(true),
			Description:      types.StringValue("route description"),
			LogoURL:          types.StringValue("https://example.com/logo.png"),
			EnableGoogleCloudServerlessAuthentication: types.BoolValue(true),
			TLSCustomCAKeyPairID:                      types.StringValue("custom-ca-1"),
			KubernetesServiceAccountTokenFile:         types.StringValue("/path/to/token"),
			BearerTokenFormat:                         types.StringValue("idp_access_token"),
			IDPAccessTokenAllowedAudiences: types.SetValueMust(types.StringType, []attr.Value{
				types.StringValue("X"), types.StringValue("Y"), types.StringValue("Z"),
			}),
		}

		actual, diag := provider.ConvertRouteToPB(context.Background(), &input)
		require.False(t, diag.HasError(), diag.Errors())

		expected := &pb.Route{
			OriginatorId:         "terraform",
			Id:                   "route-id",
			Name:                 "route-name",
			From:                 "from",
			To:                   []string{"to1", "to2"},
			Prefix:               P("/api"),
			Path:                 P("/v1"),
			PassIdentityHeaders:  P(true),
			SetRequestHeaders:    map[string]string{"X-Custom": "value"},
			RemoveRequestHeaders: []string{"Remove-Me"},
			NamespaceId:          "namespace-1",
			StatName:             "stats-name",
			PolicyIds:            []string{"policy-1", "policy-2"},
			SetResponseHeaders:   map[string]string{"X-Response": "value"},
			ShowErrorDetails:     true,
			Description:          P("route description"),
			LogoUrl:              P("https://example.com/logo.png"),
			EnableGoogleCloudServerlessAuthentication: true,
			TlsCustomCaKeyPairId:                      P("custom-ca-1"),
			KubernetesServiceAccountTokenFile:         P("/path/to/token"),
			BearerTokenFormat:                         pb.BearerTokenFormat_BEARER_TOKEN_FORMAT_IDP_ACCESS_TOKEN.Enum(),
			IdpAccessTokenAllowedAudiences: &pb.Route_StringList{
				Values: []string{"X", "Y", "Z"},
			},
		}

		if diff := cmp.Diff(expected, actual, protocmp.Transform()); diff != "" {
			t.Errorf("unexpected difference: %s", diff)
		}
	})

	t.Run("pb to model with rewrite headers", func(t *testing.T) {
		t.Parallel()

		input := &pb.Route{
			Id:                  "route-id",
			Name:                "route-name",
			From:                "from",
			To:                  []string{"to1", "to2"},
			Prefix:              P("/api"),
			Path:                P("/v1"),
			PassIdentityHeaders: P(true),
			SetRequestHeaders: map[string]string{
				"X-Custom": "value",
			},
			RemoveRequestHeaders: []string{"Remove-Me"},
			NamespaceId:          "namespace-1",
			StatName:             "stats-name",
			PolicyIds:            []string{"policy-1", "policy-2"},
			RewriteResponseHeaders: []*pb.RouteRewriteHeader{
				{
					Header:  "header-1",
					Matcher: &pb.RouteRewriteHeader_Prefix{Prefix: "prefix-1"},
					Value:   "value-1",
				},
				{
					Header: "header-2",
					Value:  "value-2",
				},
			},
			SetResponseHeaders: map[string]string{
				"X-Response": "value",
			},
			ShowErrorDetails: true,
			Description:      P("route description"),
			LogoUrl:          P("https://example.com/logo.png"),
			EnableGoogleCloudServerlessAuthentication: true,
			TlsCustomCaKeyPairId:                      P("custom-ca-1"),
			KubernetesServiceAccountTokenFile:         P("/path/to/token"),
		}

		var actual provider.RouteResourceModel
		diag := provider.ConvertRouteFromPB(&actual, input)
		require.False(t, diag.HasError(), diag.Errors())

		expected := provider.RouteResourceModel{
			ID:                  types.StringValue("route-id"),
			Name:                types.StringValue("route-name"),
			From:                types.StringValue("from"),
			Prefix:              types.StringValue("/api"),
			Path:                types.StringValue("/v1"),
			PassIdentityHeaders: types.BoolValue(true),
			To: types.SetValueMust(types.StringType, []attr.Value{
				types.StringValue("to1"),
				types.StringValue("to2"),
			}),
			SetRequestHeaders: types.MapValueMust(
				types.StringType,
				map[string]attr.Value{
					"X-Custom": types.StringValue("value"),
				},
			),
			RemoveRequestHeaders: types.SetValueMust(
				types.StringType,
				[]attr.Value{types.StringValue("Remove-Me")},
			),
			NamespaceID: types.StringValue("namespace-1"),
			StatName:    types.StringValue("stats-name"),
			Policies: types.SetValueMust(types.StringType, []attr.Value{
				types.StringValue("policy-1"),
				types.StringValue("policy-2"),
			}),
			RewriteResponseHeaders: types.SetValueMust(
				provider.RewriteHeaderObjectType(),
				[]attr.Value{
					types.ObjectValueMust(
						provider.RewriteHeaderAttrTypes(),
						map[string]attr.Value{
							"header": types.StringValue("header-1"),
							"prefix": types.StringValue("prefix-1"),
							"value":  types.StringValue("value-1"),
						},
					),
					types.ObjectValueMust(
						provider.RewriteHeaderAttrTypes(),
						map[string]attr.Value{
							"header": types.StringValue("header-2"),
							"prefix": types.StringNull(),
							"value":  types.StringValue("value-2"),
						},
					),
				},
			),
			SetResponseHeaders: types.MapValueMust(
				types.StringType,
				map[string]attr.Value{
					"X-Response": types.StringValue("value"),
				},
			),
			ShowErrorDetails: types.BoolValue(true),
			Description:      types.StringValue("route description"),
			LogoURL:          types.StringValue("https://example.com/logo.png"),
			EnableGoogleCloudServerlessAuthentication: types.BoolValue(true),
			TLSCustomCAKeyPairID:                      types.StringValue("custom-ca-1"),
			KubernetesServiceAccountTokenFile:         types.StringValue("/path/to/token"),
		}

		if diff := cmp.Diff(expected.RewriteResponseHeaders, actual.RewriteResponseHeaders); diff != "" {
			t.Errorf("unexpected difference in RewriteResponseHeaders: %s", diff)
		}
	})

	t.Run("model to pb with rewrite headers", func(t *testing.T) {
		t.Parallel()

		input := provider.RouteResourceModel{
			ID:   types.StringValue("route-id"),
			Name: types.StringValue("route-name"),
			From: types.StringValue("from"),
			To: types.SetValueMust(types.StringType, []attr.Value{
				types.StringValue("to1"),
				types.StringValue("to2"),
			}),
			Prefix:              types.StringValue("/api"),
			Path:                types.StringValue("/v1"),
			PassIdentityHeaders: types.BoolValue(true),
			SetRequestHeaders: types.MapValueMust(
				types.StringType,
				map[string]attr.Value{
					"X-Custom": types.StringValue("value"),
				},
			),
			RemoveRequestHeaders: types.SetValueMust(
				types.StringType,
				[]attr.Value{types.StringValue("Remove-Me")},
			),
			NamespaceID: types.StringValue("namespace-1"),
			StatName:    types.StringValue("stats-name"),
			Policies: types.SetValueMust(types.StringType, []attr.Value{
				types.StringValue("policy-1"),
				types.StringValue("policy-2"),
			}),
			RewriteResponseHeaders: types.SetValueMust(
				provider.RewriteHeaderObjectType(),
				[]attr.Value{
					types.ObjectValueMust(
						provider.RewriteHeaderAttrTypes(),
						map[string]attr.Value{
							"header": types.StringValue("header-1"),
							"prefix": types.StringValue("prefix-1"),
							"value":  types.StringValue("value-1"),
						},
					),
					types.ObjectValueMust(
						provider.RewriteHeaderAttrTypes(),
						map[string]attr.Value{
							"header": types.StringValue("header-2"),
							"prefix": types.StringNull(),
							"value":  types.StringValue("value-2"),
						},
					),
				},
			),
			SetResponseHeaders: types.MapValueMust(
				types.StringType,
				map[string]attr.Value{
					"X-Response": types.StringValue("value"),
				},
			),
			ShowErrorDetails: types.BoolValue(true),
			Description:      types.StringValue("route description"),
			LogoURL:          types.StringValue("https://example.com/logo.png"),
			EnableGoogleCloudServerlessAuthentication: types.BoolValue(true),
			TLSCustomCAKeyPairID:                      types.StringValue("custom-ca-1"),
			KubernetesServiceAccountTokenFile:         types.StringValue("/path/to/token"),
		}

		actual, diag := provider.ConvertRouteToPB(context.Background(), &input)
		require.False(t, diag.HasError(), diag.Errors())

		expectedHeaders := []*pb.RouteRewriteHeader{
			{
				Header:  "header-1",
				Matcher: &pb.RouteRewriteHeader_Prefix{Prefix: "prefix-1"},
				Value:   "value-1",
			},
			{
				Header: "header-2",
				Value:  "value-2",
				// no prefix matcher for null case
			},
		}

		if diff := cmp.Diff(expectedHeaders, actual.RewriteResponseHeaders, protocmp.Transform()); diff != "" {
			t.Errorf("unexpected difference in RewriteResponseHeaders: %s", diff)
		}
	})
}
