package provider_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/pomerium/enterprise-client-go/pb"
	"github.com/pomerium/enterprise-terraform-provider/internal/provider"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
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
			SetResponseHeaders: map[string]string{
				"X-Response": "value",
			},
			ShowErrorDetails: true,
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
			SetResponseHeaders: types.MapValueMust(
				types.StringType,
				map[string]attr.Value{
					"X-Response": types.StringValue("value"),
				},
			),
			ShowErrorDetails: types.BoolValue(true),
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
		}

		actual, diag := provider.ConvertRouteToPB(context.Background(), &input)
		require.False(t, diag.HasError(), diag.Errors())

		expected := &pb.Route{
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
		}

		if diff := cmp.Diff(expected, actual, protocmp.Transform()); diff != "" {
			t.Errorf("unexpected difference: %s", diff)
		}
	})
}
