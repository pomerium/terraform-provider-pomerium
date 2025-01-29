package provider_test

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/pomerium/enterprise-client-go/pb"
	"github.com/pomerium/enterprise-terraform-provider/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertRoute(t *testing.T) {
	t.Parallel()

	t.Run("pb to model", func(t *testing.T) {
		t.Parallel()

		// Test conversion from pb to model
		route := &pb.Route{
			Id:   "route-id",
			Name: "route-name",
			From: "from",
			To:   []string{"to"},
		}

		var plan provider.RouteResourceModel
		diag := provider.ConvertRouteFromPB(&plan, route)
		require.False(t, diag.HasError(), diag.Errors())
	})

	t.Run("model to pb", func(t *testing.T) {
		t.Parallel()

		// Test conversion from model to pb
		plan := provider.RouteResourceModel{
			From: types.StringValue("from"),
			To:   types.SetValueMust(types.StringType, []attr.Value{types.StringValue("to")}),
			Name: types.StringValue("route-name"),
			ID:   types.StringValue("route-id"),
		}

		route, diag := provider.ConvertRouteToPB(context.Background(), &plan)
		require.False(t, diag.HasError(), diag.Errors())
		assert.Equal(t, "route-id", route.Id)
		assert.Equal(t, "route-name", route.Name)
		assert.Equal(t, "from", route.From)
		assert.Equal(t, []string{"to"}, route.To)
	})
}
