package provider_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/enterprise-client-go/pb"
	"github.com/pomerium/enterprise-terraform-provider/internal/provider"
)

func TestCircuitBreakerThresholdsFromPB(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		src    *pb.CircuitBreakerThresholds
		expect types.Object
	}{
		{nil, types.ObjectNull(provider.CircuitBreakerThresholdsAttributes)},
		{&pb.CircuitBreakerThresholds{
			MaxConnections: proto.Uint32(1),
		}, types.ObjectValueMust(provider.CircuitBreakerThresholdsAttributes, map[string]attr.Value{
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
		}, types.ObjectValueMust(provider.CircuitBreakerThresholdsAttributes, map[string]attr.Value{
			"max_connections":      types.Int64Null(),
			"max_pending_requests": types.Int64Value(2),
			"max_requests":         types.Int64Value(3),
			"max_retries":          types.Int64Value(4),
			"max_connection_pools": types.Int64Value(5),
		})},
	} {
		var diagnostics diag.Diagnostics
		actual := provider.CircuitBreakerThresholdsFromPB(tc.src, &diagnostics)
		assert.Equal(t, tc.expect, actual)
	}
}

func TestCircuitBreakerThresholdsToPB(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		src    types.Object
		expect *pb.CircuitBreakerThresholds
	}{
		{types.ObjectNull(provider.CircuitBreakerThresholdsAttributes), nil},
		{types.ObjectValueMust(provider.CircuitBreakerThresholdsAttributes, map[string]attr.Value{
			"max_connections":      types.Int64Value(1),
			"max_pending_requests": types.Int64Null(),
			"max_requests":         types.Int64Null(),
			"max_retries":          types.Int64Null(),
			"max_connection_pools": types.Int64Null(),
		}), &pb.CircuitBreakerThresholds{
			MaxConnections: proto.Uint32(1),
		}},
		{types.ObjectValueMust(provider.CircuitBreakerThresholdsAttributes, map[string]attr.Value{
			"max_connections":      types.Int64Null(),
			"max_pending_requests": types.Int64Value(2),
			"max_requests":         types.Int64Value(3),
			"max_retries":          types.Int64Value(4),
			"max_connection_pools": types.Int64Value(5),
		}), &pb.CircuitBreakerThresholds{
			MaxPendingRequests: proto.Uint32(2),
			MaxRequests:        proto.Uint32(3),
			MaxRetries:         proto.Uint32(4),
			MaxConnectionPools: proto.Uint32(5),
		}},
	} {
		actual := provider.CircuitBreakerThresholdsToPB(tc.src)
		assert.Equal(t, tc.expect, actual)
	}
}
