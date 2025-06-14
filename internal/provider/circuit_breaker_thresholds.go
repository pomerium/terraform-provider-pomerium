package provider

import (
	"math"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/enterprise-client-go/pb"
)

var circuitBreakerThresholdsAttribute = schema.SingleNestedAttribute{
	Description: "Circuit breaker thresholds for the route.",
	Optional:    true,
	Attributes: map[string]schema.Attribute{
		"max_connections": schema.Int64Attribute{
			Description: "The maximum number of connections that Envoy will make to the upstream cluster. If not specified, the default is 1024.",
			Optional:    true,
			Validators:  []validator.Int64{int64validator.AtLeast(0), int64validator.AtMost(math.MaxUint32)},
		},
		"max_pending_requests": schema.Int64Attribute{
			Description: "The maximum number of pending requests that Envoy will allow to the upstream cluster. If not specified, the default is 1024. This limit is applied as a connection limit for non-HTTP traffic.",
			Optional:    true,
			Validators:  []validator.Int64{int64validator.AtLeast(0), int64validator.AtMost(math.MaxUint32)},
		},
		"max_requests": schema.Int64Attribute{
			Description: "The maximum number of parallel requests that Envoy will make to the upstream cluster. If not specified, the default is 1024. This limit does not apply to non-HTTP traffic.",
			Optional:    true,
			Validators:  []validator.Int64{int64validator.AtLeast(0), int64validator.AtMost(math.MaxUint32)},
		},
		"max_retries": schema.Int64Attribute{
			Description: "The maximum number of parallel retries that Envoy will allow to the upstream cluster. If not specified, the default is 3.",
			Optional:    true,
			Validators:  []validator.Int64{int64validator.AtLeast(0), int64validator.AtMost(math.MaxUint32)},
		},
		"max_connection_pools": schema.Int64Attribute{
			Description: "The maximum number of connection pools per cluster that Envoy will concurrently support at once. If not specified, the default is unlimited. Set this for clusters which create a large number of connection pools.",
			Optional:    true,
			Validators:  []validator.Int64{int64validator.AtLeast(0), int64validator.AtMost(math.MaxUint32)},
		},
	},
}

// CircuitBreakerThresholdsAttributes are the attributes for the circuit breaker thresholds object.
var CircuitBreakerThresholdsAttributes = map[string]attr.Type{
	"max_connections":      types.Int64Type,
	"max_pending_requests": types.Int64Type,
	"max_requests":         types.Int64Type,
	"max_retries":          types.Int64Type,
	"max_connection_pools": types.Int64Type,
}

// CircuitBreakerThresholdsFromPB converts circuit breaker settings to an object.
func CircuitBreakerThresholdsFromPB(src *pb.CircuitBreakerThresholds, diagnostics *diag.Diagnostics) types.Object {
	if src == nil {
		return types.ObjectNull(CircuitBreakerThresholdsAttributes)
	}

	obj, d := types.ObjectValue(CircuitBreakerThresholdsAttributes, map[string]attr.Value{
		"max_connections":      Int64PointerValue(src.MaxConnections),
		"max_pending_requests": Int64PointerValue(src.MaxPendingRequests),
		"max_requests":         Int64PointerValue(src.MaxRequests),
		"max_retries":          Int64PointerValue(src.MaxRetries),
		"max_connection_pools": Int64PointerValue(src.MaxConnectionPools),
	})
	diagnostics.Append(d...)
	return obj
}

// CircuitBreakerThresholdsToPB converts a circuit breaker settings object to protobuf.
func CircuitBreakerThresholdsToPB(src types.Object) *pb.CircuitBreakerThresholds {
	if src.IsNull() {
		return nil
	}

	attrs := src.Attributes()
	dst := &pb.CircuitBreakerThresholds{}
	if v := attrs["max_connections"].(types.Int64); !v.IsNull() {
		dst.MaxConnections = proto.Uint32(uint32(v.ValueInt64()))
	}
	if v := attrs["max_pending_requests"].(types.Int64); !v.IsNull() {
		dst.MaxPendingRequests = proto.Uint32(uint32(v.ValueInt64()))
	}
	if v := attrs["max_requests"].(types.Int64); !v.IsNull() {
		dst.MaxRequests = proto.Uint32(uint32(v.ValueInt64()))
	}
	if v := attrs["max_retries"].(types.Int64); !v.IsNull() {
		dst.MaxRetries = proto.Uint32(uint32(v.ValueInt64()))
	}
	if v := attrs["max_connection_pools"].(types.Int64); !v.IsNull() {
		dst.MaxConnectionPools = proto.Uint32(uint32(v.ValueInt64()))
	}
	return dst
}
