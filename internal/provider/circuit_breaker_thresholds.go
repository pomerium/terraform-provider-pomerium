package provider

import (
	"math"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	CircuitBreakerThresholdsSchema = schema.SingleNestedAttribute{
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
	CircuitBreakerThresholdsAttributes = CircuitBreakerThresholdsSchema.GetType().(types.ObjectType).AttrTypes
)
