package provider

import (
	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func CircuitBreakerThresholdsObjectType() types.ObjectType {
	return CircuitBreakerThresholdsSchema.GetType().(types.ObjectType)
}

func GrpcHealthCheckObjectType() types.ObjectType {
	return types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"service_name": types.StringType,
			"authority":    types.StringType,
		},
	}
}

func HealthCheckObjectType() types.ObjectType {
	return types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"timeout":                 timetypes.GoDurationType{},
			"interval":                timetypes.GoDurationType{},
			"initial_jitter":          timetypes.GoDurationType{},
			"interval_jitter":         timetypes.GoDurationType{},
			"interval_jitter_percent": types.Int64Type,
			"unhealthy_threshold":     types.Int64Type,
			"healthy_threshold":       types.Int64Type,
			"http_health_check":       HTTPHealthCheckObjectType(),
			"tcp_health_check":        TCPHealthCheckObjectType(),
			"grpc_health_check":       GrpcHealthCheckObjectType(),
		},
	}
}

func HealthCheckPayloadObjectType() types.ObjectType {
	return types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"text":       types.StringType,
			"binary_b64": types.StringType,
		},
	}
}

func HTTPHealthCheckObjectType() types.ObjectType {
	return types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"host":               types.StringType,
			"path":               types.StringType,
			"expected_statuses":  types.SetType{ElemType: Int64RangeObjectType()},
			"retriable_statuses": types.SetType{ElemType: Int64RangeObjectType()},
			"codec_client_type":  types.StringType,
		},
	}
}

func Int64RangeObjectType() types.ObjectType {
	return types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"start": types.Int64Type,
			"end":   types.Int64Type,
		},
	}
}

func JWTGroupsFilterObjectType() types.ObjectType {
	return JWTGroupsFilterSchema.GetType().(types.ObjectType)
}

func RewriteHeaderObjectType() types.ObjectType {
	return types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"header": types.StringType,
			"value":  types.StringType,
			"prefix": types.StringType,
		},
	}
}

func TCPHealthCheckObjectType() types.ObjectType {
	return types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"send":    HealthCheckPayloadObjectType(),
			"receive": types.SetType{ElemType: HealthCheckPayloadObjectType()},
		},
	}
}
