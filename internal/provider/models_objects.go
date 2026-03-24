package provider

import (
	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func BlobStorageSettingsObjectType() types.ObjectType {
	return types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"bucket_uri":     types.StringType,
			"managed_prefix": types.StringType,
		},
	}
}

func CircuitBreakerThresholdsObjectType() types.ObjectType {
	return CircuitBreakerThresholdsSchema.GetType().(types.ObjectType)
}

func GRPCHealthCheckObjectType() types.ObjectType {
	return types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"authority":    types.StringType,
			"service_name": types.StringType,
		},
	}
}

func HealthCheckObjectType() types.ObjectType {
	return types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"grpc_health_check":       GRPCHealthCheckObjectType(),
			"healthy_threshold":       types.Int64Type,
			"http_health_check":       HTTPHealthCheckObjectType(),
			"initial_jitter":          timetypes.GoDurationType{},
			"interval_jitter_percent": types.Int64Type,
			"interval_jitter":         timetypes.GoDurationType{},
			"interval":                timetypes.GoDurationType{},
			"tcp_health_check":        TCPHealthCheckObjectType(),
			"timeout":                 timetypes.GoDurationType{},
			"unhealthy_threshold":     types.Int64Type,
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

func RouteMCPObjectType() types.ObjectType {
	return types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"client": RouteMCPClientObjectType(),
			"server": RouteMCPServerObjectType(),
		},
	}
}

func RouteMCPClientObjectType() types.ObjectType {
	return types.ObjectType{
		AttrTypes: map[string]attr.Type{},
	}
}

func RouteMCPServerObjectType() types.ObjectType {
	return types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"authorization_server_url": types.StringType,
			"max_request_bytes":        types.Int64Type,
			"path":                     types.StringType,
			"upstream_oauth2":          RouteMCPServerUpstreamOAuth2ObjectType(),
		},
	}
}

func RouteMCPServerUpstreamOAuth2ObjectType() types.ObjectType {
	return types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"authorization_url_params": types.MapType{
				ElemType: types.StringType,
			},
			"client_id":       types.StringType,
			"client_secret":   types.StringType,
			"oauth2_endpoint": RouteMCPServerUpstreamOAuth2OAuth2EndpointObjectType(),
			"scopes": types.SetType{
				ElemType: types.StringType,
			},
		},
	}
}

func RouteMCPServerUpstreamOAuth2OAuth2EndpointObjectType() types.ObjectType {
	return types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"auth_style": types.StringType,
			"auth_url":   types.StringType,
			"token_url":  types.StringType,
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

func UpstreamTunnelObjectType() types.ObjectType {
	return types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"ssh_policy": types.StringType,
		},
	}
}
