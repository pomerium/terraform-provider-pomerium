package provider

import (
	"math"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/objectvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var CircuitBreakerThresholdsSchema = schema.SingleNestedAttribute{
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

var JWTGroupsFilterSchema = schema.SingleNestedAttribute{
	Optional:    true,
	Description: "JWT Groups Filter",
	Attributes: map[string]schema.Attribute{
		"groups": schema.SetAttribute{
			ElementType: types.StringType,
			Optional:    true,
			Computed:    false,
			Sensitive:   false,
			Description: "Group IDs to include",
		},
		"infer_from_ppl": schema.BoolAttribute{
			Optional: true,
		},
	},
}

func Int64RangeSchema() schema.NestedAttributeObject {
	return schema.NestedAttributeObject{
		Attributes: map[string]schema.Attribute{
			"end": schema.Int64Attribute{
				Description: "End of status code range.",
				Required:    true,
			},
			"start": schema.Int64Attribute{
				Description: "Start of status code range.",
				Required:    true,
			},
		},
	}
}

func RouteMCPSchema() schema.SingleNestedAttribute {
	return schema.SingleNestedAttribute{
		Optional:    true,
		Description: "Model Context Protocol configuration for this route.",
		Attributes: map[string]schema.Attribute{
			"client": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "MCP Client configuration",
				Attributes:  map[string]schema.Attribute{},
				Validators: []validator.Object{
					objectvalidator.ConflictsWith(path.MatchRelative().AtParent().AtName("server")),
				},
			},
			"server": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "MCP Server configuration",
				Attributes: map[string]schema.Attribute{
					"authorization_server_url": schema.StringAttribute{
						Optional: true,
					},
					"max_request_bytes": schema.Int64Attribute{
						Optional: true,
					},
					"path": schema.StringAttribute{
						Optional: true,
					},
					"upstream_oauth2": schema.SingleNestedAttribute{
						Optional: true,
						Attributes: map[string]schema.Attribute{
							"authorization_url_params": schema.MapAttribute{
								Optional:    true,
								ElementType: types.StringType,
							},
							"client_id": schema.StringAttribute{
								Optional: true,
							},
							"client_secret": schema.StringAttribute{
								Optional:  true,
								Sensitive: true,
							},
							"oauth2_endpoint": schema.SingleNestedAttribute{
								Optional: true,
								Attributes: map[string]schema.Attribute{
									"auth_style": schema.StringAttribute{
										Optional: true,
										Validators: []validator.String{
											stringvalidator.OneOf(OAuth2AuthStyleValues...),
										},
									},
									"auth_url": schema.StringAttribute{
										Optional: true,
									},
									"token_url": schema.StringAttribute{
										Optional: true,
									},
								},
							},
							"scopes": schema.SetAttribute{
								Optional:    true,
								ElementType: types.StringType,
							},
						},
					},
				},
			},
		},
	}
}
