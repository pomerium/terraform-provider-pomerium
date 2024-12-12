package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ServiceAccountSchema returns the schema for service account resources and data sources
func ServiceAccountSchema(computed bool) schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Service Account for Pomerium.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Unique identifier for the service account.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "Name of the service account.",
				Required:    !computed,
				Computed:    computed,
			},
			"namespace_id": schema.StringAttribute{
				Description: "ID of the namespace the service account belongs to.",
				Required:    !computed,
				Computed:    computed,
			},
			"description": schema.StringAttribute{
				Description: "Description of the service account.",
				Optional:    !computed,
				Computed:    computed,
			},
			"user_id": schema.StringAttribute{
				Description: "User ID associated with the service account.",
				Computed:    true,
			},
			"expires_at": schema.StringAttribute{
				Description: "Timestamp when the service account expires.",
				Computed:    true,
			},
		},
	}
}

// NamespaceSchema returns the schema for namespace resources and data sources
func NamespaceSchema(computed bool) schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Namespace for Pomerium.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Unique identifier for the namespace.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "Name of the namespace.",
				Required:    !computed,
				Computed:    computed,
			},
			"parent_id": schema.StringAttribute{
				Description: "ID of the parent namespace (optional).",
				Optional:    !computed,
				Computed:    computed,
			},
		},
	}
}

// RouteSchema returns the schema for route resources and data sources
func RouteSchema(computed bool) schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Route for Pomerium.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Unique identifier for the route.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "Name of the route.",
				Required:    !computed,
				Computed:    computed,
			},
			"from": schema.StringAttribute{
				Description: "From URL.",
				Required:    !computed,
				Computed:    computed,
			},
			"to": schema.ListAttribute{
				ElementType: types.StringType,
				Description: "To URLs.",
				Required:    !computed,
				Computed:    computed,
			},
			"namespace_id": schema.StringAttribute{
				Description: "ID of the namespace the route belongs to.",
				Required:    !computed,
				Computed:    computed,
			},
			"policies": schema.ListAttribute{
				ElementType: types.StringType,
				Description: "List of policy IDs associated with the route.",
				Optional:    !computed,
				Computed:    computed,
			},
		},
	}
}

// PolicySchema returns the schema for policy resources and data sources
func PolicySchema(computed bool) schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Policy for Pomerium.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Unique identifier for the policy.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "Name of the policy.",
				Required:    !computed,
				Computed:    computed,
			},
			"namespace_id": schema.StringAttribute{
				Description: "ID of the namespace the policy belongs to.",
				Required:    !computed,
				Computed:    computed,
			},
			"ppl": schema.StringAttribute{
				Description: "Policy Policy Language (PPL) string.",
				Required:    !computed,
				Computed:    computed,
			},
		},
	}
}
