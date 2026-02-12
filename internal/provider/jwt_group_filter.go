package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	JWTGroupsFilterSchema = schema.SingleNestedAttribute{
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
	JWTGroupsFilterSchemaAttributes = JWTGroupsFilterSchema.GetType().(types.ObjectType).AttrTypes
)
