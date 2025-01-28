package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/pomerium/enterprise-client-go/pb"
)

var (
	jwtGroupsFilterSchema = schema.SingleNestedAttribute{
		Optional:    true,
		Description: "JWT Groups Filter",
		Attributes: map[string]schema.Attribute{
			"groups": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    false,
				Sensitive:   false,
				Description: "Group IDs to filter",
			},
			"infer_from_ppl": schema.BoolAttribute{
				Optional: true,
			},
		},
	}
	jwtGroupsFilterSchemaAttr = map[string]attr.Type{
		"groups": types.SetType{
			ElemType: types.StringType,
		},
		"infer_from_ppl": types.BoolType,
	}
)

func JWTGroupsFilterFromPB(
	dst *types.Object,
	src *pb.JwtGroupsFilter,
	diags *diag.Diagnostics,
) {
	if src == nil {
		*dst = types.ObjectNull(jwtGroupsFilterSchemaAttr)
		return
	}

	attrs := make(map[string]attr.Value)
	if src.Groups == nil {
		attrs["groups"] = types.SetNull(types.StringType)
	} else {
		var vals []attr.Value
		for _, v := range src.Groups {
			vals = append(vals, types.StringValue(v))
		}
		attrs["groups"] = types.SetValueMust(types.StringType, vals)
	}

	attrs["infer_from_ppl"] = types.BoolValue(src.InferFromPpl)

	*dst = types.ObjectValueMust(jwtGroupsFilterSchemaAttr, attrs)
}

func JWTGroupsFilterToPB(
	ctx context.Context,
	dst **pb.JwtGroupsFilter,
	src types.Object,
	diags *diag.Diagnostics,
) {
	if src.IsNull() {
		dst = nil
		return
	}

	type jwtOptions struct {
		Groups       []string `tfsdk:"groups"`
		InferFromPpl bool     `tfsdk:"infer_from_ppl"`
	}
	var opts jwtOptions
	d := src.As(ctx, &opts, basetypes.ObjectAsOptions{
		UnhandledNullAsEmpty:    true,
		UnhandledUnknownAsEmpty: false,
	})
	diags.Append(d...)
	if d.HasError() {
		return
	}

	*dst = &pb.JwtGroupsFilter{
		Groups:       opts.Groups,
		InferFromPpl: opts.InferFromPpl,
	}
}
