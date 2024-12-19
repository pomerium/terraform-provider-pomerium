package provider

import (
	"context"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/pomerium/enterprise-client-go/pb"
	"google.golang.org/protobuf/types/known/durationpb"
)

func FromStringSlice(slice []string) types.List {
	if slice == nil {
		return types.ListNull(types.StringType)
	}
	fields := make([]attr.Value, 0)
	for _, v := range slice {
		fields = append(fields, types.StringValue(v))
	}
	return types.ListValueMust(types.StringType, fields)
}

// FromStringList converts a Settings_StringList to a types.List
func FromStringList(sl *pb.Settings_StringList) types.List {
	if sl == nil {
		return types.ListNull(types.StringType)
	}
	return FromStringSlice(sl.Values)
}

// FromStringMap converts a map[string]string to a types.Map
func FromStringMap(m map[string]string) types.Map {
	if m == nil {
		return types.MapNull(types.StringType)
	}
	elements := make(map[string]attr.Value)
	for k, v := range m {
		elements[k] = types.StringValue(v)
	}
	return types.MapValueMust(types.StringType, elements)
}

// ToStringList converts a types.List to Settings_StringList and handles diagnostics internally
func ToStringList(ctx context.Context, dst **pb.Settings_StringList, list types.List, diagnostics *diag.Diagnostics) {
	// Handle null list case first
	if list.IsNull() {
		*dst = nil
		return
	}

	var values []string
	diagnostics.Append(list.ElementsAs(ctx, &values, false)...)
	if !diagnostics.HasError() {
		*dst = &pb.Settings_StringList{Values: values}
	}
}

// ToStringMap converts a types.Map to map[string]string and handles diagnostics internally
func ToStringMap(ctx context.Context, dst *map[string]string, m types.Map, diagnostics *diag.Diagnostics) {
	if m.IsNull() {
		*dst = nil
		return
	}

	result := make(map[string]string)
	diagnostics.Append(m.ElementsAs(ctx, &result, false)...)
	if !diagnostics.HasError() {
		*dst = result
	}
}

// ToStringSlice converts a types.List to string slice and handles diagnostics internally
func ToStringSlice(ctx context.Context, dst *[]string, list types.List, diagnostics *diag.Diagnostics) {
	*dst = make([]string, 0)
	if !list.IsNull() {
		var values []string
		diagnostics.Append(list.ElementsAs(ctx, &values, false)...)
		if !diagnostics.HasError() {
			*dst = values
		}
	}
}

// ToDuration converts a types.String containing a duration to a durationpb.Duration and handles diagnostics internally
func ToDuration(dst **durationpb.Duration, src types.String, field string, diagnostics *diag.Diagnostics) {
	if src.IsNull() {
		*dst = nil
		return
	}

	if d, err := time.ParseDuration(src.ValueString()); err == nil {
		*dst = durationpb.New(d)
	} else {
		diagnostics.AddError("invalid "+field, err.Error())
	}
}

// FromDuration converts a durationpb.Duration to a types.String
func FromDuration(d *durationpb.Duration) types.String {
	if d == nil {
		return types.StringNull()
	}
	return types.StringValue(d.AsDuration().String())
}
