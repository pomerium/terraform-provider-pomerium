package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// OptionalString returns a pointer to the string value if not null, otherwise nil
func OptionalString(v types.String) *string {
	if v.IsNull() {
		return nil
	}
	value := v.ValueString()
	return &value
}

// OptionalBool returns a pointer to the bool value if not null, otherwise nil
func OptionalBool(v types.Bool) *bool {
	if v.IsNull() {
		return nil
	}
	value := v.ValueBool()
	return &value
}

// OptionalFloat64 returns a pointer to the float64 value if not null, otherwise nil
func OptionalFloat64(v types.Float64) *float64 {
	if v.IsNull() {
		return nil
	}
	value := v.ValueFloat64()
	return &value
}
