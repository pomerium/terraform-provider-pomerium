package provider

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// GetValidEnumValues returns a list of valid enum values for a given protobuf enum type.
// it includes zero value as well to match its use in the current api
func GetValidEnumValues[T protoreflect.Enum]() []string {
	var values []string
	var v T
	descriptor := v.Descriptor()
	for i := 0; i < descriptor.Values().Len(); i++ {
		values = append(values, string(descriptor.Values().Get(i).Name()))
	}
	return values
}

// EnumValueToPBWithDefault converts a string to a protobuf enum value.
func EnumValueToPBWithDefault[T interface {
	~int32
	protoreflect.Enum
}](
	dst *T,
	src types.String,
	defaultValue T,
	diagnostics *diag.Diagnostics,
) {
	if src.IsNull() || src.ValueString() == "" {
		*dst = defaultValue
		return
	}

	var v T
	enumValue := v.Descriptor().Values().ByName(protoreflect.Name(src.ValueString()))
	if enumValue == nil {
		diagnostics.AddError(
			"InvalidEnumValue",
			fmt.Sprintf("The provided %s enum value %q is not valid.", v.Descriptor().FullName(), src.ValueString()),
		)
		return
	}

	*dst = T(enumValue.Number())
}

func EnumValueFromPB[T interface {
	~int32
	protoreflect.Enum
}](
	src T,
) types.String {
	v := src.Descriptor().Values().ByNumber(protoreflect.EnumNumber(src))
	if v == nil {
		return types.StringNull()
	}
	return types.StringValue(string(v.Name()))
}
