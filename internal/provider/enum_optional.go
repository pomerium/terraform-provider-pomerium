package provider

import (
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// GetValidOptionalEnumValues is for an enum that is optional and can be null
// returns a list of valid string enum values for a given protobuf enum type, excluding the zero value
// also it trims the prefix of the enum values and lowercases them to match the Terraform customary naming
func GetValidEnumValuesCanonical[T protoreflect.Enum](prefix string) []string {
	var values []string
	var v T
	descriptor := v.Descriptor()
	for i := 0; i < descriptor.Values().Len(); i++ {
		val := descriptor.Values().Get(i)
		if val.Number() == 0 {
			continue
		}
		txt := string(val.Name())
		if !strings.HasPrefix(txt, prefix+"_") {
			panic(fmt.Sprintf("enum value %q does not start with prefix %q", txt, prefix))
		}
		values = append(values, strings.ToLower(strings.TrimPrefix(txt, prefix+"_")))
	}
	return values
}

// EnumValueToPBWithDefault converts a string to a protobuf enum value.
func OptionalEnumValueToPB[T interface {
	~int32
	protoreflect.Enum
}](
	dst **T,
	src types.String,
	prefix string,
	diagnostics *diag.Diagnostics,
) {
	if src.IsNull() {
		*dst = nil
		return
	}

	key := strings.ToUpper(prefix + "_" + src.ValueString())
	var v T
	enumValue := v.Descriptor().Values().ByName(protoreflect.Name(key))
	if enumValue == nil {
		diagnostics.AddError(
			"InvalidEnumValue",
			fmt.Sprintf("The provided %s enum value %q, representing %q is not valid.", v.Descriptor().FullName(), src.ValueString(), key),
		)
		return
	}

	v = T(enumValue.Number())
	*dst = &v
}

func OptionalEnumValueFromPB[T interface {
	~int32
	protoreflect.Enum
}](
	src *T,
	prefix string,
) types.String {
	if src == nil {
		return types.StringNull()
	}
	v := (*src).Descriptor().Values().ByNumber(protoreflect.EnumNumber(*src))
	if v == nil {
		return types.StringNull()
	}

	full := string(v.Name())
	if !strings.HasPrefix(full, prefix+"_") {
		panic(fmt.Sprintf("enum value %q does not start with prefix %q", full, prefix))
	}
	return types.StringValue(strings.ToLower(strings.TrimPrefix(full, prefix+"_")))
}
