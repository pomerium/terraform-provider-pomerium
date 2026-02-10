package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func buildMap[T any](diagnostics *diag.Diagnostics, elementType attr.Type, src map[string]T, fn func(T) attr.Value) types.Map {
	if src == nil {
		return types.MapNull(elementType)
	}
	elements := make(map[string]attr.Value)
	for k, v := range src {
		elements[k] = fn(v)
	}
	dst, d := types.MapValue(types.StringType, elements)
	diagnostics.Append(d...)
	return dst
}

func buildMapOfStrings(src map[string]string) types.Map {
	return buildMap(new(diag.Diagnostics), types.StringType, src,
		func(v string) attr.Value {
			return types.StringValue(v)
		})
}

func buildSet[T any](diagnostics *diag.Diagnostics, elementType attr.Type, srcs []T, fn func(T) attr.Value) types.Set {
	if srcs == nil {
		return types.SetNull(elementType)
	}
	elements := make([]attr.Value, len(srcs))
	for i, v := range srcs {
		elements[i] = fn(v)
	}
	dst, d := types.SetValue(elementType, elements)
	diagnostics.Append(d...)
	return dst
}

func buildSetOfObjects[T any](diagnostics *diag.Diagnostics, elementType types.ObjectType, srcs []T, fn func(T) types.Object) types.Set {
	return buildSet(diagnostics, elementType, srcs, func(src T) attr.Value {
		return fn(src)
	})
}

func buildSetOfStrings(srcs []string) types.Set {
	return buildSet(new(diag.Diagnostics), types.StringType, srcs,
		func(src string) attr.Value {
			return types.StringValue(src)
		})
}
