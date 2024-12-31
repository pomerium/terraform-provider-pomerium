package provider

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/iancoleman/strcase"
	"github.com/pomerium/enterprise-client-go/pb"
	"google.golang.org/protobuf/types/known/durationpb"

	"google.golang.org/protobuf/types/known/structpb"
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

// GoStructToPB converts a Go struct to a protobuf Struct.
// It only supports protobuf types.String field types
// Field names are converted to snake_case.
func GoStructToPB(input interface{}) (*structpb.Struct, error) {
	if input == nil {
		return nil, nil
	}

	val := reflect.ValueOf(input)
	if val.Kind() != reflect.Struct {
		return nil, fmt.Errorf("input must be a struct, got %v", val.Kind())
	}

	fields := make(map[string]*structpb.Value)
	typ := val.Type()

	typeString := reflect.TypeOf(types.String{})
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		fieldValue := val.Field(i)
		fieldName := strcase.ToSnake(field.Name)

		if fieldValue.Type() != typeString {
			return nil, fmt.Errorf("unsupported field type %s for field %s", fieldValue.Type(), fieldName)
		}
		protoValue, ok := fieldValue.Interface().(types.String)
		if !ok {
			return nil, fmt.Errorf("unexpected type assertion for field %s", fieldName)
		}
		if !protoValue.IsNull() {
			fields[fieldName] = structpb.NewStringValue(protoValue.ValueString())
		}
	}

	return &structpb.Struct{Fields: fields}, nil
}

// PBStructToTF converts a protobuf Struct to a types.Object,
// by enumerating the `tfsdk` tags on the struct fields.
// only supports string fields
func PBStructToTF[T any](
	dst *types.Object,
	src *structpb.Struct,
	diags *diag.Diagnostics,
) {
	attrTypes, err := GetTFObjectTypes[T]()
	if err != nil {
		diags.AddError("failed to get object types", err.Error())
		return
	}

	if src == nil {
		*dst = types.ObjectNull(attrTypes)
		return
	}

	attrs := make(map[string]attr.Value)
	for k, v := range src.Fields {
		_, ok := attrTypes[k]
		if !ok {
			diags.AddAttributeWarning(
				path.Root(k),
				"unexpected field",
				fmt.Sprintf("unexpected field %s", k),
			)
			continue
		}
		str, ok := v.GetKind().(*structpb.Value_StringValue)
		if !ok {
			diags.AddAttributeError(
				path.Root(k),
				"unsupported field type",
				fmt.Sprintf("%T for field %s", v, k))
			return
		}
		attrs[k] = types.StringValue(str.StringValue)
	}

	for k := range attrTypes {
		if _, ok := src.Fields[k]; ok {
			continue
		}
		attrs[k] = types.StringNull()
	}

	v, d := types.ObjectValue(attrTypes, attrs)
	diags.Append(d...)
	if !diags.HasError() {
		*dst = v
	}
}

func GetTFObjectTypes[T any]() (map[string]attr.Type, error) {
	tm := make(map[string]attr.Type)
	var v T
	typ := reflect.TypeOf(v)
	typeString := reflect.TypeOf(types.String{})
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.Type != typeString {
			return nil, fmt.Errorf("unsupported field type %s for field %s", field.Type, field.Name)
		}
		tfsdkTag := field.Tag.Get("tfsdk")
		if tfsdkTag == "" {
			return nil, fmt.Errorf("missing tfsdk tag for field %s", field.Name)
		}
		tm[tfsdkTag] = types.StringType
	}
	return tm, nil
}

func ToByteSlice(src types.String) []byte {
	if src.IsNull() {
		return nil
	}
	val := src.ValueString()
	if val == "" {
		return nil
	}
	return []byte(val)
}
