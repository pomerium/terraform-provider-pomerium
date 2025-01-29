package provider

import (
	"context"
	"fmt"
	"reflect"

	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/iancoleman/strcase"
	"github.com/pomerium/enterprise-client-go/pb"
	"google.golang.org/protobuf/types/known/durationpb"

	"google.golang.org/protobuf/types/known/structpb"
)

func FromStringSliceToSet(slice []string) types.Set {
	if slice == nil {
		return types.SetNull(types.StringType)
	}
	fields := make([]attr.Value, 0)
	for _, v := range slice {
		fields = append(fields, types.StringValue(v))
	}
	return types.SetValueMust(types.StringType, fields)
}

func FromStringSliceToList(slice []string) types.List {
	if slice == nil {
		return types.ListNull(types.StringType)
	}
	fields := make([]attr.Value, 0)
	for _, v := range slice {
		fields = append(fields, types.StringValue(v))
	}
	return types.ListValueMust(types.StringType, fields)
}

// FromStringListToSet converts a Settings_StringList to a types.List
func FromStringListToSet(sl *pb.Settings_StringList) types.Set {
	if sl == nil {
		return types.SetNull(types.StringType)
	}
	return FromStringSliceToSet(sl.Values)
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
func ToStringListFromSet(ctx context.Context, dst **pb.Settings_StringList, set types.Set, diagnostics *diag.Diagnostics) {
	if set.IsNull() {
		*dst = nil
		return
	}

	var values []string
	diagnostics.Append(set.ElementsAs(ctx, &values, false)...)
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

func ToStringSliceFromSet(ctx context.Context, dst *[]string, set types.Set, diagnostics *diag.Diagnostics) {
	*dst = make([]string, 0)
	if !set.IsNull() {
		var values []string
		diagnostics.Append(set.ElementsAs(ctx, &values, false)...)
		if !diagnostics.HasError() {
			*dst = values
		}
	}
}

// ToStringSliceFromList converts a types.List to string slice and handles diagnostics internally
func ToStringSliceFromList(ctx context.Context, dst *[]string, list types.List, diagnostics *diag.Diagnostics) {
	*dst = make([]string, 0)
	if !list.IsNull() {
		var values []string
		diagnostics.Append(list.ElementsAs(ctx, &values, false)...)
		if !diagnostics.HasError() {
			*dst = values
		}
	}
}

// ToDuration converts a timetypes.Duration to durationpb.Duration
func ToDuration(dst **durationpb.Duration, src timetypes.GoDuration, diagnostics *diag.Diagnostics) {
	if src.IsNull() || src.IsUnknown() {
		*dst = nil
		return
	}

	d, diags := src.ValueGoDuration()
	diagnostics.Append(diags...)
	if diagnostics.HasError() {
		return
	}
	*dst = durationpb.New(d)
}

// FromDuration converts a durationpb.Duration to a timetypes.GoDuration
func FromDuration(d *durationpb.Duration) timetypes.GoDuration {
	if d == nil {
		return timetypes.NewGoDurationNull()
	}
	return timetypes.NewGoDurationValue(d.AsDuration())
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

// StringSliceExclude returns a new slice with elements from s1 that are not in s2
func StringSliceExclude(s1, s2 []string) []string {
	if len(s1) == 0 || len(s2) == 0 {
		return s1
	}
	m := make(map[string]struct{}, len(s2))
	for _, v := range s2 {
		m[v] = struct{}{}
	}
	var result []string
	for _, v := range s1 {
		if _, ok := m[v]; !ok {
			result = append(result, v)
		}
	}
	return result
}
