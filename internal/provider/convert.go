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
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/enterprise-client-go/pb"
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

// FromStringList converts a protobuf string list into a list of strings.
func FromStringList[T any, TMessage interface {
	*T
	GetValues() []string
}](src TMessage) types.Set {
	if src == nil {
		return types.SetNull(types.StringType)
	}
	fields := make([]attr.Value, 0)
	for _, v := range (src).GetValues() {
		fields = append(fields, types.StringValue(v))
	}
	return types.SetValueMust(types.StringType, fields)
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
	if set.IsNull() || set.IsUnknown() {
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
	if m.IsNull() || m.IsUnknown() {
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
	if set.IsNull() || set.IsUnknown() {
		*dst = nil
		return
	}
	var values []string
	diagnostics.Append(set.ElementsAs(ctx, &values, false)...)
	if !diagnostics.HasError() {
		*dst = values
	}
}

// ToStringSliceFromList converts a types.List to string slice and handles diagnostics internally
func ToStringSliceFromList(ctx context.Context, dst *[]string, list types.List, diagnostics *diag.Diagnostics) {
	if list.IsNull() || list.IsUnknown() {
		*dst = nil
		return
	}

	var values []string
	diagnostics.Append(list.ElementsAs(ctx, &values, false)...)
	if !diagnostics.HasError() {
		*dst = values
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

// FromBearerTokenFormat converts a protobuf bearer token format into a string.
func FromBearerTokenFormat(src *pb.BearerTokenFormat) types.String {
	if src == nil {
		return types.StringNull()
	}

	switch *src {
	default:
		fallthrough
	case pb.BearerTokenFormat_BEARER_TOKEN_FORMAT_UNKNOWN:
		return types.StringValue("")
	case pb.BearerTokenFormat_BEARER_TOKEN_FORMAT_DEFAULT:
		return types.StringValue("default")
	case pb.BearerTokenFormat_BEARER_TOKEN_FORMAT_IDP_ACCESS_TOKEN:
		return types.StringValue("idp_access_token")
	case pb.BearerTokenFormat_BEARER_TOKEN_FORMAT_IDP_IDENTITY_TOKEN:
		return types.StringValue("idp_identity_token")
	}
}

// ToBearerTokenFormat converts a bearker token format string into a protobuf enum.
func ToBearerTokenFormat(src types.String) *pb.BearerTokenFormat {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	switch src.ValueString() {
	default:
		fallthrough

	case "":
		return pb.BearerTokenFormat_BEARER_TOKEN_FORMAT_UNKNOWN.Enum()
	case "default":
		return pb.BearerTokenFormat_BEARER_TOKEN_FORMAT_DEFAULT.Enum()
	case "idp_access_token":
		return pb.BearerTokenFormat_BEARER_TOKEN_FORMAT_IDP_ACCESS_TOKEN.Enum()
	case "idp_identity_token":
		return pb.BearerTokenFormat_BEARER_TOKEN_FORMAT_IDP_IDENTITY_TOKEN.Enum()
	}
}

// FromIssuerFormat converts a protobuf JWT issuer format into a string.
func FromIssuerFormat(src *pb.IssuerFormat) types.String {
	if src == nil {
		return types.StringNull()
	}

	switch *src {
	case pb.IssuerFormat_IssuerHostOnly:
		return types.StringValue("host_only")
	case pb.IssuerFormat_IssuerURI:
		return types.StringValue("uri")
	default:
		return types.StringNull()
	}
}

// ToIssuerFormat converts a JWT issuer format string into a protobuf enum.
func ToIssuerFormat(src types.String, diags *diag.Diagnostics) *pb.IssuerFormat {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	switch src.ValueString() {
	case "host_only":
		return pb.IssuerFormat_IssuerHostOnly.Enum()
	case "uri":
		return pb.IssuerFormat_IssuerURI.Enum()
	default:
		diags.AddError("unknown issuer format", fmt.Sprintf("unknown issuer format %q", src.ValueString()))
		return nil
	}
}

// UInt32ToInt64OrNull converts a uint32 to types.Int64, returning null if the value is 0
func UInt32ToInt64OrNull(value uint32) types.Int64 {
	if value > 0 {
		return types.Int64Value(int64(value))
	}
	return types.Int64Null()
}

func ToRouteStringList(ctx context.Context, dst **pb.Route_StringList, src types.Set, diagnostics *diag.Diagnostics) {
	if src.IsNull() || src.IsUnknown() {
		*dst = nil
		return
	}
	var values []string
	diagnostics.Append(src.ElementsAs(ctx, &values, false)...)
	if !diagnostics.HasError() {
		*dst = &pb.Route_StringList{Values: values}
	}
}

func ToSettingsStringList(ctx context.Context, dst **pb.Settings_StringList, src types.Set, diagnostics *diag.Diagnostics) {
	if src.IsNull() || src.IsUnknown() {
		*dst = nil
		return
	}
	var values []string
	diagnostics.Append(src.ElementsAs(ctx, &values, false)...)
	if !diagnostics.HasError() {
		*dst = &pb.Settings_StringList{Values: values}
	}
}
