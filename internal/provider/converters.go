package provider

import (
	"context"
	"encoding/base64"
	"fmt"
	"reflect"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/iancoleman/strcase"
	"golang.org/x/exp/constraints"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

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

// ToBearerTokenFormat converts a bearer token format string into a protobuf enum.
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

// FromCodecType converts a protobuf codec type into a string.
func FromCodecType(src *pb.CodecType) types.String {
	if src == nil {
		return types.StringNull()
	}

	switch *src {
	default:
		fallthrough
	case pb.CodecType_CODEC_TYPE_UNKNOWN:
		return types.StringValue("")
	case pb.CodecType_CODEC_TYPE_AUTO:
		return types.StringValue("auto")
	case pb.CodecType_CODEC_TYPE_HTTP1:
		return types.StringValue("http1")
	case pb.CodecType_CODEC_TYPE_HTTP2:
		return types.StringValue("http2")
	case pb.CodecType_CODEC_TYPE_HTTP3:
		return types.StringValue("http3")
	}
}

// ToCodecType converts a codec type string into a protobuf enum.
func ToCodecType(src types.String) *pb.CodecType {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	switch src.ValueString() {
	default:
		fallthrough
	case "":
		return pb.CodecType_CODEC_TYPE_UNKNOWN.Enum()
	case "auto":
		return pb.CodecType_CODEC_TYPE_AUTO.Enum()
	case "http1":
		return pb.CodecType_CODEC_TYPE_HTTP1.Enum()
	case "http2":
		return pb.CodecType_CODEC_TYPE_HTTP2.Enum()
	case "http3":
		return pb.CodecType_CODEC_TYPE_HTTP3.Enum()
	}
}

// FromIssuerFormat converts a protobuf JWT issuer format into a string.
func FromIssuerFormat(src *pb.IssuerFormat) types.String {
	if src == nil {
		return types.StringNull()
	}

	n := pb.IssuerFormat_name[int32(*src)]
	if n == "" {
		return types.StringNull()
	}
	return types.StringValue(n)
}

// ToIssuerFormat converts a JWT issuer format string into a protobuf enum.
func ToIssuerFormat(src types.String, diags *diag.Diagnostics) *pb.IssuerFormat {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	v, ok := pb.IssuerFormat_value[src.ValueString()]
	if !ok {
		diags.AddError("unknown issuer format", fmt.Sprintf("unknown issuer format %q", src.ValueString()))
		return nil
	}
	return pb.IssuerFormat(v).Enum()
}

// UInt32ToInt64OrNull converts a uint32 to types.Int64, returning null if the value is 0
func UInt32ToInt64OrNull(value uint32) types.Int64 {
	if value > 0 {
		return types.Int64Value(int64(value))
	}
	return types.Int64Null()
}

// Int64PointerValue converts a pointer to an integer to types.Int64, returning Null Value if the pointer is nil
func Int64PointerValue[T constraints.Integer](src *T) types.Int64 {
	if src == nil {
		return types.Int64Null()
	}
	return types.Int64Value(int64(*src))
}

type baseModelConverter struct {
	diagnostics *diag.Diagnostics
}

func (c *baseModelConverter) BytesFromBase64(p path.Path, src types.String) []byte {
	if src.IsNull() || src.IsUnknown() || src.ValueString() == "" {
		return nil
	}

	dst, err := base64.StdEncoding.DecodeString(src.ValueString())
	if err != nil {
		appendAttributeDiagnostics(c.diagnostics, p, diag.NewErrorDiagnostic("invalid base64 string", err.Error()))
		return nil
	}

	return dst
}

func (c *baseModelConverter) Duration(p path.Path, src timetypes.GoDuration) *durationpb.Duration {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	dur, diagnostics := src.ValueGoDuration()
	appendAttributeDiagnostics(c.diagnostics, p, diagnostics...)
	return durationpb.New(dur)
}

func (c *baseModelConverter) NullableBool(src types.Bool) *bool {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}
	return src.ValueBoolPointer()
}

func (c *baseModelConverter) NullableString(src types.String) *string {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}
	return src.ValueStringPointer()
}

func (c *baseModelConverter) NullableInt32(src types.Int64) *int32 {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}
	return proto.Int32(int32(src.ValueInt64()))
}

func (c *baseModelConverter) NullableUint32(src types.Int64) *uint32 {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}
	return proto.Uint32(uint32(src.ValueInt64()))
}

func (c *baseModelConverter) StringMap(p path.Path, src types.Map) map[string]string {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}
	dst := make(map[string]string)
	appendAttributeDiagnostics(c.diagnostics, p, src.ElementsAs(context.Background(), &dst, false)...)
	return dst
}

func (c *baseModelConverter) StringSliceFromList(p path.Path, src types.List) []string {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}
	var dst []string
	appendAttributeDiagnostics(c.diagnostics, p, src.ElementsAs(context.Background(), &dst, false)...)
	return dst
}

func (c *baseModelConverter) StringSliceFromSet(p path.Path, src types.Set) []string {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}
	var dst []string
	appendAttributeDiagnostics(c.diagnostics, p, src.ElementsAs(context.Background(), &dst, false)...)
	return dst
}

func (c *baseModelConverter) Timestamp(p path.Path, src types.String) *timestamppb.Timestamp {
	if src.IsNull() || src.IsUnknown() || src.ValueString() == "" {
		return nil
	}

	tm, err := time.Parse(time.RFC3339, src.ValueString())
	if err != nil {
		appendAttributeDiagnostics(c.diagnostics, p, diag.NewErrorDiagnostic("error parsing timestamp", err.Error()))
		return nil
	}

	return timestamppb.New(tm)
}

type baseProtoConverter struct {
	diagnostics *diag.Diagnostics
}

func (c *baseProtoConverter) Base64String(src []byte) types.String {
	if len(src) == 0 {
		return types.StringNull()
	}
	return types.StringValue(base64.StdEncoding.EncodeToString(src))
}

func (c *baseProtoConverter) Duration(src *durationpb.Duration) timetypes.GoDuration {
	if src == nil {
		return timetypes.NewGoDurationNull()
	}
	return timetypes.NewGoDurationValue(src.AsDuration())
}

func (c *baseProtoConverter) Timestamp(src *timestamppb.Timestamp) types.String {
	if src == nil || src.AsTime().IsZero() {
		return types.StringNull()
	}

	return types.StringValue(src.AsTime().Format(time.RFC3339))
}

func appendAttributeDiagnostics(dst *diag.Diagnostics, p path.Path, d ...diag.Diagnostic) {
	for _, d := range diag.Diagnostics(d).Errors() {
		dst.AddAttributeError(p, d.Summary(), d.Detail())
	}
	for _, d := range diag.Diagnostics(d).Warnings() {
		dst.AddAttributeWarning(p, d.Summary(), d.Detail())
	}
}

func fromSetOfObjects[T any](srcs types.Set, elementType types.ObjectType, fn func(src types.Object) T) []T {
	if srcs.IsNull() || srcs.IsUnknown() || !srcs.ElementType(context.Background()).Equal(elementType) {
		return nil
	}
	dst := make([]T, len(srcs.Elements()))
	for i, src := range srcs.Elements() {
		dst[i] = fn(src.(types.Object))
	}
	return dst
}

func toSetOfObjects[T any](srcs []T, elementType types.ObjectType, fn func(src T) types.Object) types.Set {
	if len(srcs) == 0 {
		return types.SetNull(elementType)
	}

	elements := make([]attr.Value, len(srcs))
	for i, src := range srcs {
		elements[i] = fn(src)
	}

	return types.SetValueMust(elementType, elements)
}

func zeroToNil[T comparable](v T) *T {
	var def T
	if def == v {
		return nil
	}
	return &v
}
