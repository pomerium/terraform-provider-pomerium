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

func (c *baseModelConverter) Bytes(src types.String) []byte {
	if src.IsNull() || src.IsUnknown() || src.ValueString() == "" {
		return nil
	}
	return []byte(src.ValueString())
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

func (c *baseModelConverter) DirectoryProvider(src SettingsModel) *string {
	if !src.IdentityProviderAuth0.IsNull() && !src.IdentityProviderAuth0.IsUnknown() {
		return proto.String("auth0")
	}
	if !src.IdentityProviderAzure.IsNull() && !src.IdentityProviderAzure.IsUnknown() {
		return proto.String("azure")
	}
	if !src.IdentityProviderBlob.IsNull() && !src.IdentityProviderBlob.IsUnknown() {
		return proto.String("blob")
	}
	if !src.IdentityProviderCognito.IsNull() && !src.IdentityProviderCognito.IsUnknown() {
		return proto.String("cognito")
	}
	if !src.IdentityProviderGitHub.IsNull() && !src.IdentityProviderGitHub.IsUnknown() {
		return proto.String("github")
	}
	if !src.IdentityProviderGitLab.IsNull() && !src.IdentityProviderGitLab.IsUnknown() {
		return proto.String("gitlab")
	}
	if !src.IdentityProviderGoogle.IsNull() && !src.IdentityProviderGoogle.IsUnknown() {
		return proto.String("google")
	}
	if !src.IdentityProviderOkta.IsNull() && !src.IdentityProviderOkta.IsUnknown() {
		return proto.String("okta")
	}
	if !src.IdentityProviderOneLogin.IsNull() && !src.IdentityProviderOneLogin.IsUnknown() {
		return proto.String("onelogin")
	}
	if !src.IdentityProviderPing.IsNull() && !src.IdentityProviderPing.IsUnknown() {
		return proto.String("ping")
	}
	return nil
}

func (c *baseModelConverter) DirectoryProviderOptions(src SettingsModel) *structpb.Struct {
	if !src.IdentityProviderAuth0.IsNull() && !src.IdentityProviderAuth0.IsUnknown() {
		return idpOptionsToStruct[Auth0Options](c.diagnostics, src.IdentityProviderAuth0)
	}
	if !src.IdentityProviderAzure.IsNull() && !src.IdentityProviderAzure.IsUnknown() {
		return idpOptionsToStruct[AzureOptions](c.diagnostics, src.IdentityProviderAzure)
	}
	if !src.IdentityProviderBlob.IsNull() && !src.IdentityProviderBlob.IsUnknown() {
		return idpOptionsToStruct[BlobOptions](c.diagnostics, src.IdentityProviderBlob)
	}
	if !src.IdentityProviderCognito.IsNull() && !src.IdentityProviderCognito.IsUnknown() {
		return idpOptionsToStruct[CognitoOptions](c.diagnostics, src.IdentityProviderCognito)
	}
	if !src.IdentityProviderGitHub.IsNull() && !src.IdentityProviderGitHub.IsUnknown() {
		return idpOptionsToStruct[GitHubOptions](c.diagnostics, src.IdentityProviderGitHub)
	}
	if !src.IdentityProviderGitLab.IsNull() && !src.IdentityProviderGitLab.IsUnknown() {
		return idpOptionsToStruct[GitLabOptions](c.diagnostics, src.IdentityProviderGitLab)
	}
	if !src.IdentityProviderGoogle.IsNull() && !src.IdentityProviderGoogle.IsUnknown() {
		return idpOptionsToStruct[GoogleOptions](c.diagnostics, src.IdentityProviderGoogle)
	}
	if !src.IdentityProviderOkta.IsNull() && !src.IdentityProviderOkta.IsUnknown() {
		return idpOptionsToStruct[OktaOptions](c.diagnostics, src.IdentityProviderOkta)
	}
	if !src.IdentityProviderOneLogin.IsNull() && !src.IdentityProviderOneLogin.IsUnknown() {
		return idpOptionsToStruct[OneLoginOptions](c.diagnostics, src.IdentityProviderOneLogin)
	}
	if !src.IdentityProviderPing.IsNull() && !src.IdentityProviderPing.IsUnknown() {
		return idpOptionsToStruct[PingOptions](c.diagnostics, src.IdentityProviderPing)
	}
	return nil
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

func (c *baseModelConverter) NullableUint64(src types.Int64) *uint64 {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}
	return proto.Uint64(uint64(src.ValueInt64()))
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

func (c *baseModelConverter) StringSliceFromString(src types.String) []string {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}
	return []string{src.ValueString()}
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

func (c *baseProtoConverter) IdentityProviderAuth0(identityProvider string, identityProviderOptions *structpb.Struct) types.Object {
	attrs, err := GetTFObjectTypes[Auth0Options]()
	if err != nil {
		c.diagnostics.AddAttributeError(path.Root("identity_provider_auth0"), err.Error(), err.Error())
		return types.ObjectNull(map[string]attr.Type{})
	}
	if identityProvider != "auth0" {
		return types.ObjectNull(attrs)
	}
	return idpOptionsFromStruct[Auth0Options](c.diagnostics, identityProviderOptions)
}

func (c *baseProtoConverter) IdentityProviderAzure(identityProvider string, identityProviderOptions *structpb.Struct) types.Object {
	attrs, err := GetTFObjectTypes[AzureOptions]()
	if err != nil {
		c.diagnostics.AddAttributeError(path.Root("identity_provider_azure"), err.Error(), err.Error())
		return types.ObjectNull(map[string]attr.Type{})
	}
	if identityProvider != "azure" {
		return types.ObjectNull(attrs)
	}
	return idpOptionsFromStruct[AzureOptions](c.diagnostics, identityProviderOptions)
}

func (c *baseProtoConverter) IdentityProviderBlob(identityProvider string, identityProviderOptions *structpb.Struct) types.Object {
	attrs, err := GetTFObjectTypes[BlobOptions]()
	if err != nil {
		c.diagnostics.AddAttributeError(path.Root("identity_provider_blob"), err.Error(), err.Error())
		return types.ObjectNull(map[string]attr.Type{})
	}
	if identityProvider != "blob" {
		return types.ObjectNull(attrs)
	}
	return idpOptionsFromStruct[BlobOptions](c.diagnostics, identityProviderOptions)
}

func (c *baseProtoConverter) IdentityProviderCognito(identityProvider string, identityProviderOptions *structpb.Struct) types.Object {
	attrs, err := GetTFObjectTypes[CognitoOptions]()
	if err != nil {
		c.diagnostics.AddAttributeError(path.Root("identity_provider_cognito"), err.Error(), err.Error())
		return types.ObjectNull(map[string]attr.Type{})
	}
	if identityProvider != "cognito" {
		return types.ObjectNull(attrs)
	}
	return idpOptionsFromStruct[CognitoOptions](c.diagnostics, identityProviderOptions)
}

func (c *baseProtoConverter) IdentityProviderGitHub(identityProvider string, identityProviderOptions *structpb.Struct) types.Object {
	attrs, err := GetTFObjectTypes[GitHubOptions]()
	if err != nil {
		c.diagnostics.AddAttributeError(path.Root("identity_provider_github"), err.Error(), err.Error())
		return types.ObjectNull(map[string]attr.Type{})
	}
	if identityProvider != "github" {
		return types.ObjectNull(attrs)
	}
	return idpOptionsFromStruct[GitHubOptions](c.diagnostics, identityProviderOptions)
}

func (c *baseProtoConverter) IdentityProviderGitLab(identityProvider string, identityProviderOptions *structpb.Struct) types.Object {
	attrs, err := GetTFObjectTypes[GitLabOptions]()
	if err != nil {
		c.diagnostics.AddAttributeError(path.Root("identity_provider_gitlab"), err.Error(), err.Error())
		return types.ObjectNull(map[string]attr.Type{})
	}
	if identityProvider != "gitlab" {
		return types.ObjectNull(attrs)
	}
	return idpOptionsFromStruct[GitLabOptions](c.diagnostics, identityProviderOptions)
}

func (c *baseProtoConverter) IdentityProviderGoogle(identityProvider string, identityProviderOptions *structpb.Struct) types.Object {
	attrs, err := GetTFObjectTypes[GoogleOptions]()
	if err != nil {
		c.diagnostics.AddAttributeError(path.Root("identity_provider_google"), err.Error(), err.Error())
		return types.ObjectNull(map[string]attr.Type{})
	}
	if identityProvider != "google" {
		return types.ObjectNull(attrs)
	}
	return idpOptionsFromStruct[GoogleOptions](c.diagnostics, identityProviderOptions)
}

func (c *baseProtoConverter) IdentityProviderOkta(identityProvider string, identityProviderOptions *structpb.Struct) types.Object {
	attrs, err := GetTFObjectTypes[OktaOptions]()
	if err != nil {
		c.diagnostics.AddAttributeError(path.Root("identity_provider_okta"), err.Error(), err.Error())
		return types.ObjectNull(map[string]attr.Type{})
	}
	if identityProvider != "okta" {
		return types.ObjectNull(attrs)
	}
	return idpOptionsFromStruct[OktaOptions](c.diagnostics, identityProviderOptions)
}

func (c *baseProtoConverter) IdentityProviderOneLogin(identityProvider string, identityProviderOptions *structpb.Struct) types.Object {
	attrs, err := GetTFObjectTypes[OneLoginOptions]()
	if err != nil {
		c.diagnostics.AddAttributeError(path.Root("identity_provider_onelogin"), err.Error(), err.Error())
		return types.ObjectNull(map[string]attr.Type{})
	}
	if identityProvider != "onelogin" {
		return types.ObjectNull(attrs)
	}
	return idpOptionsFromStruct[OneLoginOptions](c.diagnostics, identityProviderOptions)
}

func (c *baseProtoConverter) IdentityProviderPing(identityProvider string, identityProviderOptions *structpb.Struct) types.Object {
	attrs, err := GetTFObjectTypes[PingOptions]()
	if err != nil {
		c.diagnostics.AddAttributeError(path.Root("identity_provider_ping"), err.Error(), err.Error())
		return types.ObjectNull(map[string]attr.Type{})
	}
	if identityProvider != "ping" {
		return types.ObjectNull(attrs)
	}
	return idpOptionsFromStruct[PingOptions](c.diagnostics, identityProviderOptions)
}

func (c *baseProtoConverter) StringFromBytes(src []byte) types.String {
	if len(src) == 0 {
		return types.StringNull()
	}
	return types.StringValue(string(src))
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
