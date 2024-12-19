package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/pomerium/pomerium/pkg/policy/parser"
)

var (
	_ basetypes.StringTypable                    = (*PolicyLanguageType)(nil)
	_ basetypes.StringValuableWithSemanticEquals = PolicyLanguage{}
)

type PolicyLanguageType struct {
	basetypes.StringType
}

func (PolicyLanguageType) String() string {
	return "pomerium.PPL"
}

func (PolicyLanguageType) ValueType(context.Context) attr.Value {
	return PolicyLanguage{}
}

func (p PolicyLanguageType) Equal(o attr.Type) bool {
	other, ok := o.(PolicyLanguageType)
	if !ok {
		return false
	}
	return p.StringType.Equal(other.StringType)
}

func (PolicyLanguageType) Parse(src basetypes.StringValue) (PolicyLanguage, error) {
	if src.IsNull() {
		return PolicyLanguage{}, nil
	}

	ppl, err := parser.New().ParseYAML(strings.NewReader(src.ValueString()))
	if err != nil {
		return PolicyLanguage{}, fmt.Errorf("failed to parse PPL: %w", err)
	}
	data, err := ppl.MarshalJSON()
	if err != nil {
		return PolicyLanguage{}, fmt.Errorf("failed to marshal PPL: %w", err)
	}
	return PolicyLanguage{
		StringValue: src,
		Policy:      *ppl,
		PolicyJSON:  data,
	}, nil
}

func (PolicyLanguageType) ValueFromString(
	_ context.Context,
	in basetypes.StringValue,
) (basetypes.StringValuable, diag.Diagnostics) {
	var diag diag.Diagnostics
	v, err := PolicyLanguageType{}.Parse(in)
	if err != nil {
		diag.AddError("failed to parse PPL", err.Error())
		return nil, diag
	}
	return v, nil
}

func (p PolicyLanguageType) ValueFromTerraform(
	ctx context.Context,
	in tftypes.Value,
) (attr.Value, error) {
	attrValue, err := p.StringType.ValueFromTerraform(ctx, in)
	if err != nil {
		return nil, err
	}

	stringVal, ok := attrValue.(basetypes.StringValue)
	if !ok {
		return nil, fmt.Errorf("expected string value, got %T", attrValue)
	}

	v, diags := p.ValueFromString(ctx, stringVal)
	if diags.HasError() {
		return nil, fmt.Errorf("failed to convert value: %v", diags)
	}
	return v, nil
}

type PolicyLanguage struct {
	basetypes.StringValue
	Policy     parser.Policy
	PolicyJSON json.RawMessage
}

func (p PolicyLanguage) Type(context.Context) attr.Type {
	return PolicyLanguageType{}
}

// Equal is different from semantic equality, see
// https://github.com/hashicorp/terraform-plugin-framework/issues/786
func (p PolicyLanguage) Equal(o attr.Value) bool {
	other, ok := o.(PolicyLanguage)
	if !ok {
		return false
	}
	return p.StringValue.Equal(other.StringValue)
}

// StringSemanticEquals compares the semantic equality of two PolicyLanguage values.
// see https://developer.hashicorp.com/terraform/plugin/framework/handling-data/types/custom#semantic-equality
func (p PolicyLanguage) StringSemanticEquals(
	_ context.Context,
	newValuable basetypes.StringValuable,
) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics

	newValue, ok := newValuable.(PolicyLanguage)
	if !ok {
		diags.AddError(
			"Semantic Equality Check Error",
			"An unexpected value type was received while performing semantic equality checks. "+
				"Please report this to the provider developers.\n\n"+
				"Expected Value Type: "+fmt.Sprintf("%T", p)+"\n"+
				"Got Value Type: "+fmt.Sprintf("%T", newValuable),
		)
		return false, diags
	}
	equal := bytes.Equal(p.PolicyJSON, newValue.PolicyJSON)
	return equal, diags
}
