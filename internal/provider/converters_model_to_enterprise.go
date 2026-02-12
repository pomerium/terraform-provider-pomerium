package provider

import (
	"context"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	enterprise "github.com/pomerium/enterprise-client-go/pb"
)

type ModelToEnterpriseConverter struct {
	diagnostics *diag.Diagnostics
}

func NewModelToEnterpriseConverter(diagnostics *diag.Diagnostics) *ModelToEnterpriseConverter {
	return &ModelToEnterpriseConverter{
		diagnostics: diagnostics,
	}
}

func (c *ModelToEnterpriseConverter) CreateKeyPairRequest(src KeyPairModel) *enterprise.CreateKeyPairRequest {
	return &enterprise.CreateKeyPairRequest{
		Certificate:  []byte(src.Certificate.ValueString()),
		Format:       enterprise.Format_PEM,
		Id:           nil, // generated
		Key:          []byte(src.Key.ValueString()),
		Name:         src.Name.ValueString(),
		NamespaceId:  src.NamespaceID.ValueString(),
		OriginatorId: OriginatorID,
	}
}

func (c *ModelToEnterpriseConverter) NullableString(src types.String) *string {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}
	return src.ValueStringPointer()
}

func (c *ModelToEnterpriseConverter) Policy(src PolicyModel) *enterprise.Policy {
	return &enterprise.Policy{
		AllowedDomains:   nil, // not supported
		AllowedIdpClaims: nil, // not supported
		AllowedUsers:     nil, // not supported
		CreatedAt:        nil, // not supported
		DeletedAt:        nil, // not supported
		Description:      src.Description.ValueString(),
		Enforced:         src.Enforced.ValueBool(),
		Explanation:      src.Explanation.ValueString(),
		Id:               src.ID.ValueString(),
		ModifiedAt:       nil, // not supported
		Name:             src.Name.ValueString(),
		NamespaceId:      src.NamespaceID.ValueString(),
		NamespaceName:    "", // not supported
		OriginatorId:     OriginatorID,
		Ppl:              string(src.PPL.PolicyJSON),
		Rego:             c.StringSliceFromList(src.Rego),
		Remediation:      src.Remediation.ValueString(),
		Routes:           nil, // not supported
	}
}

func (c *ModelToEnterpriseConverter) ServiceAccount(src ServiceAccountModel) *enterprise.PomeriumServiceAccount {
	return &enterprise.PomeriumServiceAccount{
		AccessedAt:   nil, // not supported
		Description:  c.NullableString(src.Description),
		ExpiresAt:    c.Timestamp(src.ExpiresAt),
		Id:           src.ID.ValueString(),
		IssuedAt:     nil, // not supported
		NamespaceId:  zeroToNil(src.NamespaceID.ValueString()),
		OriginatorId: proto.String(OriginatorID),
		UserId:       src.Name.ValueString(),
	}
}

func (c *ModelToEnterpriseConverter) StringSliceFromList(src types.List) []string {
	var dst []string
	c.diagnostics.Append(src.ElementsAs(context.Background(), &dst, false)...)
	return dst
}

func (c *ModelToEnterpriseConverter) Timestamp(src types.String) *timestamppb.Timestamp {
	if src.IsNull() || src.IsUnknown() || src.ValueString() == "" {
		return nil
	}

	tm, err := time.Parse(time.RFC1123, src.ValueString())
	if err != nil {
		c.diagnostics.AddError("error parsing timestamp", err.Error())
		return nil
	}

	return timestamppb.New(tm)
}

func (c *ModelToEnterpriseConverter) UpdateKeyPairRequest(src KeyPairModel) *enterprise.UpdateKeyPairRequest {
	return &enterprise.UpdateKeyPairRequest{
		Certificate:  []byte(src.Certificate.ValueString()),
		Format:       enterprise.Format_PEM.Enum(),
		Id:           src.ID.ValueString(),
		Key:          []byte(src.Key.ValueString()),
		Name:         c.NullableString(src.Name),
		OriginatorId: OriginatorID,
	}
}
