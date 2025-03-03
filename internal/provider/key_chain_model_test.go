package provider_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/pomerium/enterprise-client-go/pb"
	"github.com/pomerium/enterprise-terraform-provider/internal/provider"
)

func TestConvertKeyPairToCreatePB(t *testing.T) {
	t.Parallel()

	expected := &pb.CreateKeyPairRequest{
		Certificate:  []byte("CERTIFICATE"),
		Format:       pb.Format_PEM,
		Key:          []byte("KEY"),
		Name:         "NAME",
		NamespaceId:  "NAMESPACE_ID",
		OriginatorId: "terraform",
	}
	actual := provider.ConvertKeyPairToCreatePB(&provider.KeyPairModel{
		ID:          types.StringValue("ID"),
		Name:        types.StringValue("NAME"),
		NamespaceID: types.StringValue("NAMESPACE_ID"),
		Certificate: types.StringValue("CERTIFICATE"),
		Key:         types.StringValue("KEY"),
	})
	if diff := cmp.Diff(expected, actual, protocmp.Transform()); diff != "" {
		t.Errorf("unexpected difference: %s", diff)
	}
}

func TestConvertKeyPairToUpdatePB(t *testing.T) {
	t.Parallel()

	fmt := pb.Format_PEM
	expected := &pb.UpdateKeyPairRequest{
		Certificate:  []byte("CERTIFICATE"),
		Format:       &fmt,
		Id:           "ID",
		Key:          []byte("KEY"),
		Name:         proto.String("NAME"),
		OriginatorId: "terraform",
	}
	actual := provider.ConvertKeyPairToUpdatePB(&provider.KeyPairModel{
		ID:          types.StringValue("ID"),
		Name:        types.StringValue("NAME"),
		NamespaceID: types.StringValue("NAMESPACE_ID"),
		Certificate: types.StringValue("CERTIFICATE"),
		Key:         types.StringValue("KEY"),
	})
	if diff := cmp.Diff(expected, actual, protocmp.Transform()); diff != "" {
		t.Errorf("unexpected difference: %s", diff)
	}
}
