package provider_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/pomerium/enterprise-client-go/pb"
	"github.com/pomerium/enterprise-terraform-provider/internal/provider"
)

func TestConvertNamespacePermissionToPB(t *testing.T) {
	t.Parallel()

	expected := &pb.NamespacePermission{
		Id:           "NAMESPACE_PERMISSION_ID",
		NamespaceId:  "NAMESPACE_ID",
		SubjectType:  "SUBJECT_TYPE",
		SubjectId:    "SUBJECT_ID",
		Role:         "ROLE",
		OriginatorId: "terraform",
	}
	actual, diag := provider.ConvertNamespacePermissionToPB(&provider.NamespacePermissionModel{
		ID:          types.StringValue("NAMESPACE_PERMISSION_ID"),
		NamespaceID: types.StringValue("NAMESPACE_ID"),
		Role:        types.StringValue("ROLE"),
		SubjectID:   types.StringValue("SUBJECT_ID"),
		SubjectType: types.StringValue("SUBJECT_TYPE"),
	})
	if !assert.Equal(t, 0, diag.ErrorsCount()) {
		t.Log(diag.Errors())
	}
	if diff := cmp.Diff(expected, actual, protocmp.Transform()); diff != "" {
		t.Errorf("unexpected difference: %s", diff)
	}
}
