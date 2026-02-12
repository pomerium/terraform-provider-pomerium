package provider_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/pomerium/enterprise-client-go/pb"
	"github.com/pomerium/enterprise-terraform-provider/internal/provider"
)

func TestModelToEnterpriseConverter(t *testing.T) {
	t.Parallel()

	t.Run("CircuitBreakerThresholds", func(t *testing.T) {
		t.Parallel()

		for _, tc := range []struct {
			src    types.Object
			expect *pb.CircuitBreakerThresholds
		}{
			{types.ObjectNull(provider.CircuitBreakerThresholdsAttributes), nil},
			{types.ObjectValueMust(provider.CircuitBreakerThresholdsAttributes, map[string]attr.Value{
				"max_connections":      types.Int64Value(1),
				"max_pending_requests": types.Int64Null(),
				"max_requests":         types.Int64Null(),
				"max_retries":          types.Int64Null(),
				"max_connection_pools": types.Int64Null(),
			}), &pb.CircuitBreakerThresholds{
				MaxConnections: proto.Uint32(1),
			}},
			{types.ObjectValueMust(provider.CircuitBreakerThresholdsAttributes, map[string]attr.Value{
				"max_connections":      types.Int64Null(),
				"max_pending_requests": types.Int64Value(2),
				"max_requests":         types.Int64Value(3),
				"max_retries":          types.Int64Value(4),
				"max_connection_pools": types.Int64Value(5),
			}), &pb.CircuitBreakerThresholds{
				MaxPendingRequests: proto.Uint32(2),
				MaxRequests:        proto.Uint32(3),
				MaxRetries:         proto.Uint32(4),
				MaxConnectionPools: proto.Uint32(5),
			}},
		} {
			var diagnostics diag.Diagnostics
			actual := provider.NewModelToEnterpriseConverter(&diagnostics).CircuitBreakerThresholds(tc.src)
			assert.Equal(t, tc.expect, actual)
		}
	})

	t.Run("key pair", func(t *testing.T) {
		t.Parallel()

		t.Run("create", func(t *testing.T) {
			t.Parallel()

			expected := &pb.CreateKeyPairRequest{
				Certificate:  []byte("CERTIFICATE"),
				Format:       pb.Format_PEM,
				Key:          []byte("KEY"),
				Name:         "NAME",
				NamespaceId:  "NAMESPACE_ID",
				OriginatorId: "terraform",
			}
			var diagnostics diag.Diagnostics
			actual := provider.NewModelToEnterpriseConverter(&diagnostics).CreateKeyPairRequest(provider.KeyPairModel{
				ID:          types.StringValue("ID"),
				Name:        types.StringValue("NAME"),
				NamespaceID: types.StringValue("NAMESPACE_ID"),
				Certificate: types.StringValue("CERTIFICATE"),
				Key:         types.StringValue("KEY"),
			})
			if !assert.Equal(t, 0, diagnostics.ErrorsCount()) {
				t.Log(diagnostics.Errors())
			}
			if diff := cmp.Diff(expected, actual, protocmp.Transform()); diff != "" {
				t.Errorf("unexpected difference: %s", diff)
			}
		})

		t.Run("update", func(t *testing.T) {
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
			var diagnostics diag.Diagnostics
			actual := provider.NewModelToEnterpriseConverter(&diagnostics).UpdateKeyPairRequest(provider.KeyPairModel{
				ID:          types.StringValue("ID"),
				Name:        types.StringValue("NAME"),
				NamespaceID: types.StringValue("NAMESPACE_ID"),
				Certificate: types.StringValue("CERTIFICATE"),
				Key:         types.StringValue("KEY"),
			})
			if !assert.Equal(t, 0, diagnostics.ErrorsCount()) {
				t.Log(diagnostics.Errors())
			}
			if diff := cmp.Diff(expected, actual, protocmp.Transform()); diff != "" {
				t.Errorf("unexpected difference: %s", diff)
			}
		})
	})

	t.Run("namespace permission", func(t *testing.T) {
		t.Parallel()

		expected := &pb.NamespacePermission{
			Id:           "NAMESPACE_PERMISSION_ID",
			NamespaceId:  "NAMESPACE_ID",
			SubjectType:  "SUBJECT_TYPE",
			SubjectId:    "SUBJECT_ID",
			Role:         "ROLE",
			OriginatorId: "terraform",
		}
		var diagnostics diag.Diagnostics
		actual := provider.NewModelToEnterpriseConverter(&diagnostics).NamespacePermission(provider.NamespacePermissionModel{
			ID:          types.StringValue("NAMESPACE_PERMISSION_ID"),
			NamespaceID: types.StringValue("NAMESPACE_ID"),
			Role:        types.StringValue("ROLE"),
			SubjectID:   types.StringValue("SUBJECT_ID"),
			SubjectType: types.StringValue("SUBJECT_TYPE"),
		})
		if !assert.Equal(t, 0, diagnostics.ErrorsCount()) {
			t.Log(diagnostics.Errors())
		}
		if diff := cmp.Diff(expected, actual, protocmp.Transform()); diff != "" {
			t.Errorf("unexpected difference: %s", diff)
		}
	})

	t.Run("policy", func(t *testing.T) {
		t.Parallel()

		expected := &pb.Policy{
			Description:  "DESCRIPTION",
			Enforced:     true,
			Explanation:  "EXPLANATION",
			Id:           "ID",
			Name:         "NAME",
			NamespaceId:  "NAMESPACE_ID",
			OriginatorId: "terraform",
			Rego:         []string{"REGO"},
			Remediation:  "REMEDIATION",
		}
		var diagnostics diag.Diagnostics
		actual := provider.NewModelToEnterpriseConverter(&diagnostics).Policy(provider.PolicyModel{
			Description: types.StringValue("DESCRIPTION"),
			Enforced:    types.BoolValue(true),
			Explanation: types.StringValue("EXPLANATION"),
			ID:          types.StringValue("ID"),
			Name:        types.StringValue("NAME"),
			NamespaceID: types.StringValue("NAMESPACE_ID"),
			PPL:         provider.PolicyLanguage{},
			Rego:        types.ListValueMust(types.StringType, []attr.Value{types.StringValue("REGO")}),
			Remediation: types.StringValue("REMEDIATION"),
		})
		if !assert.Equal(t, 0, diagnostics.ErrorsCount()) {
			t.Log(diagnostics.Errors())
		}
		if diff := cmp.Diff(expected, actual, protocmp.Transform()); diff != "" {
			t.Errorf("unexpected difference: %s", diff)
		}
	})
}
