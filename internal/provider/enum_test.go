package provider_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/pomerium/enterprise-client-go/pb"
	"github.com/pomerium/enterprise-terraform-provider/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnumValueToPB(t *testing.T) {
	t.Parallel()

	defaultValue := pb.IssuerFormat(-1)
	tests := []struct {
		name        types.String
		expect      pb.IssuerFormat
		expectError bool
	}{
		{types.StringValue("IssuerHostOnly"), pb.IssuerFormat_IssuerHostOnly, false},
		{types.StringValue("IssuerURI"), pb.IssuerFormat_IssuerURI, false},
		{types.StringValue("InvalidInexistentTest"), pb.IssuerFormat(-2), true},
		{types.StringNull(), defaultValue, false},
		{types.StringValue(""), defaultValue, false},
	}

	for _, tt := range tests {
		t.Run(tt.name.String(), func(t *testing.T) {
			var got pb.IssuerFormat
			var diagnostics diag.Diagnostics
			provider.EnumValueToPBWithDefault(&got, tt.name, defaultValue, &diagnostics)
			if tt.expectError {
				assert.True(t, diagnostics.HasError())
			} else {
				require.False(t, diagnostics.HasError(), diagnostics.Errors())
				assert.Equal(t, tt.expect, got)
			}
		})
	}
}

func TestEnumValueFromPB(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   pb.IssuerFormat
		expect types.String
	}{
		{pb.IssuerFormat_IssuerHostOnly, types.StringValue("IssuerHostOnly")},
		{pb.IssuerFormat_IssuerURI, types.StringValue("IssuerURI")},
		{pb.IssuerFormat(-1), types.StringNull()},
	}

	for _, tt := range tests {
		t.Run(tt.expect.String(), func(t *testing.T) {
			got := provider.EnumValueFromPB(tt.name)
			assert.Equal(t, tt.expect, got)
		})
	}
}
