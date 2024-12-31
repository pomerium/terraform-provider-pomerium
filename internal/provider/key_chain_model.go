package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type KeyPairModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	NamespaceID types.String `tfsdk:"namespace_id"`
	Certificate types.String `tfsdk:"certificate"`
	Key         types.String `tfsdk:"key"`
}
