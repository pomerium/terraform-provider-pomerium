package provider_test

import (
	"iter"
	"slices"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/stretchr/testify/assert"

	"github.com/pomerium/enterprise-terraform-provider/internal/provider"
)

func TestDataSourceAttributes(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		datasource datasource.DataSource
		resource   resource.Resource
		exclude    []string
	}{
		{"cluster", provider.NewClusterDataSource(), provider.NewClusterResource(), []string{}},
		{"external_data_source", provider.NewExternalDataSourceDataSource(), provider.NewExternalDataSourceResource(), []string{}},
		{"namespace", provider.NewNamespaceDataSource(), provider.NewNamespaceResource(), []string{}},
		{"policy", provider.NewPolicyDataSource(), provider.NewPolicyResource(), []string{}},
		{"route", provider.NewRouteDataSource(), provider.NewRouteResource(), []string{}},
		{"service_account", provider.NewServiceAccountDataSource(), provider.NewServiceAccountResource(), []string{"jwt"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var dsRes datasource.SchemaResponse
			tc.datasource.Schema(t.Context(), datasource.SchemaRequest{}, &dsRes)
			var resRes resource.SchemaResponse
			tc.resource.Schema(t.Context(), resource.SchemaRequest{}, &resRes)

			dsKeys := slices.Sorted(allAttributeKeys(dsRes.Schema.Attributes))
			dsKeys = slices.DeleteFunc(dsKeys, func(k string) bool { return slices.Contains(tc.exclude, k) })
			resKeys := slices.Sorted(allAttributeKeys(resRes.Schema.Attributes))
			resKeys = slices.DeleteFunc(resKeys, func(k string) bool { return slices.Contains(tc.exclude, k) })

			assert.Equal(t, dsKeys, resKeys)
		})
	}
}

func allAttributeKeys[T any](attributes map[string]T) iter.Seq[string] {
	var visit func(key string, attr any) iter.Seq[string]
	visit = func(k string, a any) iter.Seq[string] {
		return func(yield func(string) bool) {
			if !yield(k) {
				return
			}

			if n, ok := a.(schema.NestedAttribute); ok {
				for kk, na := range n.GetNestedObject().GetAttributes() {
					for s := range visit(k+"."+kk, na) {
						if !yield(s) {
							return
						}
					}
				}
			}
		}
	}
	return func(yield func(string) bool) {
		for k, a := range attributes {
			for s := range visit(k, a) {
				if !yield(s) {
					return
				}
			}
		}
	}
}
