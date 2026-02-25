package provider_test

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccExternalDataSource(t *testing.T) {
	t.Parallel()

	apiURL, sharedSecret := startTestPomeriumCore(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccExternalDataSourceConfig(t, apiURL, sharedSecret, "user.id"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("pomerium_external_data_source.test", "id"),
					resource.TestCheckResourceAttr("pomerium_external_data_source.test", "foreign_key", "user.id"),
				),
			},
			{
				Config: testAccExternalDataSourceConfig(t, apiURL, sharedSecret, "user.name"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("pomerium_external_data_source.test", "foreign_key", "user.name"),
				),
			},
		},
	})
}

func testAccExternalDataSourceConfig(t *testing.T, apiURL string, sharedSecret []byte, foreignKey string) string {
	t.Helper()

	return fmt.Sprintf(`
provider "pomerium" {
  api_url           = "%s"
  shared_secret_b64 = "%s"
}

resource "pomerium_external_data_source" "test" {
	url = "http://localhost:8080"
	foreign_key = "%s"
	record_type = "pomerium.io/Test"
}
`, apiURL, base64.StdEncoding.EncodeToString(sharedSecret), foreignKey)
}
