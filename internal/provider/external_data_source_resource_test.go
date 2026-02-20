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
				Config: testAccExternalDataSourceConfig(t, apiURL, sharedSecret),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("pomerium_external_data_source.test", "id"),
					resource.TestCheckResourceAttr("pomerium_external_data_source.test", "foreign_key", "user.id"),
				),
			},
		},
	})
}

func testAccExternalDataSourceConfig(t *testing.T, apiURL string, sharedSecret []byte) string {
	t.Helper()

	return fmt.Sprintf(`
provider "pomerium" {
  api_url           = "%s"
  shared_secret_b64 = "%s"
}

resource "pomerium_external_data_source" "test" {
	url = "http://localhost:8080"
	foreign_key = "user.id"
	record_type = "pomerium.io/Test"
}
`, apiURL, base64.StdEncoding.EncodeToString(sharedSecret))
}
