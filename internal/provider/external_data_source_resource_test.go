package provider_test

import (
	"encoding/base64"
	"fmt"
	"regexp"
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
				Config:      testAccExternalDataSourceConfig(t, apiURL, sharedSecret),
				ExpectError: regexp.MustCompile(`unsupported server type`),
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
