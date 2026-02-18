package provider_test

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccServiceAccount(t *testing.T) {
	t.Parallel()

	apiURL, sharedSecret := startTestPomeriumCore(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccServiceAccountConfig(t, apiURL, sharedSecret, "test"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("pomerium_service_account.test", "name", "test"),
					resource.TestCheckResourceAttrSet("pomerium_service_account.test", "id"),
				),
			},
		},
	})
}

func testAccServiceAccountConfig(t *testing.T, apiURL string, sharedSecret []byte, name string) string {
	t.Helper()

	return fmt.Sprintf(`
provider "pomerium" {
  api_url           = "%s"
  shared_secret_b64 = "%s"
}

resource "pomerium_service_account" "test" {
	name = "%s"
	namespace_id = "test"
}	
`, apiURL, base64.StdEncoding.EncodeToString(sharedSecret), name)
}
