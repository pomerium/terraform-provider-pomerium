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
					resource.TestCheckResourceAttrSet("pomerium_service_account.test", "id"),
					resource.TestCheckResourceAttr("pomerium_service_account.test", "name", "test"),
					resource.TestCheckResourceAttr("pomerium_service_account.test", "user_id", "test"),
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

data "pomerium_service_account" "test" {
	id = pomerium_service_account.test.id
}
`, apiURL, base64.StdEncoding.EncodeToString(sharedSecret), name)
}
