package provider_test

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccNamespace(t *testing.T) {
	t.Parallel()

	apiURL, sharedSecret := startTestPomeriumCore(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccNamespaceConfig(t, apiURL, sharedSecret, "test"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("pomerium_namespace.test", "name", "test"),
				),
			},
		},
	})
}

func testAccNamespaceConfig(t *testing.T, apiURL string, sharedSecret []byte, name string) string {
	t.Helper()

	return fmt.Sprintf(`
provider "pomerium" {
  api_url           = "%s"
  shared_secret_b64 = "%s"
}

resource "pomerium_namespace" "test" {
	name = "%s"
}
`, apiURL, base64.StdEncoding.EncodeToString(sharedSecret), name)
}
