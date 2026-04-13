package provider_test

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccSettings(t *testing.T) {
	t.Parallel()

	apiURL, sharedSecret := startTestPomeriumCore(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSettingsConfig(t, apiURL, sharedSecret),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("pomerium_settings.test", tfjsonpath.New("allow_upgrades"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.StringExact("a"), knownvalue.StringExact("b"), knownvalue.StringExact("c"),
					})),
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("pomerium_settings.test", "id"),
				),
			},
			{
				Config: testAccSettingsConfig(t, apiURL, sharedSecret),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("pomerium_settings.test", "id"),
				),
			},
		},
	})
}

func testAccSettingsConfig(t *testing.T, apiURL string, sharedSecret []byte) string {
	t.Helper()

	return fmt.Sprintf(`
provider "pomerium" {
  api_url           = "%s"
  shared_secret_b64 = "%s"
}

resource "pomerium_settings" "test" {
	grpc_address  = "0.0.0.0:5443"
	grpc_insecure = true
	allow_upgrades = ["a","b","c"]
}
`, apiURL, base64.StdEncoding.EncodeToString(sharedSecret))
}
