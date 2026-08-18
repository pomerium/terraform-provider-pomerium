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
					statecheck.ExpectKnownValue("pomerium_settings.test", tfjsonpath.New("identity_providers"), knownvalue.MapExact(map[string]knownvalue.Check{
						"idp1": knownvalue.ObjectExact(map[string]knownvalue.Check{
							"issuer":         knownvalue.StringExact("https://issuer1.example.com"),
							"jwks_url":       knownvalue.StringExact("https://issuer1.example.com/.well-known/jwks.json"),
							"supported_algs": knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact("RS256")}),
							"audiences":      knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact("AUDIENCE1")}),
						}),
						// jwks_url and supported_algs are omitted from the config, so they
						// should come back as the empty default rather than drifting.
						"idp2": knownvalue.ObjectExact(map[string]knownvalue.Check{
							"issuer":         knownvalue.StringExact("https://issuer2.example.com"),
							"jwks_url":       knownvalue.StringExact(""),
							"supported_algs": knownvalue.Null(),
							"audiences":      knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact("AUDIENCE2")}),
						}),
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
	identity_providers = {
		idp1 = {
			issuer         = "https://issuer1.example.com"
			jwks_url       = "https://issuer1.example.com/.well-known/jwks.json"
			supported_algs = ["RS256"]
			audiences      = ["AUDIENCE1"]
		}
		idp2 = {
			issuer    = "https://issuer2.example.com"
			audiences = ["AUDIENCE2"]
		}
	}
}
`, apiURL, base64.StdEncoding.EncodeToString(sharedSecret))
}
