package provider_test

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccRoute(t *testing.T) {
	t.Parallel()

	apiURL, sharedSecret := startTestPomeriumCore(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRouteConfig(t, apiURL, sharedSecret, "test", ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("pomerium_route.test", "name", "test"),
					resource.TestCheckResourceAttrSet("pomerium_route.test", "id"),
				),
			},
			{
				Config: testAccRouteConfig(t, apiURL, sharedSecret, "updated-name", ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("pomerium_route.test", "name", "updated-name"),
					resource.TestCheckResourceAttr("pomerium_route.test", "health_checks.0.http_health_check.codec_client_type", "http1"),
				),
			},
			{
				Config: testAccRouteConfig(t, apiURL, sharedSecret, "updated-name", "mcp = { client = {} }"),
			},
		},
	})
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccRouteConfig(t, apiURL, sharedSecret, "updated-name", "mcp = {}"),
				ExpectError: regexp.MustCompile(`Attribute "mcp.client" must be specified when "mcp" is specified`),
			},
			{
				Config:      testAccRouteConfig(t, apiURL, sharedSecret, "updated-name", "mcp = { client = {} \n server = {} }"),
				ExpectError: regexp.MustCompile(`Attribute "mcp.server" cannot be specified when "mcp.client" is specified`),
			},
		},
	})
}

func testAccRouteConfig(t *testing.T, apiURL string, sharedSecret []byte, name string, extraConfig string) string {
	t.Helper()

	return fmt.Sprintf(`
provider "pomerium" {
  api_url           = "%s"
  shared_secret_b64 = "%s"
}

resource "pomerium_route" "test" {
	name = "%s"
	from = "https://from.example.com"
	to = ["https://to.example.com"]
	health_checks = [{
		http_health_check = {}
	}]
	%s
}

data "pomerium_route" "test" {
	id = pomerium_route.test.id
}
`, apiURL, base64.StdEncoding.EncodeToString(sharedSecret), name, extraConfig)
}
