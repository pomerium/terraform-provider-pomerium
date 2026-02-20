package provider_test

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccCluster(t *testing.T) {
	t.Parallel()

	apiURL, sharedSecret := startTestPomeriumCore(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccClusterConfig(t, apiURL, sharedSecret, "test"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("pomerium_cluster.test", "id"),
					resource.TestCheckResourceAttrSet("pomerium_cluster.test", "namespace_id"),
					resource.TestCheckResourceAttrSet("pomerium_cluster.test", "parent_namespace_id"),
					resource.TestCheckResourceAttr("pomerium_cluster.test", "name", "test"),
				),
			},
			{
				Config: testAccClusterConfig(t, apiURL, sharedSecret, "test-update"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("pomerium_cluster.test", "name", "test-update"),
				),
			},
		},
	})
}

func testAccClusterConfig(t *testing.T, apiURL string, sharedSecret []byte, name string) string {
	t.Helper()

	return fmt.Sprintf(`
provider "pomerium" {
  api_url           = "%s"
  shared_secret_b64 = "%s"
}

resource "pomerium_cluster" "test" {
	name = "%s"
	parent_namespace_id = "test"
	shared_secret_b64 = "%s"
	databroker_service_url = "test"
}
		`,
		apiURL,
		base64.StdEncoding.EncodeToString(sharedSecret),
		name,
		base64.StdEncoding.EncodeToString(sharedSecret))
}
