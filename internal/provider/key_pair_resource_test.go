package provider_test

import (
	"encoding/base64"
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/require"
)

func TestAccKeyPair(t *testing.T) {
	t.Parallel()

	apiURL, sharedSecret := startTestPomeriumCore(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKeyPairConfig(t, apiURL, sharedSecret, "test"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("pomerium_key_pair.test", "name", "test"),
					resource.TestCheckResourceAttrSet("pomerium_key_pair.test", "id"),
				),
			},
		},
	})
}

func testAccKeyPairConfig(t *testing.T, apiURL string, sharedSecret []byte, name string) string {
	t.Helper()

	certificate, err := os.ReadFile("../../example/test.host.pem")
	require.NoError(t, err)

	key, err := os.ReadFile("../../example/test.host-key.pem")
	require.NoError(t, err)

	return fmt.Sprintf(`
provider "pomerium" {
  api_url           = "%s"
  shared_secret_b64 = "%s"
}

resource "pomerium_key_pair" "test" {
	name = "%s"
	certificate = <<EOT
%s
EOT
	key = <<EOT
%s
EOT
}
`, apiURL, base64.StdEncoding.EncodeToString(sharedSecret), name, certificate, key)
}
