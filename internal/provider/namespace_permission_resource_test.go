package provider_test

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccNamespacePermission(t *testing.T) {
	t.Parallel()

	apiURL, sharedSecret := startTestPomeriumCore(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccNamespacePermissionConfig(t, apiURL, sharedSecret),
				ExpectError: regexp.MustCompile("unsupported server type"),
			},
		},
	})
}

func testAccNamespacePermissionConfig(t *testing.T, apiURL string, sharedSecret []byte) string {
	t.Helper()

	return fmt.Sprintf(`
provider "pomerium" {
  api_url           = "%s"
  shared_secret_b64 = "%s"
}

resource "pomerium_namespace_permission" "test" {
	role = "manager"
	subject_id = "USER_ID"
	subject_type = "user"
	namespace_id = "NAMESPACE_ID"
}
`, apiURL, base64.StdEncoding.EncodeToString(sharedSecret))
}
