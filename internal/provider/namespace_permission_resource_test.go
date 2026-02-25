package provider_test

import (
	"encoding/base64"
	"fmt"
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
				Config: testAccNamespacePermissionConfig(t, apiURL, sharedSecret, "USER_ID"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("pomerium_namespace_permission.test", "id"),
					resource.TestCheckResourceAttr("pomerium_namespace_permission.test", "role", "manager"),
					resource.TestCheckResourceAttr("pomerium_namespace_permission.test", "subject_id", "USER_ID"),
				),
			},
			{
				Config: testAccNamespacePermissionConfig(t, apiURL, sharedSecret, "UPDATED_USER_ID"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("pomerium_namespace_permission.test", "subject_id", "UPDATED_USER_ID"),
				),
			},
		},
	})
}

func testAccNamespacePermissionConfig(t *testing.T, apiURL string, sharedSecret []byte, subjectID string) string {
	t.Helper()

	return fmt.Sprintf(`
provider "pomerium" {
  api_url           = "%s"
  shared_secret_b64 = "%s"
}

resource "pomerium_namespace_permission" "test" {
	role = "manager"
	subject_id = "%s"
	subject_type = "user"
	namespace_id = "NAMESPACE_ID"
}
`, apiURL, base64.StdEncoding.EncodeToString(sharedSecret), subjectID)
}
