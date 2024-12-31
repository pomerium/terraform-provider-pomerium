terraform {
  required_providers {
    pomerium = {
      source  = "pomerium/pomerium"
      version = "0.0.1"
    }
  }
}

provider "pomerium" {
  api_url                  = "https://console-api.localhost.pomerium.io"
  tls_insecure_skip_verify = true
  # service_account_token = var.pomerium_service_account_token
  shared_secret_b64 = "9OkZR6hwfmVD3a7Sfmgq58lUbFJGGz4hl/R9xbHFCAg="
}

locals {
  root_namespace_id = "9d8dbd2c-8cce-4e66-9c1f-c490b4a07243"
}
# Create resources
resource "pomerium_namespace" "test_namespace" {
  name      = "test-namespace"
  parent_id = local.root_namespace_id
}

resource "pomerium_namespace_permission" "admin_group" {
  namespace_id = pomerium_namespace.test_namespace.id
  subject_type = "group"
  subject_id   = "gid-123456"
  role         = "admin"
}

resource "pomerium_settings" "settings" {
  installation_id = "localhost-dev4"
  identity_provider_okta = {
    api_key = "key"
    url     = "http://localhost"
  }
}

resource "pomerium_policy" "test_policy" {
  name         = "test-policy"
  namespace_id = pomerium_namespace.test_namespace.id
  ppl          = <<EOF
- allow:
    and:
        - authenticated_user: true
EOF
}

resource "pomerium_route" "test_route" {
  name         = "test-route"
  namespace_id = pomerium_namespace.test_namespace.id
  from         = "https://verify-tf.localhost.pomerium.io"
  to           = ["https://verify.pomerium.com"]
  policies     = [pomerium_policy.test_policy.id]
}

resource "pomerium_key_pair" "test_key_pair" {
  namespace_id = pomerium_namespace.test_namespace.id
  name         = "test-key-pair"
  certificate  = file("test.host.pem")
  key          = file("test.host-key.pem")
}

# Data source examples
data "pomerium_namespaces" "all_namespaces" {}

data "pomerium_namespace" "existing_namespace" {
  id = pomerium_namespace.test_namespace.id
}

data "pomerium_route" "existing_route" {
  id = pomerium_route.test_route.id
}

# Output examples
output "namespace_name" {
  value = data.pomerium_namespace.existing_namespace.name
}

output "route_from" {
  value = data.pomerium_route.existing_route.from
}

output "all_namespaces" {
  value = data.pomerium_namespaces.all_namespaces.namespaces
}
