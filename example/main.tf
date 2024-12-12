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

# resource "pomerium_namespace" "test_namespace" {
#   name      = "test-namespace"
#   parent_id = "9d8dbd2c-8cce-4e66-9c1f-c490b4a07243"
# }

locals {
  namespace_id = "9d8dbd2c-8cce-4e66-9c1f-c490b4a07243"
}

resource "pomerium_policy" "test_policy" {
  name         = "test-policy"
  namespace_id = local.namespace_id
  ppl          = <<EOF
- allow:
    and:
        - authenticated_user: true
EOF
}

resource "pomerium_route" "test_route" {
  name         = "test-route"
  namespace_id = local.namespace_id
  from         = "https://verify-tf.localhost.pomerium.io"
  to           = ["https://verify.pomerium.com"]
  policies     = [pomerium_policy.test_policy.id]
}
