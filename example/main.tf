terraform {
  required_providers {
    pomerium = {
      source  = "pomerium/pomerium"
      version = "0.0.11"
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

  any_authenticated_user_ppl = {
    allow = {
      and = [
        {
          authenticated_user = true
        }
      ]
    }
  }
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

  log_level       = "info"
  proxy_log_level = "info"

  timeout_idle = "10m"

  darkmode_primary_color = "#49AAA1"

  jwt_groups_filter = {
    groups = ["id1", "id2"]
  }

  idp_access_token_allowed_audiences = ["aud1", "aud2"]
}

resource "pomerium_service_account" "test_sa" {
  namespace_id = pomerium_namespace.test_namespace.id
  name         = "test-service-account"
}

resource "pomerium_policy" "test_policy" {
  depends_on   = [pomerium_service_account.test_sa]
  name         = "test-policy"
  namespace_id = pomerium_namespace.test_namespace.id
  ppl = yamlencode({
    allow = {
      and = [
        {
          user = {
            is = pomerium_service_account.test_sa.id
          }
        }
      ]
    }
  })
}

resource "pomerium_policy" "test_policy_group" {
  name         = "group test policy"
  namespace_id = pomerium_namespace.test_namespace.id
  ppl = yamlencode({
    allow = {
      and = [
        {
          groups = {
            has = "gid-123456"
          }
        }
      ]
    }
  })
}
resource "pomerium_route" "test_route" {
  name         = "test-route"
  namespace_id = pomerium_namespace.test_namespace.id
  from         = "https://verify-tf.localhost.pomerium.io"
  to           = ["https://verify.pomerium.com"]
  policies = [
    pomerium_policy.test_policy_group.id,
    pomerium_policy.test_policy.id,
  ]
  jwt_groups_filter = {
    groups         = ["group1", "group2"]
    infer_from_ppl = true
  }
}

resource "pomerium_key_pair" "test_key_pair" {
  namespace_id = pomerium_namespace.test_namespace.id
  name         = "test-key-pair"
  certificate  = file("test.host.pem")
  key          = file("test.host-key.pem")
}

# Example route with prefix matching
resource "pomerium_route" "prefix_route" {
  name           = "prefix-route"
  namespace_id   = pomerium_namespace.test_namespace.id
  from           = "https://prefix.localhost.pomerium.io"
  to             = ["https://target-service.internal"]
  prefix         = "/api/"
  prefix_rewrite = "/v1/"
  policies       = [pomerium_policy.test_policy.id]

  timeout      = "30s"
  idle_timeout = "5m"

  set_request_headers = {
    "X-Custom-Header" = "custom-value"
  }
  remove_request_headers = ["Referer"]
  set_response_headers = {
    "Strict-Transport-Security" = "max-age=31536000"
  }

  allow_websockets      = true
  preserve_host_header  = true
  pass_identity_headers = true

  idp_access_token_allowed_audiences = ["aud3", "aud4"]
}

# Example route with path matching
resource "pomerium_route" "path_route" {
  name         = "path-route"
  namespace_id = pomerium_namespace.test_namespace.id
  from         = "https://path.localhost.pomerium.io"
  to           = ["https://path-service.internal"]
  path         = "/exact/path/match"

  tls_skip_verify            = true
  tls_upstream_server_name   = "internal-name"
  tls_downstream_server_name = "external-name"
}

# Example route with regex matching and rewriting
resource "pomerium_route" "regex_route" {
  name                       = "regex-route"
  namespace_id               = pomerium_namespace.test_namespace.id
  from                       = "https://regex.localhost.pomerium.io"
  to                         = ["https://regex-service.internal"]
  regex                      = "^/users/([0-9]+)/profile$"
  regex_rewrite_pattern      = "^/users/([0-9]+)/profile$"
  regex_rewrite_substitution = "/api/v1/profiles/$1"
  regex_priority_order       = 100
}

# Example route with host rewriting
resource "pomerium_route" "host_route" {
  name                                 = "host-route"
  namespace_id                         = pomerium_namespace.test_namespace.id
  from                                 = "https://host.localhost.pomerium.io"
  to                                   = ["https://host-service.internal"]
  host_rewrite                         = "internal-host"
  host_path_regex_rewrite_pattern      = "^/service/([^/]+)(/.*)$"
  host_path_regex_rewrite_substitution = "$1.internal$2"
}

# Example route with OAuth/OIDC configuration
resource "pomerium_route" "oauth_route" {
  name         = "oauth-route"
  namespace_id = pomerium_namespace.test_namespace.id
  from         = "https://oauth.localhost.pomerium.io"
  to           = ["https://protected-service.internal"]

  idp_client_id      = "custom-client-id"
  idp_client_secret  = "custom-client-secret"
  show_error_details = true
}

# Example route with Kubernetes integration
resource "pomerium_route" "kubernetes_route" {
  name         = "kubernetes-route"
  namespace_id = pomerium_namespace.test_namespace.id
  from         = "https://k8s.localhost.pomerium.io"
  to           = ["https://kubernetes-service.internal"]

  kubernetes_service_account_token = "eyJhbGciOiJS..."
  allow_spdy                       = true
  tls_upstream_allow_renegotiation = true
}

resource "pomerium_route" "advanced_route" {
  name         = "advanced-route"
  from         = "https://advanced.corp.example.com"
  to           = ["https://internal-service.example.com"]
  namespace_id = pomerium_namespace.test_namespace.id

  # Response header manipulation
  rewrite_response_headers = [
    {
      header = "Location"
      prefix = "http://internal"
      value  = "https://external"
    },
    {
      header = "Content-Security-Policy"
      value  = "default-src 'self'"
    }
  ]
  set_response_headers = {
    "Strict-Transport-Security" = "max-age=31536000"
    "X-Frame-Options"           = "DENY"
  }

  tls_custom_ca_key_pair_id = pomerium_key_pair.test_key_pair.id
  tls_skip_verify           = false

  enable_google_cloud_serverless_authentication = true
  kubernetes_service_account_token_file         = "/path/to/token"

  description = "Advanced route with security headers"
  logo_url    = "https://example.com/logo.png"

  show_error_details = true
}

# Data source examples
data "pomerium_namespaces" "all_namespaces" {}

data "pomerium_namespace" "existing_namespace" {
  id = pomerium_namespace.test_namespace.id
}

data "pomerium_route" "existing_route" {
  id = pomerium_route.test_route.id
}

data "pomerium_routes" "all_routes" {}

