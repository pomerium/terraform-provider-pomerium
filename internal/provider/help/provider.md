# Pomerium Provider

The Pomerium provider enables management of Pomerium Enterprise resources through Terraform. It provides resources and data sources for managing policies, routes, namespaces, and other Pomerium Enterprise features.

## Example Usage

```terraform
terraform {
  required_providers {
    pomerium = {
      source  = "pomerium/pomerium"
      version = "~> 0.0.7"
    }
  }
}

provider "pomerium" {
  api_url      = "https://console-api.your-domain.com"
  # Choose one authentication method:
  service_account_token = var.pomerium_service_account_token
  # shared_secret_b64   = var.shared_secret_b64
}
```

## Authentication Methods

The provider supports two authentication methods:

### Service Account Token (Recommended)

Uses a Pomerium Enterprise Service Account token for authentication. This method provides fine-grained access control at the namespace level.

```terraform
provider "pomerium" {
  api_url               = "https://console-api.your-domain.com"
  service_account_token = var.pomerium_service_account_token
}
```

### Bootstrap Service Account

Uses the Enterprise Console's shared secret for authentication. Requires `BOOTSTRAP_SERVICE_ACCOUNT=true` in the Enterprise Console configuration.

```terraform
provider "pomerium" {
  api_url          = "https://console-api.your-domain.com"
  shared_secret_b64 = var.shared_secret_b64
}
```

## Schema

### Required

- `api_url` (String) - The URL of your Pomerium Enterprise Console API endpoint.

### Optional

- `service_account_token` (String, Sensitive) - A Pomerium Enterprise Service Account token. Mutually exclusive with `shared_secret_b64`.
- `shared_secret_b64` (String, Sensitive) - The base64-encoded shared secret from your Pomerium Enterprise Console. Mutually exclusive with `service_account_token`.
- `tls_insecure_skip_verify` (Boolean) - Skip TLS certificate verification. Should only be used in testing environments.

~> **Note:** You must specify either `service_account_token` or `shared_secret_b64`, but not both.

