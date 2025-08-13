# Pomerium Terraform Provider

[![Terraform](https://img.shields.io/badge/Terraform-v1.0+-blue.svg)](https://www.terraform.io)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

The Pomerium Terraform Provider enables management of Pomerium Enterprise resources through Terraform.

## Quick Start

Configure the provider in your Terraform configuration:

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
  # Choose one of the authentication methods below:
  
  # Option 1: Service Account Token
  service_account_token = var.pomerium_service_account_token
  
  # Option 2: Bootstrap Service Account
  # shared_secret_b64 = var.shared_secret_b64
}
```

## Authentication

Two authentication methods are supported:

1. **Service Account Token** (Recommended)
   - Uses a [Pomerium Enterprise Service Account](https://www.pomerium.com/docs/capabilities/service-accounts)
   - Provides namespace-level access control
   - Configure using `service_account_token`

2. **Bootstrap Service Account**
   - Requires `BOOTSTRAP_SERVICE_ACCOUNT=true` in Enterprise Console
   - Configure using `shared_secret_b64`

## Documentation

- [Provider Documentation](https://registry.terraform.io/providers/pomerium/pomerium/latest/docs)
- [Example Configurations](https://github.com/pomerium/enterprise-terraform-provider/tree/main/example)
- [Kubernetes Deployment Guide](https://github.com/pomerium/install/tree/main/enterprise/terraform/kubernetes)

## Resources and Data Sources

Common resources:
- `pomerium_namespace`
- `pomerium_policy`
- `pomerium_route`
- `pomerium_settings`
- `pomerium_service_account`

Data sources:
- `pomerium_namespaces`
- `pomerium_namespace`
- `pomerium_route`

For detailed examples, see our [example directory](example/) or the [provider documentation](https://registry.terraform.io/providers/pomerium/pomerium/latest/docs).