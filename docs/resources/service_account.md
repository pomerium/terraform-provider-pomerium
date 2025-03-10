---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "pomerium_service_account Resource - pomerium"
subcategory: ""
description: |-
  Service Account for Pomerium.
---

# pomerium_service_account (Resource)

Service Account for Pomerium.



<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- `description` (String) Description of the service account.
- `name` (String) Name of the service account.
- `namespace_id` (String) ID of the namespace the service account belongs to.

### Read-Only

- `expires_at` (String) Timestamp when the service account expires.
- `id` (String) Unique identifier for the service account.
- `jwt` (String, Sensitive) The Service Account JWT used for authentication. This is only populated when creating a new service account.
- `user_id` (String) User ID associated with the service account.
