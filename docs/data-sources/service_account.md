---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "pomerium_service_account Data Source - pomerium"
subcategory: ""
description: |-
  Service Account for Pomerium.
---

# pomerium_service_account (Data Source)

Service Account for Pomerium.



<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `id` (String) Unique identifier for the service account.

### Read-Only

- `description` (String) Description of the service account.
- `expires_at` (String) Timestamp when the service account expires.
- `name` (String) Name of the service account.
- `namespace_id` (String) ID of the namespace the service account belongs to.
- `user_id` (String) User ID associated with the service account.
