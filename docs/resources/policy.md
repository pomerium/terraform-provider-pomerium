---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "pomerium_policy Resource - pomerium"
subcategory: ""
description: |-
  Policy for Pomerium.
---

# pomerium_policy (Resource)

Policy for Pomerium.



<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `name` (String) Name of the policy.
- `namespace_id` (String) ID of the namespace the policy belongs to.
- `ppl` (String) Policy Policy Language (PPL) string.

### Read-Only

- `id` (String) Unique identifier for the policy.