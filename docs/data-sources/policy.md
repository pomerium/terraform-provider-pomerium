---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "pomerium_policy Data Source - pomerium"
subcategory: ""
description: |-
  Policy for Pomerium.
---

# pomerium_policy (Data Source)

Policy for Pomerium.



<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `id` (String) Unique identifier for the policy.

### Read-Only

- `name` (String) Name of the policy.
- `namespace_id` (String) ID of the namespace the policy belongs to.
- `ppl` (String) Policy Policy Language (PPL) string.
