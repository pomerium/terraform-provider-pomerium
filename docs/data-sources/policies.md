---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "pomerium_policies Data Source - pomerium"
subcategory: ""
description: |-
  List all policies
---

# pomerium_policies (Data Source)

List all policies



<!-- schema generated by tfplugindocs -->
## Schema

### Read-Only

- `policies` (Attributes List) (see [below for nested schema](#nestedatt--policies))

<a id="nestedatt--policies"></a>
### Nested Schema for `policies`

Read-Only:

- `id` (String) Unique identifier for the policy.
- `name` (String) Name of the policy.
- `namespace_id` (String) ID of the namespace the policy belongs to.
- `ppl` (String) Policy Policy Language (PPL) string.