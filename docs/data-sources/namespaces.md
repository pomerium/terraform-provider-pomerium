---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "pomerium_namespaces Data Source - pomerium"
subcategory: ""
description: |-
  List all namespaces
---

# pomerium_namespaces (Data Source)

List all namespaces



<!-- schema generated by tfplugindocs -->
## Schema

### Read-Only

- `namespaces` (Attributes List) (see [below for nested schema](#nestedatt--namespaces))

<a id="nestedatt--namespaces"></a>
### Nested Schema for `namespaces`

Optional:

- `cluster_id` (String) ID of the cluster (optional).

Read-Only:

- `id` (String) Unique identifier for the namespace.
- `name` (String) Name of the namespace.
- `parent_id` (String) ID of the parent namespace.
