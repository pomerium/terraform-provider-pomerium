---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "pomerium_key_pair Resource - pomerium"
subcategory: ""
description: |-
  KeyPairs managed by Pomerium.
---

# pomerium_key_pair (Resource)

KeyPairs managed by Pomerium.



<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `certificate` (String) PEM encoded certificate
- `name` (String) Name of the key pair
- `namespace_id` (String) ID of the namespace this key pair belongs to

### Optional

- `key` (String, Sensitive) PEM encoded private key

### Read-Only

- `id` (String) The ID of this resource.
