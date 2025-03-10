---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "pomerium_route Resource - pomerium"
subcategory: ""
description: |-
  Route for Pomerium.
---

# pomerium_route (Resource)

Route for Pomerium.



<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `from` (String) The external URL for a proxied request. Must contain a scheme and Hostname, must not contain a path.
- `name` (String) Name of the route.
- `namespace_id` (String) ID of the namespace the route belongs to.
- `to` (Set of String) The destination(s) of a proxied request. Must contain a scheme and Hostname, with an optional weight.

### Optional

- `allow_spdy` (Boolean) If applied, this setting enables Pomerium to proxy SPDY protocol upgrades.
- `allow_websockets` (Boolean) If applied, this setting enables Pomerium to proxy websocket connections.
- `bearer_token_format` (String) Bearer token format.
- `description` (String) Description of the route.
- `enable_google_cloud_serverless_authentication` (Boolean) Enable Google Cloud serverless authentication.
- `host_path_regex_rewrite_pattern` (String) Rewrites the Host header according to a regular expression matching the path.
- `host_path_regex_rewrite_substitution` (String) Rewrites the Host header according to a regular expression matching the substitution.
- `host_rewrite` (String) Rewrites the Host header to a new literal value.
- `host_rewrite_header` (String) Rewrites the Host header to match an incoming header value.
- `idle_timeout` (String) Sets the time to terminate the upstream connection if there are no active streams. Defaults to 5 minutes.
- `idp_access_token_allowed_audiences` (Set of String) IDP access token allowed audiences.
- `idp_client_id` (String) IDP client ID.
- `idp_client_secret` (String) IDP client secret.
- `jwt_groups_filter` (Attributes) JWT Groups Filter (see [below for nested schema](#nestedatt--jwt_groups_filter))
- `jwt_issuer_format` (String) Format for JWT issuer strings. Use 'IssuerHostOnly' for hostname without scheme or trailing slash, or 'IssuerURI' for complete URI including scheme and trailing slash.
- `kubernetes_service_account_token` (String) Kubernetes service account token.
- `kubernetes_service_account_token_file` (String) Path to the Kubernetes service account token file.
- `load_balancing_policy` (String) The following values are valid for the Load Balancing Policy field:

- `round_robin`
- `maglev`
- `random`
- `ring_hash`
- `least_request`
- `logo_url` (String) URL to the logo image.
- `pass_identity_headers` (Boolean) If applied, passes X-Pomerium-Jwt-Assertion header and JWT Claims Headers to the upstream application.
- `path` (String) Matches incoming requests with a path that is an exact match for the specified path.
- `policies` (Set of String) List of policy IDs associated with the route.
- `prefix` (String) Matches incoming requests with a path that begins with the specified prefix.
- `prefix_rewrite` (String) While forwarding a request, Prefix Rewrite swaps the matched prefix (or path) with the specified value.
- `preserve_host_header` (Boolean) Passes the host header from the incoming request to the proxied host, instead of the destination hostname.
- `regex` (String) Matches incoming requests with a path that matches the specified regular expression.
- `regex_priority_order` (Number) Regex priority order.
- `regex_rewrite_pattern` (String) Rewrites the URL path according to the regex rewrite pattern.
- `regex_rewrite_substitution` (String) Rewrites the URL path according to the regex rewrite substitution.
- `remove_request_headers` (Set of String) Removes given request headers so they do not reach the upstream server.
- `rewrite_response_headers` (Attributes Set) Modifies response headers before they are returned to the client. 'Header' matches the HTTP header name; 'prefix' will be replaced with 'value'. (see [below for nested schema](#nestedatt--rewrite_response_headers))
- `set_request_headers` (Map of String) Sets static and dynamic values for given request headers. Available substitutions: ${pomerium.id_token}, ${pomerium.access_token}, ${pomerium.client_cert_fingerprint}.
- `set_response_headers` (Map of String) Sets static HTTP Response Header values for a route. These headers take precedence over globally set response headers.
- `show_error_details` (Boolean) If applied, shows error details, including policy explanation and remediation for 403 Forbidden responses.
- `stat_name` (String) Name of the stat.
- `timeout` (String) Sets the per-route timeout value. Cannot exceed global timeout values. Defaults to 30 seconds.
- `tls_client_key_pair_id` (String) Client key pair ID for TLS client authentication.
- `tls_custom_ca_key_pair_id` (String) Custom CA key pair ID for TLS verification.
- `tls_downstream_server_name` (String) TLS downstream server name.
- `tls_skip_verify` (Boolean) If applied, Pomerium accepts any certificate presented by the upstream server and any Hostname in that certificate. Use for testing only.
- `tls_upstream_allow_renegotiation` (Boolean) TLS upstream allow renegotiation.
- `tls_upstream_server_name` (String) This server name overrides the Hostname in the 'To:' field, and will be used to verify the certificate name.

### Read-Only

- `id` (String) Unique identifier for the route.

<a id="nestedatt--jwt_groups_filter"></a>
### Nested Schema for `jwt_groups_filter`

Optional:

- `groups` (Set of String) Group IDs to include
- `infer_from_ppl` (Boolean)


<a id="nestedatt--rewrite_response_headers"></a>
### Nested Schema for `rewrite_response_headers`

Required:

- `header` (String) Header name to rewrite
- `value` (String) New value for the header

Optional:

- `prefix` (String) Prefix matcher for the header
