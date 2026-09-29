package provider

import (
	"strings"
)

// JWTSigningAlgValues are the asymmetric JWT signing algorithms allowed in
// identity_providers.supported_algs. Mirrors validSigningAlgs in
// github.com/pomerium/pomerium/config/identity_provider.go.
var JWTSigningAlgValues = []string{
	"RS256", "RS384", "RS512",
	"PS256", "PS384", "PS512",
	"ES256", "ES384", "ES512",
	"EdDSA",
}

// GetValidEnumValuesCanonicalMarkdown returns a markdown string of valid enum values for a given protobuf enum type
func GetValidEnumValuesCanonicalMarkdown(name string, values []string) string {
	var sb strings.Builder
	sb.WriteString("The following values are valid for the ")
	sb.WriteString(name)
	sb.WriteString(" field:\n")
	for _, v := range values {
		sb.WriteString("  - `")
		sb.WriteString(v)
		sb.WriteString("`\n")
	}
	return sb.String()
}
