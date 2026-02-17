package provider

import (
	"strings"
)

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
