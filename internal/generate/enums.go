package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/iancoleman/strcase"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	_ "github.com/pomerium/enterprise-client-go/pb"
)

func generateEnums(_ context.Context) error {
	var buf bytes.Buffer

	buf.WriteString("package provider\n\n")
	buf.WriteString("import (\n")
	buf.WriteString(`	"fmt"` + "\n")
	buf.WriteString(`	"strings"` + "\n")
	buf.WriteString("\n")
	buf.WriteString("\t\"github.com/hashicorp/terraform-plugin-framework/path\"\n")
	buf.WriteString("\t\"github.com/hashicorp/terraform-plugin-framework/types\"\n")
	buf.WriteString("\n")
	buf.WriteString("\t\"github.com/pomerium/enterprise-client-go/pb\"\n")
	buf.WriteString(")\n")

	prefix := "pomerium.dashboard."

	var enumDescriptors []protoreflect.EnumDescriptor
	protoregistry.GlobalTypes.RangeEnums(func(t protoreflect.EnumType) bool {
		if strings.HasPrefix(string(t.Descriptor().FullName()), prefix) {
			enumDescriptors = append(enumDescriptors, t.Descriptor())
		}
		return true
	})

	slices.SortFunc(enumDescriptors, func(x, y protoreflect.EnumDescriptor) int {
		return strings.Compare(string(x.FullName()), string(y.FullName()))
	})

	for _, desc := range enumDescriptors {
		methodName := strings.ReplaceAll(string(desc.FullName()[len(prefix):]), ".", "")
		typeName := strings.ReplaceAll(string(desc.FullName()[len(prefix):]), ".", "_")
		valuePrefix := strcase.ToScreamingSnake(string(desc.Name())) + "_"
		buf.WriteString("\n")
		fmt.Fprintf(&buf, "func (c *ModelToEnterpriseConverter) %s(p path.Path, src types.String) *pb.%s {\n", methodName, typeName)
		buf.WriteString(`	if src.IsNull() || src.IsUnknown() {` + "\n")
		buf.WriteString(`		return nil` + "\n")
		buf.WriteString(`	}` + "\n")
		buf.WriteString("\n")
		buf.WriteString(`	switch strings.ToLower(src.ValueString()) {` + "\n")
		for i := range desc.Values().Len() {
			valueDesc := desc.Values().Get(i)
			name := strings.ToLower(strings.TrimPrefix(string(valueDesc.Name()), valuePrefix))
			if name == "unknown" || name == "undefined_do_not_use" || name == "unspecified" {
				continue
			}
			buf.WriteString(`	case "` + name + `":` + "\n")
			buf.WriteString(`		return pb.` + typeName + `(` + fmt.Sprint(valueDesc.Number()) + `).Enum()` + "\n")
		}
		buf.WriteString(`	default:` + "\n")
		buf.WriteString(`		c.diagnostics.AddAttributeError(p, "unknown ` + typeName + `", fmt.Sprintf("unknown ` + typeName + `: %s", src.ValueString()))` + "\n")
		buf.WriteString(`		return nil` + "\n")
		buf.WriteString(`	}` + "\n")
		buf.WriteString(`}` + "\n")
	}

	return os.WriteFile("./internal/provider/converters_model_to_enterprise.gen.go", buf.Bytes(), 0o0600)
}
