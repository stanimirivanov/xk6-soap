// Package archtest implements repository architecture checks, not runtime code.
package archtest

import (
	"fmt"
	"go/parser"
	"go/token"
	"path"
	"strconv"
	"strings"
)

const module = "github.com/stanimirivanov/xk6-soap"

// A new production package requires an explicit boundary decision here.
var layers = map[string][]string{
	".":                {"internal/adapter"},
	"internal/adapter": {"internal/message", "internal/wssec", "internal/keys", "internal/clock"},
	"internal/message": {},
	"internal/keys":    {},
	"internal/clock":   {},
	"internal/wssec":   {"internal/message", "internal/keys", "internal/clock"},
}

func checkSource(name string, source []byte) []string {
	var violations []string
	report := func(rule, remedy string) {
		violations = append(violations, fmt.Sprintf("%s: %s: %s", name, rule, remedy))
	}
	layer := path.Dir(name)
	allowed, known := layers[layer]
	if !known {
		report("ARCH_LAYER", "declare the package boundary in harness/archtest/rules.go before adding production code")
	}
	file, err := parser.ParseFile(token.NewFileSet(), name, source, parser.ParseComments)
	if err != nil {
		report("ARCH_PARSE", err.Error())
		return violations
	}
	for _, group := range file.Comments {
		for _, comment := range group.List {
			if strings.HasPrefix(comment.Text, "//go:linkname") || strings.HasPrefix(comment.Text, "//go:generate") {
				report("ARCH_ESCAPE", "use an explicit reviewed build command; hidden generation/linkname escapes are prohibited")
			}
		}
	}
	for _, imp := range file.Imports {
		dependency, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			report("ARCH_PARSE", err.Error())
			continue
		}
		if dependency == "C" || dependency == "unsafe" || dependency == "plugin" || dependency == "syscall" || strings.HasPrefix(dependency, "golang.org/x/sys/") || dependency == "os" || strings.HasPrefix(dependency, "os/") || (dependency == "net" || strings.HasPrefix(dependency, "net/")) && dependency != "net/url" {
			report("ARCH_IO", "keep transport/filesystem/process access in k6 or test fixtures; forbidden import "+dependency)
		}
		k6 := dependency == "go.k6.io/k6" || strings.HasPrefix(dependency, "go.k6.io/k6/")
		sobek := dependency == "github.com/grafana/sobek" || strings.HasPrefix(dependency, "github.com/grafana/sobek/")
		if layer != "internal/adapter" && (k6 || sobek) {
			report("ARCH_VU", "keep k6/Sobek and VU state in internal/adapter")
		}
		if strings.HasPrefix(dependency, "github.com/knroy/") && layer != "internal/wssec" {
			report("ARCH_PROVIDER", "keep candidate XML/crypto implementation behind internal/wssec")
		}
		if dependency == "software.sslmate.com/src/go-pkcs12" && layer != "internal/keys" {
			report("ARCH_KEYS", "decode key containers only in internal/keys")
		}
		if layer == "." || dependency == module || strings.HasPrefix(dependency, module+"/") {
			found := false
			for _, candidate := range allowed {
				if dependency == module+"/"+candidate {
					found = true
				}
			}
			if !found {
				report("ARCH_DEPENDENCY", "forbidden dependency "+dependency+"; keep dependencies directed toward lower layers")
			}
		}
	}
	return violations
}
