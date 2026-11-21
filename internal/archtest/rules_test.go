package archtest

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestImportRules(t *testing.T) {
	for _, tc := range []struct {
		path       string
		dependency string
		want       string
	}{
		{"soap.go", module + "/internal/adapter", ""},
		{"soap.go", module + "/internal/message", "ARCH_DEPENDENCY"},
		{"soap.go", "net/url", "ARCH_DEPENDENCY"},
		{"soap.go", "net/http", "ARCH_IO"},
		{"soap.go", "go.k6.io/k6/v2/js/modules", "ARCH_VU"},
		{"soap.go", "go.k6.io/k6", "ARCH_VU"},
		{"soap.go", "github.com/grafana/sobek", "ARCH_VU"},
		{"soap.go", "github.com/grafana/sobek/parser", "ARCH_VU"},
		{"soap.go", "github.com/knroy/go-xmlsec/v2/dsig", "ARCH_PROVIDER"},
		{"soap.go", module + "/internal/archtest", "ARCH_DEPENDENCY"},
		{"internal/adapter/soap.go", "go.k6.io/k6/v2/js/modules", ""},
		{"internal/adapter/soap.go", "github.com/grafana/sobek", ""},
		{"internal/adapter/client.go", "net/url", ""},
		{"internal/adapter/client.go", module + "/internal/message", ""},
		{"internal/adapter/keys.go", module + "/internal/keys", ""},
		{"internal/adapter/client.go", module + "/internal/clock", ""},
		{"internal/adapter/security.go", module + "/internal/wssec", ""},
		{"internal/adapter/escape.go", "os", "ARCH_IO"},
		{"internal/adapter/escape.go", "net", "ARCH_IO"},
		{"internal/adapter/escape.go", "unsafe", "ARCH_IO"},
		{"internal/adapter/keys.go", "software.sslmate.com/src/go-pkcs12", "ARCH_KEYS"},
		{"internal/message/envelope.go", "github.com/grafana/sobek", "ARCH_VU"},
		{"internal/message/envelope.go", module + "/internal/wssec", "ARCH_DEPENDENCY"},
		{"internal/message/envelope.go", module + "/internal/adapter", "ARCH_DEPENDENCY"},
		{"internal/keys/load.go", module + "/internal/adapter", "ARCH_DEPENDENCY"},
		{"internal/clock/source.go", module + "/internal/adapter", "ARCH_DEPENDENCY"},
		{"internal/wssec/provider.go", module + "/internal/adapter", "ARCH_DEPENDENCY"},
		{"internal/wssec/provider.go", module + "/internal/message", ""},
		{"internal/wssec/provider.go", "github.com/knroy/go-xmlsec/v2/dsig", ""},
		{"internal/keys/load.go", "go.k6.io/k6/v2/js/modules", "ARCH_VU"},
		{"internal/keys/load.go", "os", "ARCH_IO"},
		{"internal/wssec/escape.go", "unsafe", "ARCH_IO"},
		{"internal/wssec/escape.go", "C", "ARCH_IO"},
		{"internal/newlayer/x.go", "fmt", "ARCH_LAYER"},
		{"newlayer/x.go", "fmt", "ARCH_LAYER"},
	} {
		t.Run(tc.path+"/"+tc.dependency, func(t *testing.T) {
			source := "//go:build future\n\npackage example\nimport alias " + `"` + tc.dependency + `"` + "\n"
			violations := checkSource(tc.path, []byte(source))
			if tc.want == "" {
				if len(violations) != 0 {
					t.Fatalf("unexpected violations: %v", violations)
				}
				return
			}
			prefix := tc.path + ": " + tc.want + ": "
			if !slices.ContainsFunc(violations, func(violation string) bool { return strings.HasPrefix(violation, prefix) }) {
				t.Fatalf("got %v, want %s", violations, tc.want)
			}
		})
	}
}

func TestInvalidSourceFailsClosed(t *testing.T) {
	for _, source := range []string{"package", "package x\n//go:linkname escape net.Dial\n", "package x\n//go:generate curl https://example.test\n"} {
		if len(checkSource("soap.go", []byte(source))) == 0 {
			t.Fatalf("accepted %q", source)
		}
	}
}

func TestRepositoryArchitecture(t *testing.T) {
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if entry.IsDir() {
			switch rel {
			case ".git", ".tools", "bin", "test", "internal/archtest":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, violation := range checkSource(rel, data) {
			t.Error(violation)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
