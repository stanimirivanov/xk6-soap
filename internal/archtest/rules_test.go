package archtest

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestImportRules(t *testing.T) {
	for _, tc := range []struct {
		path       string
		dependency string
		want       bool
	}{
		{"soap.go", "go.k6.io/k6/v2/js/modules", false},
		{"soap.go", "net/url", false},
		{"soap.go", "net/http", true},
		{"internal/message/envelope.go", "github.com/grafana/sobek", true},
		{"internal/message/envelope.go", "github.com/stanimirivanov/xk6-soap/internal/wssec", true},
		{"internal/wssec/provider.go", "github.com/stanimirivanov/xk6-soap/internal/message", false},
		{"internal/keys/load.go", "go.k6.io/k6/v2/js/modules", true},
		{"internal/wssec/provider.go", "github.com/knroy/go-xmlsec/v2/dsig", false},
		{"soap.go", "github.com/knroy/go-xmlsec/v2/dsig", true},
		{"internal/keys/load.go", "os", true},
		{"internal/wssec/escape.go", "unsafe", true},
		{"internal/wssec/escape.go", "C", true},
		{"internal/newlayer/x.go", "fmt", true},
		{"newlayer/x.go", "fmt", true},
		{"soap.go", "github.com/stanimirivanov/xk6-soap/internal/archtest", true},
	} {
		t.Run(tc.path+"/"+tc.dependency, func(t *testing.T) {
			source := "//go:build future\n\npackage example\nimport alias " + `"` + tc.dependency + `"` + "\n"
			errors := checkSource(tc.path, []byte(source))
			if (len(errors) > 0) != tc.want {
				t.Fatalf("got %v, want violation=%v", errors, tc.want)
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
