package archtest

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeclarationStyle(t *testing.T) {
	for _, tc := range []struct {
		source string
		bad    bool
	}{
		{"package x; type T struct { A, B *bool }", true},
		{"package x; type T struct { A string; B int }", true},
		{"package x; var a, b int", true},
		{"package x; const a, b = 1, 2", true},
		{"package x; var (a int; b int)", true},
		{"package x; var a int; var b int", true},
		{"package x\ntype T struct {\n A *bool\n B *bool\n}", false},
		{"package x\nvar (\n a int\n b int\n)", false},
		{"package x\nfunc f(a, b int) (int, int) { x, y := a, b; return x, y }", false},
		{"package x\ntype T struct {\n *Other\n A string `json:\"a\"`\n}", false},
	} {
		violations := checkDeclarationStyle("example.go", []byte(tc.source))
		if (len(violations) > 0) != tc.bad {
			t.Fatalf("source %q: %v; want violation=%v", tc.source, violations, tc.bad)
		}
	}
}

func TestRepositoryDeclarationStyle(t *testing.T) {
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", ".tools", "bin":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		data, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		rel, e := filepath.Rel(root, path)
		if e != nil {
			return e
		}
		for _, violation := range checkDeclarationStyle(filepath.ToSlash(rel), data) {
			t.Error(violation)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
