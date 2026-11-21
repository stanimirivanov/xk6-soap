package archtest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/mod/modfile"
)

func TestModulePins(t *testing.T) {
	root := filepath.Join("..", "..")
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	mod, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		t.Fatal(err)
	}
	version, err := os.ReadFile(filepath.Join(root, ".go-version"))
	if err != nil {
		t.Fatal(err)
	}
	if mod.Module.Mod.Path != module {
		t.Errorf("ARCH_MODULE: module identity changed: %s", mod.Module.Mod.Path)
	}
	if mod.Go == nil || mod.Go.Version != strings.TrimSpace(string(version)) {
		t.Error("ARCH_PIN: go.mod and .go-version must agree on the supported toolchain")
	}
	if len(mod.Replace) > 0 || len(mod.Exclude) > 0 {
		t.Error("ARCH_PIN: replace/exclude directives hide dependency selection; resolve and pin the actual module instead")
	}
}
