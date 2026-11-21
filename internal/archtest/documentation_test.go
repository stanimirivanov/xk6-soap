package archtest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Contract pages use ordinary inline links and name each Go evidence test in its link label.
func TestContractDocumentationReferences(t *testing.T) {
	inlineLink := regexp.MustCompile(`\[([^\[\]\n]+)\]\(([^()\s]+)\)`)
	heading := regexp.MustCompile(`(?m)^#{1,6} +(.+)$`)
	testName := regexp.MustCompile(`^Test[A-Z]\w*$`)
	punctuation := regexp.MustCompile(`[^\p{L}\p{N} _-]`)
	for _, doc := range []string{
		"README.md", "docs/architecture.md", "docs/contracts.md", "docs/jmeter-map.md",
		"docs/adr/README.md", "docs/keys.md", "docs/object-payloads.md", "docs/plain-api.md",
		"docs/security-policy.md", "test/interop/README.md", "tasks/plan.md",
		"docs/release.md", "RELEASE_NOTES.md", "THIRD_PARTY_NOTICES.md",
	} {
		t.Run(doc, func(t *testing.T) {
			root := filepath.Join("..", "..")
			path := filepath.Join(root, doc)
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			named := 0
			for _, link := range inlineLink.FindAllStringSubmatch(string(content), -1) {
				label := strings.Trim(link[1], "`")
				address := link[2]
				if strings.Contains(address, "://") {
					continue
				}
				target, fragment, _ := strings.Cut(address, "#")
				destination := path
				if target != "" {
					destination = filepath.Join(filepath.Dir(path), target)
				}
				info, err := os.Stat(destination)
				if err != nil {
					t.Errorf("link %q: %v", address, err)
					continue
				}
				if fragment != "" && filepath.Ext(destination) == ".md" {
					page, err := os.ReadFile(destination)
					if err != nil {
						t.Error(err)
						continue
					}
					found := false
					for _, match := range heading.FindAllStringSubmatch(string(page), -1) {
						slug := strings.ReplaceAll(punctuation.ReplaceAllString(strings.ToLower(match[1]), ""), " ", "-")
						found = found || slug == fragment
					}
					if !found {
						t.Errorf("link %q: heading not found", address)
					}
				}
				if strings.HasSuffix(destination, "_test.go") || testName.MatchString(label) {
					named++
					if info.IsDir() || !strings.HasSuffix(destination, "_test.go") || !declaresEvidenceTest(t, destination, label) {
						t.Errorf("evidence link %q: %s is not a named Go test", address, label)
					}
				}
			}
			if doc == "docs/contracts.md" && named == 0 {
				t.Error("missing named evidence tests")
			}
		})
	}
}

func declaresEvidenceTest(t *testing.T, path, name string) bool {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Error(err)
		return false
	}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Recv == nil && function.Name.Name == name && strings.HasPrefix(name, "Test") {
			return true
		}
	}
	return false
}
