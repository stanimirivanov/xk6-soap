package interop

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"slices"
	"strings"
	"testing"
)

type matrixRow struct {
	SOAPVersion string
	Order       string
	Bits        int
	Target      string
	Endpoint    string
	Outcomes    []string
	Test        string
}

type matrixProfile struct {
	ID           string
	Algorithm    string
	Digest       string
	KeyID        string
	Mode         string
	Marker       string
	SOAPVersions []string
	Coverage     []string
	Test         string
}

type interoperabilityMatrix struct {
	Core                   []matrixRow
	Algorithms             []matrixProfile
	Identifiers            []matrixProfile
	Profiles               []matrixProfile
	Unsupported            []string
	UnclaimedCrossProducts []string
}

func loadMatrix(t *testing.T) interoperabilityMatrix {
	t.Helper()
	raw, err := os.ReadFile("matrix.json")
	if err != nil {
		t.Fatal(err)
	}
	var matrix interoperabilityMatrix
	if err := json.Unmarshal(raw, &matrix); err != nil {
		t.Fatal(err)
	}
	return matrix
}

func TestInteropMatrixManifest(t *testing.T) {
	matrix := loadMatrix(t)
	versions := []string{"1.1", "1.2"}
	orders := []string{"sign-then-encrypt", "encrypt-then-sign"}
	sizes := []int{128, 256}
	targets := []string{"content", "body", "headers"}
	expected := map[string]bool{}
	for _, version := range versions {
		for _, order := range orders {
			for _, bits := range sizes {
				for _, target := range targets {
					expected[matrixKey(version, order, bits, target)] = true
				}
			}
		}
	}
	endpoints := map[string]bool{}
	for _, row := range matrix.Core {
		key := matrixKey(row.SOAPVersion, row.Order, row.Bits, row.Target)
		if !expected[key] {
			t.Errorf("unexpected or duplicate core row %s", key)
		}
		delete(expected, key)
		if row.Endpoint == "" || endpoints[row.Endpoint] || !slices.Equal(row.Outcomes, []string{"success", "fault"}) || row.Test != "TestK6InteropMatrix" {
			t.Errorf("invalid endpoint, outcome or evidence for %s", key)
		}
		endpoints[row.Endpoint] = true
	}
	if len(expected) != 0 {
		t.Errorf("missing core combinations: %v", expected)
	}
	tests := matrixTestNames(t)
	if !tests["TestK6InteropMatrix"] {
		t.Error("missing native core matrix test")
	}
	for _, profile := range slices.Concat(matrix.Algorithms, matrix.Identifiers, matrix.Profiles) {
		if !tests[profile.Test] || !slices.Equal(profile.SOAPVersions, versions) {
			t.Errorf("profile has missing test evidence or SOAP version: %+v", profile)
		}
	}
	algorithms := map[string]bool{}
	digests := map[string]bool{}
	for _, p := range matrix.Algorithms {
		if algorithms[p.Algorithm] || p.Mode == "" || p.Test != "TestK6SignatureAlgorithms" {
			t.Errorf("invalid algorithms row: %+v", p)
		}
		algorithms[p.Algorithm] = true
		digests[p.Digest] = true
	}
	identifiers := map[string]bool{}
	for _, p := range matrix.Identifiers {
		if identifiers[p.KeyID] || p.Mode == "" || p.Marker == "" || p.Test != "TestK6SignatureKeyIdentifiers" {
			t.Errorf("invalid identifier row: %+v", p)
		}
		identifiers[p.KeyID] = true
	}
	assertMatrixDimensions(t, algorithms, []string{"rsa-sha256", "rsa-sha384", "rsa-sha512", "ecdsa-sha256", "ecdsa-sha384", "ecdsa-sha512"})
	assertMatrixDimensions(t, digests, []string{"sha256", "sha384", "sha512"})
	assertMatrixDimensions(t, identifiers, []string{"direct", "issuer-serial", "x509keyidentifier", "ski", "ThumbprintSHA1"})
	profiles := map[string]bool{}
	for _, p := range matrix.Profiles {
		if profiles[p.ID] || len(p.Coverage) == 0 {
			t.Errorf("invalid named profile: %+v", p)
		}
		profiles[p.ID] = true
	}
	assertMatrixDimensions(t, profiles, []string{"username-token", "signed-token", "signed-replies", "signed-headers-addressing", "timestamp-freshness", "mixed-orders"})
	if len(matrix.Unsupported) == 0 || len(matrix.UnclaimedCrossProducts) == 0 {
		t.Error("missing unsupported configurations or evidence exclusions")
	}
}

func matrixKey(version, order string, bits int, target string) string {
	return fmt.Sprintf("%s/%s/%d/%s", version, order, bits, target)
}

func assertMatrixDimensions(t *testing.T, actual map[string]bool, expected []string) {
	t.Helper()
	if len(actual) != len(expected) {
		t.Errorf("dimension size %d, want %d", len(actual), len(expected))
	}
	for _, item := range expected {
		if !actual[item] {
			t.Errorf("missing matrix dimension %q", item)
		}
	}
}

func matrixTestNames(t *testing.T) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), entry.Name(), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && strings.HasPrefix(fn.Name.Name, "Test") {
				names[fn.Name.Name] = true
			}
		}
	}
	return names
}
