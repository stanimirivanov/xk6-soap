package interop

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInteropMatrixEchoFixtures(t *testing.T) {
	// These literals record the former inline matrix.js inputs.
	fixtures := map[string]string{
		"echo-success.xml": `<m:echo xmlns:m="urn:xk6-soap:fixture"><value>MATRIX_PRIVATE_SENTINEL</value></m:echo>`,
		"echo-fault.xml":   `<m:echo xmlns:m="urn:xk6-soap:fixture"><value>fault</value></m:echo>`,
	}
	checkMatrixFixtureBytes(t, fixtures)
}

func TestInteropMatrixHeaderFixtures(t *testing.T) {
	// These literals record the former inline matrix.js inputs.
	fixtures := map[string]string{
		"header-trace.xml": `<h:Trace xmlns:h="urn:trace">MATRIX_PRIVATE_HEADER</h:Trace>`,
		"header-other.xml": `<h:Other xmlns:h="urn:trace">clear-header</h:Other>`,
	}
	checkMatrixFixtureBytes(t, fixtures)
}

func checkMatrixFixtureBytes(t *testing.T, fixtures map[string]string) {
	t.Helper()
	for name, want := range fixtures {
		t.Run(name, func(t *testing.T) {
			got, err := os.ReadFile(filepath.Join("testdata", "matrix", name))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != want {
				t.Errorf("fixture bytes differ (got %d bytes, want %d)", len(got), len(want))
			}
		})
	}
}
