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
	for name, want := range fixtures {
		t.Run(name, func(t *testing.T) {
			got, err := os.ReadFile(filepath.Join("testdata", "matrix", name))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != want {
				t.Errorf("operation bytes differ (got %d bytes, want %d)", len(got), len(want))
			}
		})
	}
}
