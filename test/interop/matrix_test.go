//go:build interop

package interop

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stanimirivanov/xk6-soap/test/e2e"
)

func TestK6InteropMatrix(t *testing.T) {
	base := os.Getenv("SOAP_INTEROP_URL")
	if base == "" {
		t.Fatal("use make interop")
	}
	var paths []string
	for _, row := range loadMatrix(t).Core {
		paths = append(paths, "/"+row.Endpoint)
	}
	waitApache(t, &http.Client{Timeout: 5 * time.Second}, base, paths)
	binary, err := filepath.Abs("../../bin/k6")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	output, err := e2e.Run(ctx, binary, []string{"run", "--quiet", "--no-usage-report", "matrix.js"}, nil)
	if err != nil {
		t.Fatalf("k6-to-Apache exchanges: %v\n%s", err, output)
	}
	if strings.Contains(output, "MATRIX_PRIVATE_HEADER") || strings.Contains(output, "MATRIX_PRIVATE_SENTINEL") || strings.Contains(output, "PRIVATE KEY") || strings.Contains(output, "fixture-password") {
		t.Fatal("encryption debug logs exposed private input")
	}
}
