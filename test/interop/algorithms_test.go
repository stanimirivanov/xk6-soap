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

func TestK6SignatureAlgorithms(t *testing.T) {
	base := os.Getenv("SOAP_INTEROP_URL")
	if base == "" {
		t.Fatal("use make interop")
	}
	waitApache(t, &http.Client{Timeout: 5 * time.Second}, base, []string{"/sigrsa38411", "/sigrsa51212", "/sigec25611", "/sigec38412", "/sigec52112", "/sigecwrongcurve11"})
	binary, err := filepath.Abs("../../bin/k6")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	output, err := e2e.Run(ctx, binary, []string{"run", "--quiet", "--no-usage-report", "algorithms.js"}, nil)
	if err != nil {
		t.Fatalf("k6-to-Apache exchanges: %v\n%s", err, output)
	}
	if strings.Contains(output, "ALGORITHM_PRIVATE_SENTINEL") || strings.Contains(output, "PRIVATE KEY") || strings.Contains(output, "fixture-password") {
		t.Fatal("signed debug logs exposed private input")
	}
}
