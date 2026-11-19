//go:build interop

package interop

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stanimirivanov/xk6-soap/test/e2e"
)

func TestK6UsernameTokenExchanges(t *testing.T) {
	base := os.Getenv("SOAP_INTEROP_URL")
	if base == "" {
		t.Fatal("use make interop")
	}
	waitApache(t, &http.Client{Timeout: 5 * time.Second}, base, []string{"/ut11", "/ut12", "/ts11", "/ts12"})
	binary, err := filepath.Abs("../../bin/k6")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	output, err := e2e.Run(ctx, binary, []string{"run", "--quiet", "--no-usage-report", "username.js"}, nil)
	if err != nil {
		t.Fatalf("k6-to-Apache exchanges: %v\n%s", err, output)
	}
}
