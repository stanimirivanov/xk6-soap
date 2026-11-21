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

func TestDocumentedSignedExample(t *testing.T) {
	base := os.Getenv("SOAP_INTEROP_URL")
	if base == "" {
		t.Fatal("use make interop")
	}
	waitApache(t, &http.Client{Timeout: 5 * time.Second}, base, []string{"/sig12"})
	binary, err := filepath.Abs("../../bin/k6")
	if err != nil {
		t.Fatal(err)
	}
	fixtureKeys, err := filepath.Abs("../../internal/wssec/testdata")
	if err != nil {
		t.Fatal(err)
	}
	env := []string{
		"SOAP_URL=" + base + "/sig12",
		"SOAP_SIGN_CERT=" + filepath.Join(fixtureKeys, "signing-cert.pem"),
		"SOAP_SIGN_KEY=" + filepath.Join(fixtureKeys, "signing-key.pem"),
		"SOAP_TRUST_CERT=" + os.Getenv("SOAP_INTEROP_SIGNATURE_TRUST"),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	output, err := e2e.Run(ctx, binary, []string{"run", "--quiet", "--no-usage-report", "../../examples/signed.js"}, env)
	if err != nil {
		t.Fatalf("signed example failed: %v\n%s", err, output)
	}
}
