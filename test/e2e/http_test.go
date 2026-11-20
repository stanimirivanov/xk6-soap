//go:build e2e

package e2e

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stanimirivanov/xk6-soap/test/fixture"
)

func TestK6SOAPFixture(t *testing.T) {
	binary, err := filepath.Abs("../../bin/k6")
	if err != nil {
		t.Fatal(err)
	}
	for _, negative := range []bool{false, true} {
		name := "pass"
		if negative {
			name = "failed-check"
		}
		t.Run(name, func(t *testing.T) {
			server := fixture.Start(t)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			env := []string{"SOAP_FIXTURE_URL=" + server.URL, "SOAP_E2E_FAIL=0"}
			if negative {
				env[1] = "SOAP_E2E_FAIL=1"
			}
			output, err := Run(ctx, binary, []string{"run", "--quiet", "--no-usage-report", "http.js"}, env)
			if negative {
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 99 {
					t.Fatalf("expected threshold exit 99: %v\n%s", err, output)
				}
			} else if err != nil {
				t.Fatalf("k6 failed: %v\n%s", err, output)
			}
			captures := server.Captures()
			if len(captures) != 9 {
				t.Fatalf("expected 9 HTTP requests, got %d\n%s", len(captures), output)
			}
			for i := range 2 {
				if captures[i].Path != "/echo" || captures[i].Header.Get("X-Synthetic") != "soap-e2e" {
					t.Fatalf("request %d: %+v", i, captures[i])
				}
			}
		})
	}
}
