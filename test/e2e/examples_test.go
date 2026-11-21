//go:build e2e

package e2e

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stanimirivanov/xk6-soap/test/fixture"
)

func TestDocumentedSOAPExamples(t *testing.T) {
	binary, err := filepath.Abs("../../bin/k6")
	if err != nil {
		t.Fatal(err)
	}
	echo := fixture.Start(t)
	fault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/soap+xml")
		_, _ = w.Write([]byte(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><s:Fault><s:Code><s:Value>s:Receiver</s:Value></s:Code><s:Reason><s:Text xml:lang="en">Synthetic fault</s:Text></s:Reason></s:Fault></s:Body></s:Envelope>`))
	}))
	t.Cleanup(fault.Close)
	for _, example := range []string{"plain", "object"} {
		t.Run(example, func(t *testing.T) {
			path := "../../examples/" + example + ".js"
			args := []string{"run", "--quiet", "--no-usage-report", path}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if output, err := Run(ctx, binary, args, []string{"SOAP_URL=" + echo.URL + "/echo"}); err != nil {
				t.Fatalf("example failed: %v\n%s", err, output)
			}
			output, err := Run(ctx, binary, args, []string{"SOAP_URL=" + fault.URL})
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 99 || !strings.Contains(output, "soap_req_failed") {
				t.Fatalf("HTTP 200 SOAP Fault must fail the SOAP threshold: %v\n%s", err, output)
			}
		})
	}
	if captures := echo.Captures(); len(captures) != 2 {
		t.Fatalf("expected both examples to send requests, got %d", len(captures))
	}
}
