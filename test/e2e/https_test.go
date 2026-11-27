//go:build e2e

package e2e

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stanimirivanov/xk6-soap/test/fixture"
)

func TestK6SOAPHTTPSWithBasicAuth(t *testing.T) {
	const user = "fixture-user"
	const password = "fixture-only"
	wantOperation := readSOAPFixture(t, "https-echo-operation.xml")
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		username, secret, ok := r.BasicAuth()
		if !ok || username != user || secret != password {
			w.Header().Set("WWW-Authenticate", `Basic realm="soap-fixture"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, fixture.MaxBodyBytes))
		var envelope echoEnvelope
		if err != nil || xml.Unmarshal(body, &envelope) != nil || envelope.XMLName != (xml.Name{Space: soap12Envelope, Local: "Envelope"}) ||
			envelope.Body.XMLName.Space != soap12Envelope || len(envelope.Body.Markers) != 1 || envelope.Body.Markers[0] != "tls-auth-echo" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if envelope.Body.InnerXML != wantOperation {
			t.Errorf("HTTPS Echo operation bytes differ (got %d bytes, want %d)", len(envelope.Body.InnerXML), len(wantOperation))
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/soap+xml; charset=utf-8")
		_, _ = w.Write(body)
	}))
	server.Config.ReadTimeout = 2 * time.Second
	server.Config.WriteTimeout = 2 * time.Second
	server.Config.IdleTimeout = 2 * time.Second
	server.StartTLS()
	t.Cleanup(server.Close)

	// Go on Linux uses these overrides to load only the loopback fixture's trust.
	trustDir := t.TempDir()
	certPath := filepath.Join(trustDir, "loopback.pem")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(certPath, certificate, 0600); err != nil {
		t.Fatal(err)
	}
	binary, err := filepath.Abs("../../bin/k6")
	if err != nil {
		t.Fatal(err)
	}
	env := []string{
		"SOAP_TLS_URL=" + server.URL,
		"SOAP_BASIC_AUTH=" + base64.StdEncoding.EncodeToString([]byte(user+":"+password)),
		"SSL_CERT_FILE=" + certPath,
		"SSL_CERT_DIR=" + trustDir,
	}
	args := []string{"run", "--quiet", "--no-usage-report", "--insecure-skip-tls-verify=false", "--http-debug=", "--http-debug-redact=false", "--no-thresholds=false", "https.js"}
	for _, scenario := range []struct {
		name      string
		interrupt string
	}{
		{name: "complete"},
		{name: "interrupted-before-checks", interrupt: "before-checks"},
		{name: "interrupted-after-authenticated", interrupt: "after-authenticated"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			output, err := Run(ctx, binary, args, append(env, "SOAP_HTTPS_INTERRUPT="+scenario.interrupt))
			if scenario.interrupt == "" {
				if err != nil {
					t.Fatalf("HTTPS SOAP exchange: %v\n%s", err, output)
				}
				return
			}
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 99 ||
				!strings.Contains(output, "HTTPS control: "+scenario.interrupt) ||
				!strings.Contains(output, "thresholds on metrics 'https_scenarios_completed' have been crossed") {
				t.Fatalf("expected HTTPS interruption %s to fail only the completion threshold: %v\n%s", scenario.interrupt, err, output)
			}
		})
	}
}
