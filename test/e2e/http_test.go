//go:build e2e

package e2e

import (
	"context"
	"encoding/xml"
	"errors"
	"mime"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stanimirivanov/xk6-soap/test/fixture"
)

const soap11Envelope = "http://schemas.xmlsoap.org/soap/envelope/"
const soap12Envelope = "http://www.w3.org/2003/05/soap-envelope"

type echoEnvelope struct {
	XMLName xml.Name
	Body    struct {
		XMLName xml.Name `xml:"Body"`
		Markers []string `xml:"urn:fixture Echo"`
	} `xml:"Body"`
}

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
			output, err := Run(ctx, binary, []string{"run", "--quiet", "--no-usage-report", "--http-debug=", "--http-debug-redact=false", "--no-thresholds=false", "http.js"}, env)
			if negative {
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 99 {
					t.Fatalf("expected threshold exit 99: %v\n%s", err, output)
				}
			} else if err != nil {
				t.Fatalf("k6 failed: %v\n%s", err, output)
			}
			captures := server.Captures()
			assertSOAPActionCaptures(t, captures)
			if len(captures) != 50 {
				t.Fatalf("expected 50 HTTP requests, got %d\n%s", len(captures), output)
			}
		})
	}
}

func assertSOAPActionCaptures(t *testing.T, captures []fixture.Capture) {
	t.Helper()
	want := map[string]struct {
		namespace  string
		mediaType  string
		soapAction string
		action     string
	}{
		"soap11-explicit": {soap11Envelope, "text/xml", `"urn:echo"`, ""},
		"soap11-omitted":  {soap11Envelope, "text/xml", `""`, ""},
		"soap12-explicit": {soap12Envelope, "application/soap+xml", "", "urn:echo"},
		"soap12-omitted":  {soap12Envelope, "application/soap+xml", "", ""},
	}
	seen := make(map[string]int, len(want))
	for _, capture := range captures {
		if capture.Path != "/echo" {
			continue
		}
		var envelope echoEnvelope
		if err := xml.Unmarshal([]byte(capture.Body), &envelope); err != nil {
			t.Fatalf("invalid wire Envelope: %v", err)
		}
		marked := capture.Header.Get("X-Synthetic") == "soap-e2e"
		if len(envelope.Body.Markers) != 1 {
			if marked || len(envelope.Body.Markers) > 1 {
				t.Errorf("expected one Echo marker in Body, got %d", len(envelope.Body.Markers))
			}
			continue
		}
		marker := envelope.Body.Markers[0]
		expected, ok := want[marker]
		if !ok {
			if marked {
				t.Errorf("unexpected wire marker %q", marker)
			}
			continue
		}
		seen[marker]++
		if !marked || envelope.XMLName != (xml.Name{Space: expected.namespace, Local: "Envelope"}) || envelope.Body.XMLName.Space != expected.namespace {
			t.Errorf("%s: wrong synthetic header or SOAP namespace", marker)
		}
		contentType := capture.Header.Get("Content-Type")
		mediaType, params, err := mime.ParseMediaType(contentType)
		action, hasAction := params["action"]
		if err != nil || len(capture.Header.Values("Content-Type")) != 1 || mediaType != expected.mediaType ||
			params["charset"] != "utf-8" || action != expected.action || hasAction != (expected.action != "") {
			t.Errorf("%s: wrong Content-Type %q", marker, contentType)
		}
		values := capture.Header.Values("SOAPAction")
		if expected.soapAction == "" && len(values) != 0 || expected.soapAction != "" && (len(values) != 1 || values[0] != expected.soapAction) {
			t.Errorf("%s: wrong SOAPAction %q", marker, values)
		}
	}
	for marker := range want {
		if seen[marker] != 1 {
			t.Errorf("expected wire marker %q once, saw it %d times", marker, seen[marker])
		}
	}
}
