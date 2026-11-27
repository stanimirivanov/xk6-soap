//go:build e2e

package e2e

import (
	"context"
	"encoding/xml"
	"errors"
	"mime"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stanimirivanov/xk6-soap/test/fixture"
)

const soap11Envelope = "http://schemas.xmlsoap.org/soap/envelope/"
const soap12Envelope = "http://www.w3.org/2003/05/soap-envelope"

type echoEnvelope struct {
	XMLName xml.Name
	Body    struct {
		XMLName  xml.Name `xml:"Body"`
		InnerXML string   `xml:",innerxml"`
		Markers  []string `xml:"urn:fixture Echo"`
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
			assertSOAP11DeclarationCapture(t, captures)
			assertSOAP12DeclarationCaptures(t, captures)
			assertFixedSOAPRequestCaptures(t, captures)
			if len(captures) != 58 {
				t.Fatalf("expected 58 HTTP requests, got %d\n%s", len(captures), output)
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
			t.Fatal("invalid wire Envelope")
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
				t.Error("unexpected wire Echo marker")
			}
			continue
		}
		seen[marker]++
		wantOperation := readSOAPFixture(t, "th1-"+marker+"-operation.xml")
		if envelope.Body.InnerXML != wantOperation {
			t.Errorf("%s: operation bytes differ (got %d bytes, want %d)", marker, len(envelope.Body.InnerXML), len(wantOperation))
		}
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

func assertFixedSOAPRequestCaptures(t *testing.T, captures []fixture.Capture) {
	t.Helper()
	wantFaultRequest := readSOAPFixture(t, "fault-request.xml")
	wantMalformedFault := readSOAPFixture(t, "soap12-duplicate-fault-code-value-envelope.xml")
	malformedFaultCount := 0
	faultRequests := map[string]int{"/fault11": 0, "/fault12": 0}
	for _, capture := range captures {
		path := capture.Path
		if path == "/echo" && capture.Header.Get("X-Synthetic") == "malformed-fault" {
			malformedFaultCount++
			if capture.Body != wantMalformedFault {
				t.Errorf("malformed SOAP 1.2 Fault request bytes differ (got %d bytes, want %d)", len(capture.Body), len(wantMalformedFault))
			}
			continue
		}
		if _, fault := faultRequests[path]; fault {
			faultRequests[path]++
			if capture.Body != wantFaultRequest {
				t.Errorf("%s request body bytes differ (got %d bytes, want %d)", path, len(capture.Body), len(wantFaultRequest))
			}
			continue
		}
		if strings.HasPrefix(path, "/w3c-") || strings.HasPrefix(path, "/soap12-") || path == "/empty" || path == "/binary" {
			if len(capture.Body) != 0 {
				t.Errorf("%s request body has %d bytes, want 0", path, len(capture.Body))
			}
		}
	}
	if malformedFaultCount != 1 {
		t.Errorf("malformed SOAP 1.2 Fault request count = %d, want 1", malformedFaultCount)
	}
	for path, count := range faultRequests {
		if count != 1 {
			t.Errorf("%s request count = %d, want 1", path, count)
		}
	}
}

func assertSOAP11DeclarationCapture(t *testing.T, captures []fixture.Capture) {
	t.Helper()
	wantOperation := readSOAPFixture(t, "soap11-declaration-echo-operation.xml")
	const declaration = `<?xml version="1.0" encoding="UTF-8"?>` + "\n"
	count := 0
	for _, capture := range captures {
		if capture.Path != "/echo" {
			continue
		}
		var envelope echoEnvelope
		if xml.Unmarshal([]byte(capture.Body), &envelope) != nil || len(envelope.Body.Markers) != 1 || envelope.Body.Markers[0] != "soap11-declared" {
			continue
		}
		count++
		if !strings.HasPrefix(capture.Body, declaration) {
			t.Error("SOAP 1.1 declaration Echo request lacks the expected UTF-8 declaration")
		}
		if envelope.XMLName != (xml.Name{Space: soap11Envelope, Local: "Envelope"}) || envelope.Body.XMLName.Space != soap11Envelope {
			t.Error("SOAP 1.1 declaration Echo request has the wrong SOAP namespace")
		}
		if envelope.Body.InnerXML != wantOperation {
			t.Errorf("SOAP 1.1 declaration Echo operation bytes differ (got %d bytes, want %d)", len(envelope.Body.InnerXML), len(wantOperation))
		}
	}
	if count != 1 {
		t.Errorf("SOAP 1.1 declaration Echo request count = %d, want 1", count)
	}
}

func assertSOAP12DeclarationCaptures(t *testing.T, captures []fixture.Capture) {
	t.Helper()
	undeclared := readSOAPFixture(t, "t66-undeclared-envelope.xml")
	declared := readSOAPFixture(t, "t66-declared-envelope.xml")
	const declaration = `<?xml version="1.0" encoding="UTF-8"?>` + "\n"
	if declaration+undeclared != declared {
		t.Fatal("T66 fixtures must differ only by the UTF-8 declaration line")
	}
	for variant, want := range map[string]string{"t66-undeclared": undeclared, "t66-declared": declared} {
		count := 0
		for _, capture := range captures {
			if capture.Path != "/echo" || capture.Header.Get("X-Synthetic") != variant {
				continue
			}
			count++
			if capture.Body != want {
				t.Errorf("%s request body bytes differ (got %d bytes, want %d)", variant, len(capture.Body), len(want))
			}
		}
		if count != 1 {
			t.Errorf("%s echo request count = %d, want 1", variant, count)
		}
	}
}

func readSOAPFixture(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("../fixture/testdata/soap12", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
