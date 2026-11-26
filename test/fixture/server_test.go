package fixture

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type failingResponseWriter struct {
	http.ResponseWriter
}

func (*failingResponseWriter) Write([]byte) (int, error) {
	return 0, errors.New("synthetic-write-error-secret")
}

func TestSOAP12ReplyWriteFailureDiagnostics(t *testing.T) {
	for _, path := range []string{"/w3c-t68/compact", "/fault12"} {
		t.Run(path, func(t *testing.T) {
			var diagnostics bytes.Buffer
			server := &Server{Server: &httptest.Server{
				Config: &http.Server{ErrorLog: log.New(&diagnostics, "", 0)},
			}}
			request := httptest.NewRequest(http.MethodPost, path+"?token=synthetic-query-secret", strings.NewReader("<request>synthetic-request-secret</request>"))
			request.SetBasicAuth("fixture-user", "synthetic-password")
			writer := &failingResponseWriter{ResponseWriter: httptest.NewRecorder()}

			server.serveHTTP(writer, request)

			want := "SOAP 1.2 fixture " + path + ": response write failed\n"
			if got := diagnostics.String(); got != want {
				t.Fatalf("diagnostic = %q, want %q", got, want)
			}
		})
	}
}

func TestResponses(t *testing.T) {
	server := Start(t)
	for _, tc := range []struct {
		path        string
		status      int
		contentType string
		body        string
	}{
		{"/echo", 200, "text/xml; charset=utf-8", "<request/>"},
		{"/fault11", 500, "text/xml; charset=utf-8", ""},
		{"/fault12", 500, "application/soap+xml; charset=utf-8", ""},
		{"/empty", 204, "", ""},
		{"/binary", 200, "application/octet-stream", string([]byte{0, 128, 255})},
	} {
		t.Run(tc.path, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, server.URL+tc.path, strings.NewReader("<request/>"))
			req.Header.Set("X-Synthetic", "fixture")
			res, err := server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			body, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatal(err)
			}
			if res.StatusCode != tc.status || res.Header.Get("Content-Type") != tc.contentType {
				t.Fatalf("response: %d %v", res.StatusCode, res.Header)
			}
			if strings.HasPrefix(tc.path, "/fault") {
				var envelope struct {
					XMLName xml.Name
					Body    struct {
						Fault struct {
							XMLName  xml.Name
							Code     string `xml:"faultcode"`
							Reason   string `xml:"faultstring"`
							Code12   string `xml:"Code>Value"`
							Reason12 string `xml:"Reason>Text"`
						}
					}
				}
				if err := xml.Unmarshal(body, &envelope); err != nil {
					t.Fatal(err)
				}
				ns := "http://schemas.xmlsoap.org/soap/envelope/"
				if tc.path == "/fault12" {
					ns = "http://www.w3.org/2003/05/soap-envelope"
				}
				if envelope.XMLName.Space != ns || envelope.Body.Fault.XMLName.Local != "Fault" {
					t.Fatalf("fault: %s", body)
				}
				if tc.path == "/fault11" && (envelope.Body.Fault.Code != "s:Server" || envelope.Body.Fault.Reason != "Synthetic fault") {
					t.Fatalf("1.1 fault: %s", body)
				}
				if tc.path == "/fault12" && (envelope.Body.Fault.Code12 != "s:Receiver" || envelope.Body.Fault.Reason12 != "Synthetic fault") {
					t.Fatalf("1.2 fault: %s", body)
				}
			} else if string(body) != tc.body {
				t.Fatalf("body: %q", body)
			}
		})
	}
	captures := server.Captures()
	if len(captures) != 5 || captures[0].Body != "<request/>" || captures[0].Header.Get("X-Synthetic") != "fixture" {
		t.Fatalf("capture: %+v", captures)
	}
	captures[0].Header.Set("X-Synthetic", "changed")
	if server.Captures()[0].Header.Get("X-Synthetic") != "fixture" {
		t.Fatal("capture headers alias storage")
	}
}

func TestDelayAndDisconnect(t *testing.T) {
	server := Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/delay", nil)
	if res, err := server.Client().Do(req); err == nil {
		res.Body.Close()
		t.Fatal("delay did not exceed deadline")
	}
	if res, err := server.Client().Post(server.URL+"/disconnect", "text/xml", nil); err == nil {
		res.Body.Close()
		t.Fatal("disconnect returned HTTP response")
	}
}

func TestCaptureLimit(t *testing.T) {
	server := Start(t)
	for range 2 {
		res, err := server.Client().Post(server.URL+"/echo", "text/xml", strings.NewReader(strings.Repeat("x", MaxBodyBytes+1)))
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("status %d", res.StatusCode)
		}
	}
	if len(server.Captures()) != 0 {
		t.Fatal("oversized request captured")
	}
}

func TestCaptureCapacity(t *testing.T) {
	server := Start(t)
	for i := 0; i <= maxCaptures; i++ {
		res, err := server.Client().Post(server.URL+"/empty", "text/xml", nil)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		want := http.StatusNoContent
		if i == maxCaptures {
			want = http.StatusServiceUnavailable
		}
		if res.StatusCode != want {
			t.Fatalf("request %d status %d", i, res.StatusCode)
		}
	}
	if len(server.Captures()) != maxCaptures {
		t.Fatal("capture storage exceeded capacity")
	}
}
