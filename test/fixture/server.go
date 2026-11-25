// Package fixture supplies synthetic, local-only HTTP responses for SOAP tests.
package fixture

import (
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

const MaxBodyBytes = 64 << 10
const maxCaptures = 128

// Capture is an in-memory synthetic request, never written to production logs.
type Capture struct {
	Path   string
	Body   string
	Header http.Header
}

type Server struct {
	*httptest.Server
	mu       sync.Mutex
	captures []Capture
}

// Start binds a loopback ephemeral port before returning, so readiness needs no
// polling or sleep. The test owns all server connections through Cleanup.
func Start(t testing.TB) *Server {
	t.Helper()
	s := &Server{}
	s.Server = httptest.NewUnstartedServer(http.HandlerFunc(s.serveHTTP))
	s.Config.ReadTimeout = 2 * time.Second
	s.Config.WriteTimeout = 2 * time.Second
	s.Config.IdleTimeout = 2 * time.Second
	s.Start()
	t.Cleanup(func() { s.CloseClientConnections(); s.Close() })
	return s
}

func (s *Server) Captures() []Capture {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]Capture, len(s.captures))
	for i, c := range s.captures {
		result[i] = c
		result[i].Header = c.Header.Clone()
	}
	return result
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	if err != nil {
		http.Error(w, "fixture request too large", http.StatusRequestEntityTooLarge)
		return
	}
	s.mu.Lock()
	if len(s.captures) >= maxCaptures {
		s.mu.Unlock()
		http.Error(w, "fixture capture capacity exceeded", http.StatusServiceUnavailable)
		return
	}
	s.captures = append(s.captures, Capture{Path: r.URL.Path, Body: string(body), Header: r.Header.Clone()})
	s.mu.Unlock()
	switch r.URL.Path {
	case "/echo":
		var root struct{ XMLName xml.Name }
		mediaType := "text/xml"
		if xml.Unmarshal(body, &root) == nil && root.XMLName == (xml.Name{Space: "http://www.w3.org/2003/05/soap-envelope", Local: "Envelope"}) {
			mediaType = "application/soap+xml"
		}
		w.Header().Set("Content-Type", mediaType+"; charset=utf-8")
		_, _ = w.Write(body)
	case "/fault11":
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		w.WriteHeader(500)
		_, _ = io.WriteString(w, `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault><faultcode>s:Server</faultcode><faultstring>Synthetic fault</faultstring><detail><fixture/></detail></s:Fault></s:Body></s:Envelope>`)
	case "/fault12":
		w.Header().Set("Content-Type", "application/soap+xml; charset=utf-8")
		w.WriteHeader(500)
		_, _ = io.WriteString(w, `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><s:Fault><s:Code><s:Value>s:Receiver</s:Value></s:Code><s:Reason><s:Text xml:lang="en">Synthetic fault</s:Text></s:Reason><s:Detail><fixture/></s:Detail></s:Fault></s:Body></s:Envelope>`)
	case "/w3c-t12", "/w3c-t15":
		// https://www.w3.org/TR/soap12-testcollection/#T12 and #T15
		// Adapt the two roles to synthetic client-side replies. Both carry the
		// same Body so the parser can show whether the role permits access to it.
		role := "urn:fixture:other-role"
		if r.URL.Path == "/w3c-t12" {
			role = "http://www.w3.org/2003/05/soap-envelope/role/ultimateReceiver"
		}
		w.Header().Set("Content-Type", "application/soap+xml; charset=utf-8")
		_, _ = io.WriteString(w, `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header><m:Unknown xmlns:m="urn:fixture" s:mustUnderstand="1" s:role="`+role+`"/></s:Header><s:Body><m:Echo xmlns:m="urn:fixture">w3c-role-marker</m:Echo></s:Body></s:Envelope>`)
	case "/empty":
		w.WriteHeader(http.StatusNoContent)
	case "/binary":
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte{0, 128, 255})
	case "/delay":
		timer := time.NewTimer(250 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-r.Context().Done():
			return
		case <-timer.C:
		}
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		_, _ = w.Write(body)
	case "/disconnect":
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close()
		}
	default:
		http.NotFound(w, r)
	}
}
