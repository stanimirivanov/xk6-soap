// Package fixture supplies synthetic, local-only HTTP responses for SOAP tests.
package fixture

import (
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const MaxBodyBytes = 64 << 10
const maxCaptures = 128
const soap12EncodingNone = "http://www.w3.org/2003/05/soap-envelope/encoding/none"
const soap12EnvelopeFixtureBody = `<s:Body><m:Echo>soap12-envelope-marker</m:Echo></s:Body>`
const legacySOAPNamespace = ` xmlns:legacy="http://schemas.xmlsoap.org/soap/envelope/"`

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
		writeSOAP12FaultReply(w, http.StatusInternalServerError, "Receiver", "Synthetic fault", `<s:Detail><fixture/></s:Detail>`)
	case "/soap12-sender-fault":
		writeSOAP12FaultReply(w, http.StatusBadRequest, "Sender", "Synthetic Sender reason", "")
	case "/soap12-must-understand-fault":
		writeSOAP12FaultReply(w, http.StatusInternalServerError, "MustUnderstand", "Synthetic MustUnderstand reason", "")
	case "/w3c-t28":
		writeWrapperAttributeReply(w, "", ` s:encodingStyle="`+soap12EncodingNone+`"`, "")
	case "/soap12-valid-envelope":
		writeEnvelopeStructureReply(w, soap12EnvelopeFixtureBody)
	case "/w3c-t69":
		writeEnvelopeStructureReply(w, "")
	case "/w3c-t70":
		writeEnvelopeStructureReply(w, soap12EnvelopeFixtureBody+`<Trailer/>`)
	case "/w3c-t71":
		writeWrapperAttributeReply(w, ` xmlns="http://www.w3.org/2003/05/soap-envelope" ordinary="fixture"`, "", "")
	case "/w3c-t72":
		writeWrapperAttributeReply(w, ` xmlns:env="http://www.w3.org/2003/05/soap-envelope" env:encodingStyle="`+soap12EncodingNone+`"`, "", "")
	case "/soap12-qualified-wrapper-attributes":
		writeWrapperAttributeReply(w, ` m:encodingStyle="fixture"`, ` m:metadata="fixture"`, ` s:encodingStyle="`+soap12EncodingNone+`"`)
	case "/w3c-t30":
		// Adapt W3C T30 to projection of a supplied Fault reply.
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Header><s:Upgrade><s:SupportedEnvelope xmlns:n="http://www.w3.org/2003/05/soap-envelope" qname="n:Envelope"/></s:Upgrade></s:Header><s:Body><s:Fault><faultcode>s:VersionMismatch</faultcode><faultstring>Synthetic version mismatch</faultstring></s:Fault></s:Body></s:Envelope>`)
	case "/w3c-t12":
		writeHeaderRoleReply(w, "http://www.w3.org/2003/05/soap-envelope/role/ultimateReceiver", "1")
	case "/w3c-t15":
		writeHeaderRoleReply(w, "urn:fixture:other-role", "1")
	case "/w3c-standard-role/next", "/w3c-standard-role/none":
		writeHeaderRoleReply(w, "http://www.w3.org/2003/05/soap-envelope/role/"+strings.TrimPrefix(r.URL.Path, "/w3c-standard-role/"), "1")
	case "/w3c-default-role/0", "/w3c-default-role/1", "/w3c-default-role/true", "/w3c-default-role/false":
		writeHeaderRoleReply(w, "", strings.TrimPrefix(r.URL.Path, "/w3c-default-role/"))
	case "/w3c-t34/foreign-only":
		writeHeaderReply(w, legacySOAPNamespace+` legacy:mustUnderstand="1"`)
	case "/w3c-t34/mandatory-native-first":
		writeHeaderReply(w, legacySOAPNamespace+` s:mustUnderstand="1" legacy:mustUnderstand="0"`)
	case "/w3c-t34/mandatory-foreign-first":
		writeHeaderReply(w, legacySOAPNamespace+` legacy:mustUnderstand="0" s:mustUnderstand="1"`)
	case "/w3c-t34/optional-native-first":
		writeHeaderReply(w, legacySOAPNamespace+` s:mustUnderstand="0" legacy:mustUnderstand="1"`)
	case "/w3c-t34/optional-foreign-first":
		writeHeaderReply(w, legacySOAPNamespace+` legacy:mustUnderstand="1" s:mustUnderstand="0"`)
	case "/w3c-t34/foreign-actor":
		writeHeaderReply(w, legacySOAPNamespace+` legacy:actor="urn:fixture:actor"`)
	case "/w3c-t37":
		writeHeaderReply(w, ` s:role="http://www.w3.org/2003/05/soap-envelope/role/ultimateReceiver"`)
	case "/w3c-t39":
		writeHeaderRoleReply(w, "", "invalid")
	case "/w3c-t74":
		writeHeaderBlockReply(w, `<m:Unknown xmlns:m="urn:fixture"><m:Nested s:role="http://www.w3.org/2003/05/soap-envelope/role/next" s:mustUnderstand="1"/></m:Unknown>`)
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

func writeSOAP12FaultReply(w http.ResponseWriter, status int, code, reason, detail string) {
	w.Header().Set("Content-Type", "application/soap+xml; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><s:Fault>`+
		`<s:Code><s:Value>s:`+code+`</s:Value></s:Code><s:Reason><s:Text xml:lang="en">`+reason+
		`</s:Text></s:Reason>`+detail+`</s:Fault></s:Body></s:Envelope>`)
}

// Adapt W3C T11, T12, T13, T15, T17, T19, T35 and T38 to client reply acceptance.
// Keep the Body marker fixed while varying only the role or mustUnderstand.
func writeHeaderRoleReply(w http.ResponseWriter, role, mustUnderstand string) {
	roleAttribute := ""
	if role != "" {
		roleAttribute = ` s:role="` + role + `"`
	}
	writeHeaderReply(w, ` s:mustUnderstand="`+mustUnderstand+`"`+roleAttribute)
}

// All attributes come from the synthetic cases above.
func writeHeaderReply(w http.ResponseWriter, attributes string) {
	writeHeaderBlockReply(w, `<m:Unknown xmlns:m="urn:fixture"`+attributes+`/>`)
}

// Keep the Body marker fixed across SOAP 1.2 Header cases.
func writeHeaderBlockReply(w http.ResponseWriter, block string) {
	w.Header().Set("Content-Type", "application/soap+xml; charset=utf-8")
	_, _ = io.WriteString(w, `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header>`+block+`</s:Header><s:Body><m:Echo xmlns:m="urn:fixture">w3c-role-marker</m:Echo></s:Body></s:Envelope>`)
}

// Adapt W3C T28, T71 and T72 to client reply acceptance.
func writeWrapperAttributeReply(w http.ResponseWriter, envelope, body, child string) {
	w.Header().Set("Content-Type", "application/soap+xml; charset=utf-8")
	_, _ = io.WriteString(w, `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:m="urn:fixture"`+envelope+
		`><s:Body`+body+`><m:Echo`+child+`>soap12-wrapper-marker</m:Echo></s:Body></s:Envelope>`)
}

// Adapt W3C T69 and T70 to client reply acceptance with the same optional Header.
func writeEnvelopeStructureReply(w http.ResponseWriter, afterHeader string) {
	w.Header().Set("Content-Type", "application/soap+xml; charset=utf-8")
	_, _ = io.WriteString(w, `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:m="urn:fixture">`+
		`<s:Header><m:Optional/></s:Header>`+afterHeader+`</s:Envelope>`)
}
