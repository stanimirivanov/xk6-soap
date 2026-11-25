package message

import (
	"errors"
	"strings"
	"testing"
)

func code(t *testing.T, err error, want string) {
	t.Helper()
	var failure *Error
	if !errors.As(err, &failure) || failure.Code != want {
		t.Fatalf("got %v, want %s", err, want)
	}
	if strings.Contains(err.Error(), "SECRET") {
		t.Fatal("error reflects input")
	}
}

func TestBuild(t *testing.T) {
	payload := `<m:Echo xmlns:m="urn:test" label="&amp;"><m:x><![CDATA[a<b]]></m:x></m:Echo>`
	for _, version := range []string{"", "1.1", "1.2"} {
		req, err := Build("Echo", payload, Options{Version: version, Action: "urn:test:Echo"})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(req.Body, payload) {
			t.Fatal("raw payload changed")
		}
		if err := ValidateEnvelope(req.Body, version, Limits{}); err != nil {
			t.Fatal(err)
		}
		if version == "1.2" {
			if req.Headers["SOAPAction"] != "" || req.Headers["Content-Type"] != `application/soap+xml; charset=utf-8; action="urn:test:Echo"` {
				t.Fatal(req.Headers)
			}
		} else if req.Headers["SOAPAction"] != `"urn:test:Echo"` || req.Headers["Content-Type"] != "text/xml; charset=utf-8" {
			t.Fatal(req.Headers)
		}
	}
	for _, version := range []string{"1.1", "1.2"} {
		req, err := Build("Echo", `<Echo/>`, Options{Version: version})
		if err != nil {
			t.Fatal(err)
		}
		if version == "1.1" && req.Headers["SOAPAction"] != `""` {
			t.Fatal(req.Headers)
		}
		if version == "1.2" && strings.Contains(req.Headers["Content-Type"], "action=") {
			t.Fatal(req.Headers)
		}
	}
}

func TestInvalidPayloads(t *testing.T) {
	for _, payload := range []string{
		``, `<Other/>`, `<Echo/><Echo/>`, `<Echo>`, `<p:Echo/>`, `<Echo p:x="1"/>`,
		`<Echo a="1" a="2"/>`, `<Echo xmlns:p="urn:a" xmlns:q="urn:a" p:x="1" q:x="2"/>`,
		`<Echo xmlns:p=""/>`, `<Echo xmlns:xml="urn:bad"/>`, `<Echo xmlns:xmlns="urn:bad"/>`,
		`<!DOCTYPE Echo [<!ENTITY x "SECRET">]><Echo>&x;</Echo>`, `<Echo>&unknown;</Echo>`,
		`<?xml version="1.0"?><Echo/>`, `<Echo><?pi SECRET?></Echo>`, `<Echo><x></Echo></x>`,
		`<Echo xmlns="http://schemas.xmlsoap.org/soap/envelope/"/>`,
		`<Echo><s:Body xmlns:s="http://www.w3.org/2003/05/soap-envelope"/></Echo>`,
		`<Echo xmlns:p="urn:a" xmlns:p="urn:b"/>`, `<Echo xmlns:p="http://www.w3.org/2000/xmlns/"/>`,
		`<Echo xmlns="http://www.w3.org/XML/1998/namespace"/>`, "<Echo>\xff</Echo>",
	} {
		t.Run(payload, func(t *testing.T) { _, err := Build("Echo", payload, Options{}); code(t, err, "XML_INVALID") })
	}
	for _, operation := range []string{"p:Echo", "1Echo", "Echo><SECRET", ""} {
		_, err := Build(operation, `<Echo/>`, Options{})
		code(t, err, "INVALID_ARGUMENT")
	}
	for _, action := range []string{"a\r\nSECRET", "a\"b", `a\b`, "a\x7fb"} {
		_, err := Build("Echo", `<Echo/>`, Options{Action: action})
		code(t, err, "INVALID_ARGUMENT")
	}
	_, err := Build("Echo", `<Echo/>`, Options{Version: "SECRET"})
	code(t, err, "INVALID_ARGUMENT")
}

func TestValidateRejectsUnknownMode(t *testing.T) {
	limits, err := (Limits{}).Normalized()
	if err != nil {
		t.Fatal(err)
	}
	document := `<s:Envelope xmlns:s="` + SOAP12 + `"/>`
	code(t, validate(document, limits, 0, "", SOAP12), "XML_INVALID")
}

func TestEnvelopeStructure(t *testing.T) {
	ns := ` xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"`
	for _, inside := range []string{`<s:Body/>`, `<s:Header/><s:Body/>`, `<s:Body><x xmlns="urn:test"/></s:Body>`} {
		if err := ValidateEnvelope("<s:Envelope"+ns+">"+inside+"</s:Envelope>", "1.1", Limits{}); err != nil {
			t.Fatal(err)
		}
	}
	for _, xml := range []string{
		`<Envelope><Body/></Envelope>`, `<s:Envelope` + ns + `/>`,
		`<s:Envelope` + ns + `><s:Body/><s:Body/></s:Envelope>`,
		`<s:Envelope` + ns + `><s:Body/><s:Header/></s:Envelope>`,
		`<s:Envelope` + ns + `><s:Header/><s:Header/><s:Body/></s:Envelope>`,
		`<s:Envelope` + ns + `><Body/></s:Envelope>`,
		`<s:Envelope` + ns + `>SECRET<s:Body/></s:Envelope>`,
		`<s:Envelope` + ns + `><s:Body/></s:Envelope><extra/>`,
		`<s:Envelope` + ns + `><x/><s:Body/></s:Envelope>`,
	} {
		code(t, ValidateEnvelope(xml, "1.1", Limits{}), "XML_INVALID")
	}
	code(t, ValidateEnvelope(`<s:Envelope`+ns+`><s:Body/></s:Envelope>`, "1.2", Limits{}), "XML_INVALID")
}

func TestLimits(t *testing.T) {
	for _, limits := range []Limits{{Bytes: 10}, {Depth: 2}, {Nodes: 2}, {Attributes: 1}} {
		_, err := Build("Echo", `<Echo a="1" b="2"><x/></Echo>`, Options{Limits: limits})
		code(t, err, "LIMIT_EXCEEDED")
	}
	for _, limits := range []Limits{{Bytes: -1}, {Depth: 65}, {Nodes: 50001}, {Attributes: 65}, {Bytes: 4<<20 + 1}} {
		_, err := Build("Echo", `<Echo/>`, Options{Limits: limits})
		code(t, err, "INVALID_ARGUMENT")
	}
	// Payload fits the byte limit, but its generated envelope does not.
	_, err := Build("Echo", `<Echo/>`, Options{Limits: Limits{Bytes: 20}})
	code(t, err, "LIMIT_EXCEEDED")
}

func FuzzValidateEnvelope(f *testing.F) {
	for _, seed := range []string{`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body/></s:Envelope>`, `<!DOCTYPE x><x/>`, `<x xmlns:p=""/>`, `<x><y></x>`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		_ = ValidateEnvelope(input, "1.1", Limits{Bytes: 4096, Depth: 16, Nodes: 128, Attributes: 16})
	})
}

func TestBoundaryRegressions(t *testing.T) {
	ns := ` xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"`
	code(t, ValidateEnvelope(`<s:Envelope`+ns+`><s:Body><s:Envelope/></s:Body></s:Envelope>`, "1.1", Limits{}), "XML_INVALID")
	_, err := Build("Echo", `<Echo/>`, Options{Action: string([]byte{255})})
	code(t, err, "INVALID_ARGUMENT")
	// The plain envelope has four element tokens and the operation has two.
	req, err := Build("Echo", `<Echo/>`, Options{Limits: Limits{Depth: 3, Nodes: 6}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = Build("Echo", `<Echo/>`, Options{Limits: Limits{Bytes: len(req.Body)}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = Build("Echo", `<Echo/>`, Options{Limits: Limits{Bytes: len(req.Body) - 1}})
	code(t, err, "LIMIT_EXCEEDED")
}

func FuzzBuild(f *testing.F) {
	for _, seed := range []string{`<Echo/>`, `<Echo xmlns="urn:test"/>`, `<p:Echo/>`, `<Echo a="&amp;"/>`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, payload string) {
		limits := Limits{Bytes: 4096, Depth: 16, Nodes: 128, Attributes: 16}
		req, err := Build("Echo", payload, Options{Limits: limits})
		if err == nil {
			if !strings.Contains(req.Body, payload) {
				t.Fatal("payload bytes changed")
			}
			if err := ValidateEnvelope(req.Body, "1.1", limits); err != nil {
				t.Fatalf("build emitted invalid envelope: %v", err)
			}
		}
	})
}
