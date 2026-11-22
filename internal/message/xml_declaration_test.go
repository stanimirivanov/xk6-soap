package message

import "testing"

const xmlDeclaration = `<?xml version="1.0"?>`

func TestResponseXMLDeclaration(t *testing.T) {
	const wire = `<s:Envelope xmlns:s="` + SOAP11 + `"><s:Body><Echo>café</Echo></s:Body></s:Envelope>`
	control := Parse(200, wire, "1.1", Limits{})
	for _, tc := range []struct {
		name   string
		prefix string
	}{
		{"version only", xmlDeclaration},
		{"UTF-8", `<?xml version="1.0" encoding="UTF-8"?>`},
		{"quoting and whitespace", "<?xml\tversion = '1.0'\r\nencoding = 'utf-8' standalone = \"yes\" ?>\n"},
		{"standalone without encoding", `<?xml version='1.0' standalone='no'?>`},
		{"UTF-8 BOM", "\uFEFF" + xmlDeclaration},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parsed := Parse(200, tc.prefix+wire, "1.1", Limits{})
			if !parsed.OK || parsed.Body == nil || control.Body == nil || *parsed.Body != *control.Body {
				t.Fatalf("declaration changed the accepted response: %+v", parsed)
			}
		})
	}
	for _, tc := range []struct {
		name string
		wire string
	}{
		{"no version", `<?xml encoding="UTF-8"?>` + wire},
		{"unsupported version", `<?xml version="1.1"?>` + wire},
		{"unsupported encoding", `<?xml version="1.0" encoding="UTF-16"?>` + wire},
		{"invalid UTF-8 bytes", xmlDeclaration + wire + "\xff"},
		{"mismatched quotes", `<?xml version="1.0'?>` + wire},
		{"extra field", `<?xml version="1.0" extra="no"?>` + wire},
		{"invalid standalone", `<?xml version="1.0" standalone="true"?>` + wire},
		{"field order", `<?xml version="1.0" standalone="no" encoding="UTF-8"?>` + wire},
		{"duplicate field", `<?xml version="1.0" version="1.0"?>` + wire},
		{"duplicate declaration", xmlDeclaration + xmlDeclaration + wire},
		{"leading whitespace", " " + xmlDeclaration + wire},
		{"leading comment", "<!-- leading -->" + xmlDeclaration + wire},
		{"trailing declaration", wire + xmlDeclaration},
		{"processing instruction", xmlDeclaration + `<?local instruction?>` + wire},
		{"DTD", xmlDeclaration + `<!DOCTYPE s:Envelope>` + wire},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parsed := Parse(500, tc.wire, "1.1", Limits{})
			if parsed.Error == nil || parsed.Error.Code != "XML_INVALID" || parsed.OK || parsed.Body != nil || parsed.Fault != nil {
				t.Fatalf("unexpected result for invalid response: %+v", parsed)
			}
		})
	}
}

func TestResponseXMLDeclarationCountsTowardLimits(t *testing.T) {
	const envelope = `<s:Envelope xmlns:s="` + SOAP11 + `"><s:Body/></s:Envelope>`
	const wire = "\uFEFF" + xmlDeclaration + envelope
	for _, limits := range []Limits{{Bytes: len(wire) - 1}, {Nodes: 4}, {Nodes: 1}} {
		p := Parse(200, wire, "1.1", limits)
		if p.Error == nil || p.Error.Code != "LIMIT_EXCEEDED" || p.Body != nil {
			t.Fatalf("expected rejection at limits %+v: %+v", limits, p)
		}
	}
	p := Parse(200, wire, "1.1", Limits{Bytes: len(wire), Nodes: 5})
	if !p.OK {
		t.Fatalf("response at both limits was rejected: %v", p.Error)
	}
}

func TestXMLDeclarationRestrictedToInboundEnvelope(t *testing.T) {
	_, err := Build("Echo", xmlDeclaration+`<Echo/>`, Options{})
	code(t, err, "XML_INVALID")
	_, err = Build("Echo", `<Echo/>`, Options{Headers: []Header{{
		Name: "header",
		XML:  xmlDeclaration + `<m:Header xmlns:m="urn:test"/>`,
	}}})
	code(t, err, "XML_INVALID")

	const body = `<s:Body xmlns:s="` + SOAP11 + `"/>`
	p := ParseAcceptedBody(200, xmlDeclaration+body, "1.1", Limits{})
	if p.Error == nil || p.Error.Code != "XML_INVALID" || p.Body != nil {
		t.Fatalf("accepted a declaration on a Body projection: %+v", p)
	}
}
