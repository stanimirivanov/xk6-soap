package message

import (
	"encoding/xml"
	"io"
	"strings"
	"unicode/utf8"
)

const xmlNS = "http://www.w3.org/XML/1998/namespace"
const xmlnsNS = "http://www.w3.org/2000/xmlns/"

type frame struct {
	raw xml.Name
	ns  map[string]string
}

// encoding/xml owns lexical decoding. RawToken retains prefixes so this layer
// can reject undeclared prefixes and duplicate expanded attributes explicitly;
// Decoder.Token otherwise tolerates unresolved prefixes. No external resolver is used.
func validate(input string, limits Limits, mode, operation, soapNS string) error {
	bad := func() error { return failure("XML_INVALID", "xml") }
	if len(input) > limits.Bytes {
		return failure("LIMIT_EXCEEDED", "xml")
	}
	if !utf8.ValidString(input) {
		return bad()
	}
	decoder := xml.NewDecoder(strings.NewReader(input))
	var stack []frame
	roots, nodes := 0, 0
	header, body := false, false
	for {
		tok, err := decoder.RawToken()
		if err == io.EOF {
			break
		}
		if err != nil {
			return bad()
		}
		nodes++
		if nodes > limits.Nodes {
			return failure("LIMIT_EXCEEDED", "xml")
		}
		switch token := tok.(type) {
		case xml.StartElement:
			if len(stack) >= limits.Depth || len(token.Attr) > limits.Attributes {
				return failure("LIMIT_EXCEEDED", "xml")
			}
			ns := map[string]string{"xml": xmlNS}
			if len(stack) > 0 {
				for p, u := range stack[len(stack)-1].ns {
					ns[p] = u
				}
			}
			declarations := map[string]bool{}
			for _, a := range token.Attr {
				if a.Name.Space == "xmlns" || a.Name.Space == "" && a.Name.Local == "xmlns" {
					p := a.Name.Local
					if a.Name.Space == "" {
						p = ""
					}
					if declarations[p] || p != "" && !ncname(p) || p == "xmlns" || a.Value == xmlnsNS || p == "xml" && a.Value != xmlNS || p != "xml" && a.Value == xmlNS || p != "" && a.Value == "" {
						return bad()
					}
					declarations[p] = true
					ns[p] = a.Value
				}
			}
			expanded, ok := resolve(token.Name, ns, false)
			if !ok {
				return bad()
			}
			attrs := map[xml.Name]bool{}
			for _, a := range token.Attr {
				if a.Name.Space == "xmlns" || a.Name.Space == "" && a.Name.Local == "xmlns" {
					continue
				}
				name, ok := resolve(a.Name, ns, true)
				if !ok || attrs[name] {
					return bad()
				}
				attrs[name] = true
			}
			depth := len(stack)
			if depth == 0 {
				roots++
				if roots != 1 {
					return bad()
				}
				if mode == "payload" {
					if expanded.Local != operation {
						return bad()
					}
				} else if mode == "header" {
					if expanded.Space == "" {
						return bad()
					}
				} else if mode == "body" {
					if expanded != (xml.Name{Space: soapNS, Local: "Body"}) {
						return bad()
					}
				} else if expanded != (xml.Name{Space: soapNS, Local: "Envelope"}) {
					return bad()
				}
			}
			if mode == "payload" && (expanded.Space == SOAP11 || expanded.Space == SOAP12) {
				return bad()
			}
			if mode == "envelope" && depth == 1 {
				switch expanded {
				case xml.Name{Space: soapNS, Local: "Header"}:
					if header || body {
						return bad()
					}
					header = true
				case xml.Name{Space: soapNS, Local: "Body"}:
					if body {
						return bad()
					}
					body = true
				default:
					return bad()
				}
			}
			if mode == "envelope" && (expanded.Space == SOAP11 || expanded.Space == SOAP12) {
				switch expanded.Local {
				case "Envelope":
					if depth != 0 {
						return bad()
					}
				case "Header", "Body":
					if depth != 1 {
						return bad()
					}
				}
			}
			stack = append(stack, frame{raw: token.Name, ns: ns})
		case xml.EndElement:
			if len(stack) == 0 || stack[len(stack)-1].raw != token.Name {
				return bad()
			}
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if (len(stack) == 0 || mode == "envelope" && len(stack) == 1) && strings.TrimSpace(string(token)) != "" {
				return bad()
			}
		case xml.Directive, xml.ProcInst:
			return bad()
		}
	}
	if roots != 1 || len(stack) != 0 || mode == "envelope" && !body {
		return bad()
	}
	return nil
}

func resolve(name xml.Name, ns map[string]string, attribute bool) (xml.Name, bool) {
	if !ncname(name.Local) || name.Space != "" && !ncname(name.Space) || name.Space == "xmlns" {
		return xml.Name{}, false
	}
	if name.Space == "" {
		if !attribute {
			name.Space = ns[""]
		}
		return name, true
	}
	uri, ok := ns[name.Space]
	if !ok || uri == "" {
		return xml.Name{}, false
	}
	return xml.Name{Space: uri, Local: name.Local}, true
}
