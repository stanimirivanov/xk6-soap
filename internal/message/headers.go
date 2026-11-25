package message

import (
	"encoding/xml"
	"io"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

const AddressingNS = "http://www.w3.org/2005/08/addressing"

// Header is a named standalone XML block. Names select blocks for signing.
type Header struct {
	Name string
	XML  string
}
type Addressing struct {
	Action    string
	To        string
	MessageID string
	ReplyTo   string
}

// HeaderSelector binds a caller-visible selector to one validated direct block.
type HeaderSelector struct {
	Name      string
	Namespace string
	LocalName string
}

func IsAddressingHeader(namespace, local string) bool {
	return namespace == AddressingNS && (local == "Action" || local == "To" || local == "MessageID" || local == "ReplyTo" || local == "RelatesTo")
}
func absoluteURI(value string) bool {
	if value == "" || !utf8.ValidString(value) || strings.ContainsAny(value, "\"<>\\^`{|}") {
		return false
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	// net/url leaves opaque scheme-specific percent escapes unchecked.
	if _, e := url.PathUnescape(value); e != nil {
		return false
	}
	u, e := url.Parse(value)
	return e == nil && u.IsAbs()
}
func headerBlocks(options Options, limits Limits, ns string) (string, []HeaderSelector, string, error) {
	bad := func() (string, []HeaderSelector, string, error) {
		return "", nil, "", failure("INVALID_ARGUMENT", "headers")
	}
	if len(options.Headers) > 16 {
		return "", nil, "", failure("LIMIT_EXCEEDED", "headers")
	}
	names := map[string]bool{"wsaAction": true, "wsaTo": true, "wsaMessageID": true, "wsaReplyTo": true}
	expanded := map[xml.Name]bool{}
	var selectors []HeaderSelector
	var blocks strings.Builder
	for _, h := range options.Headers {
		if len(h.Name) > limits.Bytes {
			return "", nil, "", failure("LIMIT_EXCEEDED", "headers")
		}
		if !utf8.ValidString(h.Name) || !ncname(h.Name) || names[h.Name] {
			return bad()
		}
		names[h.Name] = true
		if err := validate(h.XML, limits, headerMode, "", ns); err != nil {
			return "", nil, "", err
		}
		decoder := xml.NewDecoder(strings.NewReader(h.XML))
		depth := 0
		var root xml.Name
		for {
			tok, e := decoder.Token()
			if e == io.EOF {
				break
			}
			if e != nil {
				return bad()
			}
			switch n := tok.(type) {
			case xml.StartElement:
				if depth == 0 {
					root = n.Name
				}
				depth++
				if n.Name.Space == SOAP11 || n.Name.Space == SOAP12 || n.Name.Space == AddressingNS || n.Name.Space == "http://www.w3.org/2000/09/xmldsig#" || securityNamespace(n.Name.Space) || n.Name.Space == "http://www.w3.org/2001/04/xmlenc#" || n.Name.Space == "http://www.w3.org/2009/xmlenc11#" {
					return bad()
				}
				for _, a := range n.Attr {
					if a.Name.Space == "xmlns" || a.Name.Space == "" && a.Name.Local == "xmlns" {
						continue
					}
					if a.Name.Space == "" && (a.Name.Local == "mustUnderstand" || a.Name.Local == "actor" || a.Name.Local == "role" || a.Name.Local == "relay") {
						return bad()
					}
					if a.Name.Local == "Id" || a.Name.Local == "ID" || a.Name.Space == xmlNS && a.Name.Local == "id" {
						return bad()
					}
					if a.Name.Space == SOAP11 || a.Name.Space == SOAP12 {
						if depth != 1 || a.Name.Space != ns {
							return bad()
						}
						switch a.Name.Local {
						case "mustUnderstand":
							if a.Value != "0" && a.Value != "1" && (ns != SOAP12 || a.Value != "true" && a.Value != "false") {
								return bad()
							}
						case "actor":
							if ns != SOAP11 || !absoluteURI(a.Value) {
								return bad()
							}
						case "role":
							if ns != SOAP12 || !absoluteURI(a.Value) {
								return bad()
							}
						case "relay":
							if ns != SOAP12 || a.Value != "0" && a.Value != "1" && a.Value != "true" && a.Value != "false" {
								return bad()
							}
						default:
							return bad()
						}
					}
				}
			case xml.EndElement:
				depth--
			}
		}
		if root.Space == "" || expanded[root] {
			return bad()
		}
		expanded[root] = true
		if len(h.XML) > limits.Bytes-blocks.Len() {
			return "", nil, "", failure("LIMIT_EXCEEDED", "headers")
		}
		blocks.WriteString(h.XML)
		selectors = append(selectors, HeaderSelector{Name: h.Name, Namespace: root.Space, LocalName: root.Local})
	}
	action := options.Action
	if a := options.Addressing; a != nil {
		for _, value := range []string{a.Action, a.To, a.MessageID, a.ReplyTo} {
			if len(value) > limits.Bytes {
				return "", nil, "", failure("LIMIT_EXCEEDED", "addressing")
			}
		}
		if !absoluteURI(a.Action) || !absoluteURI(a.To) || !absoluteURI(a.MessageID) || !absoluteURI(a.ReplyTo) || a.To != options.URL || (options.ActionSet || action != "") && action != a.Action {
			return "", nil, "", failure("INVALID_ARGUMENT", "addressing")
		}
		action = a.Action
		for j, local := range []string{"Action", "To", "MessageID", "ReplyTo"} {
			value := []string{a.Action, a.To, a.MessageID, a.ReplyTo}[j]
			var escaped strings.Builder
			if xml.EscapeText(&escaped, []byte(value)) != nil {
				return bad()
			}
			text := escaped.String()
			if local == "ReplyTo" {
				text = "<wsa:Address>" + text + "</wsa:Address>"
			}
			block := `<wsa:` + local + ` xmlns:wsa="` + AddressingNS + `">` + text + `</wsa:` + local + `>`
			if len(block) > limits.Bytes-blocks.Len() {
				return "", nil, "", failure("LIMIT_EXCEEDED", "headers")
			}
			blocks.WriteString(block)
			selectors = append(selectors, HeaderSelector{Name: "wsa" + local, Namespace: AddressingNS, LocalName: local})
		}
	}
	return blocks.String(), selectors, action, nil
}

func securityNamespace(ns string) bool {
	switch ns {
	case "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
		"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
		"http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd":
		return true
	}
	return false
}
