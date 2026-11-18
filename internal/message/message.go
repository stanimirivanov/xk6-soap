// Package message validates plain SOAP boundaries. It does not canonicalize XML.
package message

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	SOAP11 = "http://schemas.xmlsoap.org/soap/envelope/"
	SOAP12 = "http://www.w3.org/2003/05/soap-envelope"
)

// Error contains only stable diagnostics; hostile XML and action values are omitted.
type Error struct{ Code, Stage string }

func (e *Error) Error() string         { return fmt.Sprintf("%s: %s", e.Code, e.Stage) }
func failure(code, stage string) error { return &Error{Code: code, Stage: stage} }

// Limits may reduce defaults. Zero selects the default; increases are unsupported.
// Nodes counts all decoder tokens, including closing tags, text and comments.
type Limits struct{ Bytes, Depth, Nodes, Attributes int }

func (l Limits) normalized() (Limits, error) {
	values := []*int{&l.Bytes, &l.Depth, &l.Nodes, &l.Attributes}
	for i, max := range []int{4 << 20, 64, 50000, 64} {
		if *values[i] < 0 || *values[i] > max {
			return l, failure("INVALID_ARGUMENT", "limits")
		}
		if *values[i] == 0 {
			*values[i] = max
		}
	}
	return l, nil
}

type Options struct {
	Version, Action string
	Limits          Limits
}
type Request struct {
	Body    string
	Headers map[string]string
}

func namespace(version string) (string, error) {
	switch version {
	case "", "1.1":
		return SOAP11, nil
	case "1.2":
		return SOAP12, nil
	}
	return "", failure("INVALID_ARGUMENT", "soapVersion")
}

// Build preserves the caller's raw operation XML verbatim within a new envelope.
// The resulting plain document is not suitable for post-signature serialization.
func Build(operation, payload string, options Options) (Request, error) {
	var result Request
	ns, err := namespace(options.Version)
	if err != nil {
		return result, err
	}
	limits, err := options.Limits.normalized()
	if err != nil {
		return result, err
	}
	if !utf8.ValidString(operation) || !ncname(operation) {
		return result, failure("INVALID_ARGUMENT", "operation")
	}
	if !utf8.ValidString(options.Action) || len(options.Action) > limits.Bytes {
		return result, failure("INVALID_ARGUMENT", "soapAction")
	}
	for _, r := range options.Action {
		if unicode.IsControl(r) || r == '"' || r == '\\' {
			return result, failure("INVALID_ARGUMENT", "soapAction")
		}
	}
	if err := validate(payload, limits, "payload", operation, ns); err != nil {
		return result, err
	}
	// A prefixed wrapper adds no default namespace to the standalone payload.
	prefix := `<s:Envelope xmlns:s="` + ns + `"><s:Body>`
	suffix := `</s:Body></s:Envelope>`
	if len(payload) > limits.Bytes-len(prefix)-len(suffix) {
		return result, failure("LIMIT_EXCEEDED", "xml")
	}
	body := prefix + payload + suffix
	if err := validate(body, limits, "envelope", "", ns); err != nil {
		return result, err
	}
	headers := map[string]string{}
	if ns == SOAP11 {
		headers["Content-Type"] = "text/xml; charset=utf-8"
		headers["SOAPAction"] = `"` + options.Action + `"`
	} else {
		headers["Content-Type"] = "application/soap+xml; charset=utf-8"
		if options.Action != "" {
			headers["Content-Type"] += `; action="` + options.Action + `"`
		}
	}
	return Request{Body: body, Headers: headers}, nil
}

func ValidateEnvelope(document, version string, limits Limits) error {
	ns, err := namespace(version)
	if err != nil {
		return err
	}
	limits, err = limits.normalized()
	if err != nil {
		return err
	}
	return validate(document, limits, "envelope", "", ns)
}

// XML 1.0 (fifth edition) NCName ranges, excluding the namespace separator.
func nameStart(r rune) bool {
	return r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= 0xC0 && r <= 0xD6 || r >= 0xD8 && r <= 0xF6 || r >= 0xF8 && r <= 0x2FF || r >= 0x370 && r <= 0x37D || r >= 0x37F && r <= 0x1FFF || r >= 0x200C && r <= 0x200D || r >= 0x2070 && r <= 0x218F || r >= 0x2C00 && r <= 0x2FEF || r >= 0x3001 && r <= 0xD7FF || r >= 0xF900 && r <= 0xFDCF || r >= 0xFDF0 && r <= 0xFFFD || r >= 0x10000 && r <= 0xEFFFF
}
func ncname(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if nameStart(r) {
			continue
		}
		if i == 0 || !(r == '-' || r == '.' || r >= '0' && r <= '9' || r == 0xB7 || r >= 0x300 && r <= 0x36F || r >= 0x203F && r <= 0x2040) {
			return false
		}
	}
	return !strings.ContainsRune(s, ':')
}
