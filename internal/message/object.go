package message

import (
	"bytes"
	"encoding/xml"
	"strings"
	"unicode/utf8"
)

// ObjectElement is an ordered, runtime-independent payload projection.
type ObjectElement struct {
	Name       string
	Attributes []ObjectAttribute
	Text       *string
	Children   []ObjectElement
}
type ObjectAttribute struct {
	Name  string
	Value string
}

func ValidObjectName(name string) bool {
	return utf8.ValidString(name) && ncname(name) && name != "xmlns"
}
func validObjectText(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if !(r == 9 || r == 10 || r == 13 || r >= 0x20 && r <= 0xD7FF || r >= 0xE000 && r <= 0xFFFD || r >= 0x10000 && r <= 0x10FFFF) {
			return false
		}
	}
	return true
}
func ValidObjectNamespace(namespace string) bool {
	return namespace != "" && namespace != xmlNS && namespace != xmlnsNS && namespace != SOAP11 && namespace != SOAP12 && !strings.ContainsAny(namespace, " \t\r\n") && validObjectText(namespace)
}

type objectOutput struct {
	bytes.Buffer
	max int
}

func (w *objectOutput) Write(p []byte) (int, error) {
	if len(p) > w.max-w.Len() {
		return 0, failure("LIMIT_EXCEEDED", "payload")
	}
	return w.Buffer.Write(p)
}

// MarshalObject uses the standard XML encoder for escaping, never canonicalization.
// Envelope validation remains authoritative for complete byte/token/depth limits.
func MarshalObject(operation, namespace string, root ObjectElement, limits Limits) (string, error) {
	limits, e := limits.Normalized()
	if e != nil {
		return "", e
	}
	bad := func() error { return failure("INVALID_ARGUMENT", "payload") }
	if !ValidObjectName(operation) || !ValidObjectNamespace(namespace) {
		return "", bad()
	}
	root.Name = operation
	out := &objectOutput{max: limits.Bytes}
	encoder := xml.NewEncoder(out)
	nodes := 0
	var write func(ObjectElement, int) error
	write = func(node ObjectElement, depth int) error {
		nodes++
		if depth+2 > limits.Depth || nodes > limits.Nodes {
			return failure("LIMIT_EXCEEDED", "payload")
		}
		if !ValidObjectName(node.Name) || node.Text != nil && len(node.Children) > 0 {
			return bad()
		}
		if len(node.Attributes) > limits.Attributes {
			return failure("LIMIT_EXCEEDED", "payload")
		}
		start := xml.StartElement{Name: xml.Name{Local: node.Name}}
		if depth == 1 {
			start.Attr = append(start.Attr, xml.Attr{Name: xml.Name{Local: "xmlns"}, Value: namespace})
		}
		seen := map[string]bool{}
		for _, a := range node.Attributes {
			if !ValidObjectName(a.Name) || seen[a.Name] || !validObjectText(a.Value) {
				return bad()
			}
			seen[a.Name] = true
			start.Attr = append(start.Attr, xml.Attr{Name: xml.Name{Local: a.Name}, Value: a.Value})
		}
		if e := encoder.EncodeToken(start); e != nil {
			return e
		}
		if node.Text != nil {
			if !validObjectText(*node.Text) {
				return bad()
			}
			if e := encoder.EncodeToken(xml.CharData(*node.Text)); e != nil {
				return e
			}
		}
		for _, child := range node.Children {
			if e := write(child, depth+1); e != nil {
				return e
			}
		}
		return encoder.EncodeToken(start.End())
	}
	if e = write(root, 1); e != nil {
		return "", e
	}
	if e = encoder.Flush(); e != nil {
		return "", e
	}
	return out.String(), nil
}
