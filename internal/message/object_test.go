package message

import (
	"strings"
	"testing"
)

func TestMarshalObjectBoundsAndValidity(t *testing.T) {
	text := strings.Repeat("&", 100)
	_, e := MarshalObject("Echo", "urn:test", ObjectElement{Text: &text}, Limits{Bytes: 128})
	code(t, e, "LIMIT_EXCEEDED")
	for _, node := range []ObjectElement{
		{Attributes: []ObjectAttribute{{Name: "a", Value: "x"}, {Name: "a", Value: "y"}}},
		{Attributes: []ObjectAttribute{{Name: "xmlns", Value: "urn:private"}}},
		{Attributes: []ObjectAttribute{{Name: "a", Value: "\x00"}}},
		{Children: []ObjectElement{{Name: "p:x"}}},
		{Text: &text, Children: []ObjectElement{{Name: "x"}}},
	} {
		_, e = MarshalObject("Echo", "urn:test", node, Limits{})
		code(t, e, "INVALID_ARGUMENT")
	}
}
