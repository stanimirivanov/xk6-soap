package message

import (
	"github.com/antchfx/xmlquery"
	"github.com/antchfx/xpath"
	"strings"
	"unicode"
	"unicode/utf8"
)

// strictXPath binds unprefixed element/attribute name tests to the empty
// namespace. antchfx otherwise matches the source prefix, which incorrectly
// includes default-namespaced elements. Quoted literals/functions/axes/operators
// are preserved; compilation and evaluation remain owned by the XPath library.
func strictXPath(input string, namespaces map[string]string) (string, map[string]string) {
	prefix := "_soap_empty"
	for strings.Contains(input, prefix) {
		prefix += "_"
	}
	var out strings.Builder
	operand := false
	for i := 0; i < len(input); {
		c := input[i]
		if c == '\'' || c == '"' {
			end := i + 1
			for end < len(input) && input[end] != c {
				end++
			}
			if end < len(input) {
				end++
			}
			out.WriteString(input[i:end])
			i = end
			operand = true
			continue
		}
		// XPath NCNames have the same XML name characters used by message validation.
		r, size := utf8.DecodeRuneInString(input[i:])
		if nameStart(r) {
			end := i + size
			for end < len(input) {
				next, n := utf8.DecodeRuneInString(input[end:])
				if !(nameStart(next) || next == '-' || next == '.' || unicode.IsDigit(next) || next == 0xB7 || next >= 0x300 && next <= 0x36F || next >= 0x203F && next <= 0x2040) {
					break
				}
				end += n
			}
			name := input[i:end]
			look := end
			for look < len(input) && strings.ContainsRune(" \t\r\n", rune(input[look])) {
				look++
			}
			axis := strings.HasPrefix(input[look:], "::")
			function := look < len(input) && input[look] == '('
			qualified := end < len(input) && input[end] == ':' && !strings.HasPrefix(input[end:], "::")
			operator := operand && (name == "and" || name == "or" || name == "div" || name == "mod")
			if qualified {
				// Copy the entire QName (including namespace wildcard), never its local part.
				end++
				if end < len(input) && input[end] == '*' {
					uri, ok := namespaces[name]
					if !ok {
						panic("undefined prefix")
					}
					out.WriteString("*[namespace-uri()=" + xpathLiteral(uri) + "]")
					i = end + 1
					operand = true
					continue
				}
				for end < len(input) {
					next, n := utf8.DecodeRuneInString(input[end:])
					if !(nameStart(next) || unicode.IsDigit(next) || next == '-' || next == '.' || next == '*') {
						break
					}
					end += n
				}
				out.WriteString(input[i:end])
				operand = true
			} else if axis || function || operator {
				out.WriteString(name)
				if operator {
					operand = false
				}
			} else {
				out.WriteString(prefix + ":" + name)
				operand = true
			}
			i = end
			continue
		}
		out.WriteByte(c)
		i++
		switch c {
		case '/', '@', '[', '(', '=', '<', '>', '+', '-', ',', '|', ':':
			operand = false
		case ']', ')', '*', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			operand = true
		}
	}
	return out.String(), map[string]string{prefix: ""}
}

// xpathLiteral quotes namespace URIs as XPath string literals without allowing
// namespace values to inject executable expression text.
func xpathLiteral(value string) string {
	if !strings.Contains(value, "'") {
		return "'" + value + "'"
	}
	if !strings.Contains(value, `"`) {
		return `"` + value + `"`
	}
	parts := strings.Split(value, "'")
	for i, part := range parts {
		parts[i] = "'" + part + "'"
	}
	return "concat(" + strings.Join(parts, `,"'",`) + ")"
}

type bodyNavigator struct{ *xmlquery.NodeNavigator }

func (n *bodyNavigator) Copy() xpath.NodeNavigator {
	return &bodyNavigator{n.NodeNavigator.Copy().(*xmlquery.NodeNavigator)}
}
func (n *bodyNavigator) Value() string {
	if n.Current().Type == xmlquery.CharDataNode {
		return n.Current().Data
	}
	return n.NodeNavigator.Value()
}

func (n *bodyNavigator) MoveTo(other xpath.NodeNavigator) bool {
	target, ok := other.(*bodyNavigator)
	return ok && n.NodeNavigator.MoveTo(target.NodeNavigator)
}
