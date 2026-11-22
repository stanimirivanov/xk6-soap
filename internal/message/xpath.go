package message

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/antchfx/xmlquery"
	"github.com/antchfx/xpath"
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
		if c == '.' || c >= '0' && c <= '9' {
			end := xpathNumberOrStepEnd(input, i)
			out.WriteString(input[i:end])
			i = end
			operand = true
			continue
		}
		r, size := utf8.DecodeRuneInString(input[i:])
		if nameStart(r) {
			end := xpathNameEnd(input, i+size)
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
				end = xpathNameEnd(input, end)
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
		case ']', ')':
			operand = true
		case '*':
			// A wildcard completes a name test. Multiplication starts a new operand.
			operand = !operand
		}
	}
	return out.String(), map[string]string{prefix: ""}
}

func xpathNameEnd(input string, end int) int {
	for end < len(input) {
		next, size := utf8.DecodeRuneInString(input[end:])
		if !(nameStart(next) || next == '-' || next == '.' || unicode.IsDigit(next) || next == 0xB7 || next >= 0x300 && next <= 0x36F || next >= 0x203F && next <= 0x2040) {
			break
		}
		end += size
	}
	return end
}

// A dot can be a context step, the start of a parent step, or part of a number.
// Consume the whole token so the following operator sees a completed operand.
func xpathNumberOrStepEnd(input string, start int) int {
	if strings.HasPrefix(input[start:], "..") {
		return start + 2
	}
	end := xpathDigitsEnd(input, start)
	if end < len(input) && input[end] == '.' {
		end = xpathDigitsEnd(input, end+1)
	}
	return end
}

func xpathDigitsEnd(input string, end int) int {
	for end < len(input) && input[end] >= '0' && input[end] <= '9' {
		end++
	}
	return end
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
