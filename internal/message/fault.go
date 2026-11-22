package message

import (
	"errors"
	"slices"
	"strings"

	"github.com/antchfx/xmlquery"
)

func readFault(n *xmlquery.Node, ns string) (map[string]any, error) {
	fault := map[string]any{"code": nil, "subcodes": []any{}, "reason": nil, "reasons": []any{}, "role": nil, "node": nil, "detail": nil}
	if ns == SOAP11 {
		allowed := map[string]bool{"faultcode": true, "faultstring": true, "faultactor": true, "detail": true}
		seen := map[string]bool{}
		for field := n.FirstChild; field != nil; field = field.NextSibling {
			if field.Type != xmlquery.ElementNode {
				continue
			}
			if field.NamespaceURI != "" || !allowed[field.Data] || seen[field.Data] {
				return nil, errors.New("invalid fault")
			}
			seen[field.Data] = true
		}
		codeNode := child(n, "", "faultcode")
		reason := child(n, "", "faultstring")
		if codeNode == nil || reason == nil {
			return nil, errors.New("invalid fault")
		}
		expanded, err := faultQName(codeNode)
		if err != nil {
			return nil, err
		}
		fault["code"] = expanded
		fault["reason"] = reason.InnerText()
		fault["reasons"] = []any{map[string]any{"lang": "", "text": reason.InnerText()}}
		if role := child(n, "", "faultactor"); role != nil {
			fault["role"] = role.InnerText()
		}
		if detail := child(n, "", "detail"); detail != nil {
			fault["detail"] = detail.OutputXMLWithOptions(xmlquery.WithPreserveSpace())
		}
	} else {
		if !orderedFault12Children(n, "Code", "Reason", "Node", "Role", "Detail") {
			return nil, errors.New("invalid fault")
		}
		c := child(n, ns, "Code")
		r := child(n, ns, "Reason")
		if c == nil || r == nil {
			return nil, errors.New("invalid fault")
		}
		subcodes := []any{}
		for field := c; field != nil; field = child(field, ns, "Subcode") {
			value := child(field, ns, "Value")
			if value == nil || !orderedFault12Children(field, "Value", "Subcode") || !faultScalar(value) {
				return nil, errors.New("invalid fault")
			}
			expanded, err := faultQName(value)
			if err != nil {
				return nil, err
			}
			if field == c {
				fault["code"] = expanded
			} else {
				subcodes = append(subcodes, expanded)
			}
		}
		fault["subcodes"] = subcodes
		reasons := []any{}
		preferred := ""
		foundEnglish := false
		for reason := r.FirstChild; reason != nil; reason = reason.NextSibling {
			if faultFormatting(reason) {
				continue
			}
			if reason.Type != xmlquery.ElementNode || reason.NamespaceURI != ns || reason.Data != "Text" || !faultScalar(reason) {
				return nil, errors.New("invalid fault")
			}
			lang := ""
			for _, a := range reason.Attr {
				if a.NamespaceURI == xmlNS && a.Name.Local == "lang" {
					lang = a.Value
				}
			}
			if lang == "" {
				return nil, errors.New("invalid fault")
			}
			value := reason.InnerText()
			reasons = append(reasons, map[string]any{"lang": lang, "text": value})
			if len(reasons) == 1 || !foundEnglish && (strings.EqualFold(lang, "en") || strings.HasPrefix(strings.ToLower(lang), "en-")) {
				preferred = value
			}
			if strings.EqualFold(lang, "en") || strings.HasPrefix(strings.ToLower(lang), "en-") {
				foundEnglish = true
			}
		}
		if len(reasons) == 0 {
			return nil, errors.New("invalid fault")
		}
		fault["reasons"] = reasons
		fault["reason"] = preferred
		for _, field := range []string{"Node", "Role"} {
			if node := child(n, ns, field); node != nil {
				if !faultScalar(node) {
					return nil, errors.New("invalid fault")
				}
				if value := node.InnerText(); value != "" {
					fault[strings.ToLower(field)] = value
				}
			}
		}
		if detail := child(n, ns, "Detail"); detail != nil {
			fault["detail"] = detail.OutputXMLWithOptions(xmlquery.WithPreserveSpace())
		}
	}
	return fault, nil
}

// SOAP 1.2 element-only fields allow formatting whitespace and comments.
func faultFormatting(n *xmlquery.Node) bool {
	switch n.Type {
	case xmlquery.CommentNode:
		return true
	case xmlquery.TextNode, xmlquery.CharDataNode:
		return strings.Trim(n.Data, " \t\r\n") == ""
	default:
		return false
	}
}

// Consume each permitted field once. Omitted fields are checked by the caller
// when required at that level.
func orderedFault12Children(parent *xmlquery.Node, remaining ...string) bool {
	for n := parent.FirstChild; n != nil; n = n.NextSibling {
		if faultFormatting(n) {
			continue
		}
		index := slices.Index(remaining, n.Data)
		if n.Type != xmlquery.ElementNode || n.NamespaceURI != SOAP12 || index < 0 {
			return false
		}
		remaining = remaining[index+1:]
	}
	return true
}

func faultScalar(n *xmlquery.Node) bool {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == xmlquery.ElementNode {
			return false
		}
	}
	return true
}

func faultQName(n *xmlquery.Node) (map[string]any, error) {
	value := strings.TrimSpace(n.InnerText())
	parts := strings.Split(value, ":")
	prefix, local := "", value
	if len(parts) == 2 {
		prefix, local = parts[0], parts[1]
		if !ncname(prefix) {
			return nil, errors.New("invalid fault")
		}
	} else if len(parts) != 1 {
		return nil, errors.New("invalid fault")
	}
	if !ncname(local) {
		return nil, errors.New("invalid fault")
	}
	bindings := namespaceBindings(n)
	uri := bindings[prefix]
	if prefix != "" && uri == "" {
		return nil, errors.New("invalid fault")
	}
	return map[string]any{"namespace": uri, "localName": local}, nil
}
