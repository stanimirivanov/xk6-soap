package message

import (
	"errors"
	"strings"

	"github.com/antchfx/xmlquery"
)

func readFault(n *xmlquery.Node, ns string) (map[string]any, error) {
	expectedNS := ns
	allowed := map[string]bool{"Code": true, "Reason": true, "Node": true, "Role": true, "Detail": true}
	if ns == SOAP11 {
		expectedNS = ""
		allowed = map[string]bool{"faultcode": true, "faultstring": true, "faultactor": true, "detail": true}
	}
	seen := map[string]bool{}
	for field := n.FirstChild; field != nil; field = field.NextSibling {
		if field.Type != xmlquery.ElementNode {
			continue
		}
		if field.NamespaceURI != expectedNS || !allowed[field.Data] || seen[field.Data] {
			return nil, errors.New("invalid fault")
		}
		seen[field.Data] = true
	}
	fault := map[string]any{"code": nil, "subcodes": []any{}, "reason": nil, "reasons": []any{}, "role": nil, "node": nil, "detail": nil}
	text := func(parent *xmlquery.Node, space, name string) string {
		if c := child(parent, space, name); c != nil {
			return c.InnerText()
		}
		return ""
	}
	if ns == SOAP11 {
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
		c := child(n, ns, "Code")
		r := child(n, ns, "Reason")
		if c == nil || r == nil || child(c, ns, "Value") == nil {
			return nil, errors.New("invalid fault")
		}
		expanded, err := faultQName(child(c, ns, "Value"))
		if err != nil {
			return nil, err
		}
		fault["code"] = expanded
		subcodes := []any{}
		for sub := child(c, ns, "Subcode"); sub != nil; sub = child(sub, ns, "Subcode") {
			value := child(sub, ns, "Value")
			if value == nil {
				return nil, errors.New("invalid fault")
			}
			expanded, err := faultQName(value)
			if err != nil {
				return nil, err
			}
			subcodes = append(subcodes, expanded)
		}
		fault["subcodes"] = subcodes
		reasons := []any{}
		preferred := ""
		foundEnglish := false
		for reason := r.FirstChild; reason != nil; reason = reason.NextSibling {
			if reason.Type != xmlquery.ElementNode || reason.NamespaceURI != ns || reason.Data != "Text" {
				continue
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
		if node := text(n, ns, "Node"); node != "" {
			fault["node"] = node
		}
		if role := text(n, ns, "Role"); role != "" {
			fault["role"] = role
		}
		if detail := child(n, ns, "Detail"); detail != nil {
			fault["detail"] = detail.OutputXMLWithOptions(xmlquery.WithPreserveSpace())
		}
	}
	return fault, nil
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
