package message

import (
	"encoding/xml"
	"strings"

	"github.com/antchfx/xmlquery"
	"github.com/antchfx/xpath"
)

// Parsed owns an isolated read-only Body projection. No node is exported.
type Parsed struct {
	OK             bool
	Status         int
	Body           *string
	Fault          map[string]any
	Error          *Error
	root           *xmlquery.Node
	budget         int
	SigVerified    *bool
	TimestampValid *bool
}

func Parse(status int, body, version string, limits Limits) (result *Parsed) {
	result = &Parsed{Status: status}
	defer func() {
		if recover() != nil {
			result = &Parsed{Status: status, Error: &Error{Code: "XML_INVALID", Stage: "parse"}}
		}
	}()
	fail := func(code string) *Parsed { result.Error = &Error{Code: code, Stage: "parse"}; return result }
	if status == 0 {
		return fail("TRANSPORT_ERROR")
	}
	if body == "" {
		return fail("BODY_UNAVAILABLE")
	}
	if err := ValidateEnvelope(body, version, limits); err != nil {
		result.Error = err.(*Error)
		return result
	}
	normalized, _ := limits.Normalized()
	doc, err := xmlquery.Parse(strings.NewReader(body))
	if err != nil {
		return fail("XML_INVALID")
	}
	ns, _ := namespace(version)
	env := child(doc, ns, "Envelope")
	if env == nil {
		return fail("XML_INVALID")
	}
	if err := plainPolicy(env, ns); err != nil {
		result.Error = err
		return result
	}
	node := child(env, ns, "Body")
	if node == nil {
		return fail("XML_INVALID")
	}
	return projectBody(status, node, ns, normalized, false)
}

// ParseAcceptedBody projects only the security adapter's accepted canonical Body.
// It never receives or reselects content from the untrusted envelope.
func ParseAcceptedBody(status int, body, version string, limits Limits) (result *Parsed) {
	result = &Parsed{Status: status}
	defer func() {
		if recover() != nil {
			result = &Parsed{Status: status, Error: &Error{Code: "XML_INVALID", Stage: "parse"}}
		}
	}()
	normalized, e := limits.Normalized()
	if e != nil {
		result.Error = e.(*Error)
		return result
	}
	ns, e := namespace(version)
	if e != nil {
		result.Error = e.(*Error)
		return result
	}
	if e = validate(body, normalized, "body", "", ns); e != nil {
		result.Error = e.(*Error)
		return result
	}
	doc, e := xmlquery.Parse(strings.NewReader(body))
	if e != nil {
		result.Error = &Error{Code: "XML_INVALID", Stage: "parse"}
		return result
	}
	node := child(doc, ns, "Body")
	if node == nil {
		result.Error = &Error{Code: "XML_INVALID", Stage: "parse"}
		return result
	}
	return projectBody(status, node, ns, normalized, true)
}
func projectBody(status int, node *xmlquery.Node, ns string, normalized Limits, selfContained bool) *Parsed {
	result := &Parsed{Status: status}
	fail := func(code string) *Parsed { result.Error = &Error{Code: code, Stage: "parse"}; return result }
	var err error
	// Preserve inherited namespace bindings for QName-valued fault codes before
	// detaching the Body from all envelope/header/sibling navigation paths.
	budget := normalized.Bytes
	if !retainNamespaces(node, nil) {
		return fail("LIMIT_EXCEEDED")
	}
	if selfContained {
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			if c.Type == xmlquery.ElementNode {
				if !retainNamespaces(c, &budget) {
					return fail("LIMIT_EXCEEDED")
				}
			}
		}
	}
	node.Parent = nil
	node.PrevSibling = nil
	node.NextSibling = nil
	text := node.OutputXMLWithOptions(xmlquery.WithPreserveSpace())
	if len(text) > normalized.Bytes {
		return fail("LIMIT_EXCEEDED")
	}
	var fault map[string]any
	elements := 0
	for n := node.FirstChild; n != nil; n = n.NextSibling {
		if n.Type == xmlquery.ElementNode {
			elements++
		}
	}
	for n := node.FirstChild; n != nil; n = n.NextSibling {
		if n.Type == xmlquery.ElementNode && n.NamespaceURI == ns && n.Data == "Fault" {
			if fault != nil || elements != 1 {
				return fail("XML_INVALID")
			}
			fault, err = readFault(n, ns)
			if err != nil {
				return fail("XML_INVALID")
			}
		}
	}
	result.Body = &text
	result.root = node
	result.budget = normalized.Bytes
	result.Fault = fault
	if fault != nil {
		return fail("SOAP_FAULT")
	}
	if status < 200 || status >= 300 {
		return fail("HTTP_STATUS")
	}
	result.OK = true
	return result
}

func retainNamespaces(node *xmlquery.Node, budget *int) bool {
	bindings := namespaceBindings(node)
	for prefix, uri := range bindings {
		if prefix == "xml" {
			continue
		}
		present := false
		for _, a := range node.Attr {
			if a.Name.Space == "xmlns" && a.Name.Local == prefix || prefix == "" && a.Name.Space == "" && a.Name.Local == "xmlns" {
				present = true
			}
		}
		if !present {
			// Reserve the worst-case escaped attribute size before copying bindings.
			cost := len(prefix) + 6*len(uri) + 12
			if budget != nil && cost > *budget {
				return false
			}
			if budget != nil {
				*budget -= cost
			}
			a := xmlquery.Attr{Value: uri}
			a.Name.Space = "xmlns"
			a.Name.Local = prefix
			if prefix == "" {
				a.Name.Space = ""
				a.Name.Local = "xmlns"
			}
			node.Attr = append(node.Attr, a)
		}
	}

	return true
}
func child(parent *xmlquery.Node, ns, name string) *xmlquery.Node {
	for n := parent.FirstChild; n != nil; n = n.NextSibling {
		if n.Type == xmlquery.ElementNode && n.NamespaceURI == ns && n.Data == name {
			return n
		}
	}
	return nil
}
func namespaceBindings(n *xmlquery.Node) map[string]string {
	bindings := map[string]string{"xml": xmlNS}
	var chain []*xmlquery.Node
	for p := n; p != nil; p = p.Parent {
		chain = append(chain, p)
	}
	for i := len(chain) - 1; i >= 0; i-- {
		for _, a := range chain[i].Attr {
			if a.Name.Space == "xmlns" {
				bindings[a.Name.Local] = a.Value
			} else if a.Name.Local == "xmlns" && a.Name.Space == "" {
				bindings[""] = a.Value
			}
		}
	}
	return bindings
}

// XPath compiles per call (no global cache) and only traverses the detached Body.
func (p *Parsed) XPath(expression string, ns map[string]string) (value any, err error) {
	defer func() {
		if recover() != nil {
			value = nil
			err = failure("XPATH_INVALID", "xpath")
		}
	}()
	if p.root == nil {
		return nil, failure("CONTENT_UNAVAILABLE", "xpath")
	}
	if len(expression) > 4096 {
		return nil, failure("LIMIT_EXCEEDED", "xpath")
	}
	if len(ns) > 64 {
		return nil, failure("LIMIT_EXCEEDED", "xpath")
	}
	bindings := map[string]string{}
	for prefix, uri := range ns {
		if !ncname(prefix) || uri == "" || len(uri) > 4096 {
			return nil, failure("XPATH_INVALID", "xpath")
		}
		bindings[prefix] = uri
	}
	expression, emptyBinding := strictXPath(expression, bindings)
	for prefix, uri := range emptyBinding {
		bindings[prefix] = uri
	}
	if len(expression) > 32768 {
		return nil, failure("LIMIT_EXCEEDED", "xpath")
	}
	expr, compileErr := xpath.CompileWithNS(expression, bindings)
	if compileErr != nil {
		return nil, failure("XPATH_INVALID", "xpath")
	}
	value = expr.Evaluate(&bodyNavigator{xmlquery.CreateXPathNavigator(p.root)})
	if nodes, ok := value.(*xpath.NodeIterator); ok {
		values := []string{}
		total := 0
		for nodes.MoveNext() {
			if len(values) >= 1000 {
				return nil, failure("LIMIT_EXCEEDED", "xpath")
			}
			text := nodes.Current().Value()
			total += len(text)
			if total > p.budget {
				return nil, failure("LIMIT_EXCEEDED", "xpath")
			}
			values = append(values, text)
		}
		return values, nil
	}
	switch v := value.(type) {
	case string:
		if len(v) > p.budget {
			return nil, failure("LIMIT_EXCEEDED", "xpath")
		}
	case float64, bool:
	default:
		return nil, failure("XPATH_INVALID", "xpath")
	}
	return value, nil
}

// CheckSecurityEnvelope applies ordinary SOAP header handling while allowing the
// security adapter to understand the targeted Security header. The security
// adapter is responsible for checking the encryption graph.
func CheckSecurityEnvelope(body, version string, limits Limits, understood ...xml.Name) *Error {
	if e := ValidateEnvelope(body, version, limits); e != nil {
		return e.(*Error)
	}
	doc, e := xmlquery.Parse(strings.NewReader(body))
	if e != nil {
		return &Error{Code: "XML_INVALID", Stage: "parse"}
	}
	ns, _ := namespace(version)
	return headerPolicy(child(doc, ns, "Envelope"), ns, true, understood...)
}
func plainPolicy(env *xmlquery.Node, ns string) *Error { return headerPolicy(env, ns, false) }
func headerPolicy(env *xmlquery.Node, ns string, security bool, allowed ...xml.Name) *Error {
	// Plain mode never reports success for encrypted content it cannot interpret.
	var visit func(*xmlquery.Node) bool
	visit = func(n *xmlquery.Node) bool {
		if n.Type == xmlquery.ElementNode && (n.NamespaceURI == "http://www.w3.org/2001/04/xmlenc#" || n.NamespaceURI == "http://www.w3.org/2009/xmlenc11#" || n.NamespaceURI == "http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd" && n.Data == "EncryptedHeader") {
			return false
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if !visit(c) {
				return false
			}
		}
		return true
	}
	if !security && !visit(env) {
		return &Error{Code: "POLICY_VIOLATION", Stage: "parse"}
	}
	if header := child(env, ns, "Header"); header != nil {
		for n := header.FirstChild; n != nil; n = n.NextSibling {
			if n.Type != xmlquery.ElementNode {
				continue
			}
			if n.NamespaceURI == "" {
				return &Error{Code: "XML_INVALID", Stage: "parse"}
			}
			required := false
			role := ""
			for _, a := range n.Attr {
				if a.NamespaceURI == ns {
					switch a.Name.Local {
					case "mustUnderstand":
						if a.Value != "0" && a.Value != "1" && (ns != SOAP12 || a.Value != "true" && a.Value != "false") {
							return &Error{Code: "XML_INVALID", Stage: "parse"}
						}
						required = a.Value == "1" || a.Value == "true"
					case "role", "actor":
						if (a.Name.Local == "role" && ns != SOAP12) || (a.Name.Local == "actor" && ns != SOAP11) || !absoluteURI(a.Value) {
							return &Error{Code: "XML_INVALID", Stage: "parse"}
						}
						role = a.Value
					}
				}
			}
			targeted := role == "" || ns == SOAP12 && (role == SOAP12+"/role/ultimateReceiver" || role == SOAP12+"/role/next") || ns == SOAP11 && role == "http://schemas.xmlsoap.org/soap/actor/next"
			addressing := IsAddressingHeader(n.NamespaceURI, n.Data)
			understood := security && n.NamespaceURI == "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" && n.Data == "Security"
			for _, name := range allowed {
				if name.Space == n.NamespaceURI && name.Local == n.Data {
					understood = true
				}
			}
			if required && targeted && !addressing && !understood {
				return &Error{Code: "POLICY_VIOLATION", Stage: "parse"}
			}
		}
	}
	return nil
}
