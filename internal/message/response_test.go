package message

import (
	"reflect"
	"strings"
	"testing"

	"github.com/antchfx/xmlquery"
	"github.com/antchfx/xpath"
)

func wrap(body string) string {
	return `<s:Envelope xmlns:s="` + SOAP11 + `" xmlns:m="urn:test"><s:Header><m:secret>hidden</m:secret></s:Header><s:Body>` + body + `</s:Body></s:Envelope>`
}
func TestParsePlain(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		want   string
	}{
		{200, wrap(`<m:Result>yes</m:Result>`), ""}, {0, "garbage", "TRANSPORT_ERROR"},
		{204, "", "BODY_UNAVAILABLE"}, {200, "garbage", "XML_INVALID"}, {500, wrap(`<x/>`), "HTTP_STATUS"},
		{200, wrap(`<s:Fault><faultcode>s:Server</faultcode><faultstring>Synthetic</faultstring><detail><x/></detail></s:Fault>`), "SOAP_FAULT"},
		{200, wrap(`<x><s:Fault/></x>`), ""},
	} {
		parsed := Parse(tc.status, tc.body, "1.1", Limits{})
		if parsed.Error != nil && parsed.Error.Code != tc.want || parsed.Error == nil && tc.want != "" {
			t.Fatalf("%d %s: %+v", tc.status, tc.body, parsed.Error)
		}
		if parsed.OK != (tc.want == "") {
			t.Fatalf("ok: %+v", parsed)
		}
		if parsed.Error != nil && (tc.want == "XML_INVALID" || tc.want == "TRANSPORT_ERROR") && parsed.Body != nil {
			t.Fatal("failed content exposed")
		}
	}
}
func TestXPathIsolationAndTypes(t *testing.T) {
	parsed := Parse(200, wrap(`<m:Result flag="yes">one</m:Result><m:Result>two</m:Result>`), "1.1", Limits{})
	for _, tc := range []struct {
		expr string
		want any
	}{
		{`//m:Result`, []string{"one", "two"}}, {`string(//m:Result/@flag)`, "yes"},
		{`count(//m:Result)`, float64(2)}, {`boolean(//m:Result)`, true},
		{`//m:secret`, []string{}}, {`../s:Header/m:secret`, []string{}}, {`ancestor::s:Envelope/s:Header/m:secret`, []string{}}, {`../../s:Header`, []string{}}, {`/s:Envelope`, []string{}},
	} {
		value, err := parsed.XPath(tc.expr, map[string]string{"m": "urn:test", "s": SOAP11})
		if err != nil || !reflect.DeepEqual(value, tc.want) {
			t.Fatalf("%s: %#v %v", tc.expr, value, err)
		}
	}
	for _, expr := range []string{`//*[`, `//unknown:Result`, strings.Repeat("x", 4097)} {
		if _, err := parsed.XPath(expr, nil); err == nil {
			t.Fatalf("accepted %s", expr)
		}
	}
	bad := Parse(200, "not XML", "1.1", Limits{})
	_, err := bad.XPath(`//*`, nil)
	code(t, err, "CONTENT_UNAVAILABLE")
	many := Parse(200, wrap(strings.Repeat(`<x/>`, 1001)), "1.1", Limits{})
	_, err = many.XPath(`//x`, nil)
	code(t, err, "LIMIT_EXCEEDED")
}
func TestFaultDetails(t *testing.T) {
	p := Parse(500, wrap(`<s:Fault><faultcode>s:Server</faultcode><faultstring>oops</faultstring><faultactor>role</faultactor><detail><x>detail</x></detail></s:Fault>`), "1.1", Limits{})
	if p.Fault == nil || p.Fault["reason"] != "oops" || p.Fault["role"] != "role" {
		t.Fatalf("fault: %#v", p.Fault)
	}
	p = Parse(500, `<s:Envelope xmlns:s="`+SOAP12+`" xmlns:m="urn:test"><s:Body><s:Fault><s:Code><s:Value>s:Receiver</s:Value><s:Subcode><s:Value>m:Bad</s:Value></s:Subcode></s:Code><s:Reason><s:Text xml:lang="bg">грешка</s:Text><s:Text xml:lang="en">error</s:Text></s:Reason><s:Node>node</s:Node><s:Role>role</s:Role><s:Detail><m:data/></s:Detail></s:Fault></s:Body></s:Envelope>`, "1.2", Limits{})
	if p.Fault == nil || p.Fault["reason"] != "error" || p.Fault["node"] != "node" || len(p.Fault["subcodes"].([]any)) != 1 {
		t.Fatalf("fault: %#v, error %v", p.Fault, p.Error)
	}
}

func TestDefaultNamespaceAndUnavailableResults(t *testing.T) {
	p := Parse(200, wrap(`<Result xmlns="urn:test">value</Result>`), "1.1", Limits{})
	value, err := p.XPath(`//Result`, nil)
	if err != nil || !reflect.DeepEqual(value, []string{}) {
		t.Fatalf("unprefixed XPath must not match namespaced XML: %#v %v", value, err)
	}
	value, err = p.XPath(`//q:Result`, map[string]string{"q": "urn:test"})
	if err != nil || !reflect.DeepEqual(value, []string{"value"}) {
		t.Fatalf("namespace query: %#v %v", value, err)
	}
	for _, body := range []string{
		`<s:Envelope xmlns:s="` + SOAP11 + `"><s:Header><x:Required xmlns:x="urn:other" s:mustUnderstand="1"/></s:Header><s:Body/></s:Envelope>`,
		wrap(`<e:EncryptedData xmlns:e="http://www.w3.org/2001/04/xmlenc#"/>`),
	} {
		p := Parse(200, body, "1.1", Limits{})
		if p.Body != nil || p.Error == nil || p.Error.Code != "POLICY_VIOLATION" {
			t.Fatalf("policy: %+v", p)
		}
	}
}

func TestXPathNameTestsAndOperators(t *testing.T) {
	p := Parse(200, wrap(`<Result xmlns="urn:test">default</Result><x n="2">plain</x><and>node</and>`), "1.1", Limits{})
	for _, tc := range []struct {
		expression string
		want       any
	}{
		{`name(//*[local-name()='Result'])`, "Result"},
		{`namespace-uri(//*[local-name()='Result'])`, "urn:test"},
		{`//x[@n=2 and text()='plain']`, []string{"plain"}},
		{`1 and true()`, true}, {`1 div 2`, float64(0.5)},
		{`count(child::x)`, float64(1)}, {`/s:Body/x`, []string{}},
		{`//and`, []string{"node"}}, {`string('urn:literal value')`, "urn:literal value"},
	} {
		value, err := p.XPath(tc.expression, map[string]string{"s": SOAP11})
		if err != nil || !reflect.DeepEqual(value, tc.want) {
			t.Fatalf("%s: %#v %v", tc.expression, value, err)
		}
	}
}

func TestXPathCDATAAndNamespaceWildcard(t *testing.T) {
	p := Parse(200, wrap(`<m:Result><![CDATA[hello<world]]></m:Result>`), "1.1", Limits{})
	for _, expression := range []string{`//m:Result/text()`, `//m:*`} {
		value, err := p.XPath(expression, map[string]string{"m": "urn:test"})
		if err != nil || !reflect.DeepEqual(value, []string{"hello<world"}) {
			t.Fatalf("%s: %#v %v", expression, value, err)
		}
	}
}

func TestXPathOperandBoundaries(t *testing.T) {
	p := Parse(200, wrap(`<m:名>文字</m:名><m:Value>2</m:Value><and xmlns="urn:other">9</and><and>3</and>`), "1.1", Limits{})
	for _, tc := range []struct {
		expression string
		want       any
	}{
		{`. and true()`, true},
		{`.. or true()`, true},
		{`./m:名[. and true()][.. and true()]`, []string{"文字"}},
		{`child::* and true()`, true},
		{`./m:*`, []string{"文字", "2"}},
		{`2 * and`, float64(6)},
		{`./m:Value*and`, float64(6)},
		{`.5 * and`, float64(1.5)},
		{`3. div 2`, float64(1.5)},
		{`string('.. or *')`, ".. or *"},
	} {
		t.Run(tc.expression, func(t *testing.T) {
			got, err := p.XPath(tc.expression, map[string]string{"m": "urn:test"})
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %#v, %v; want %#v", got, err, tc.want)
			}
		})
	}
}

func TestXPathRewriteEquivalence(t *testing.T) {
	p := Parse(200, wrap(`<m:Value>3</m:Value>`), "1.1", Limits{})
	if !p.OK {
		t.Fatal(p.Error)
	}
	bindings := map[string]string{"m": "urn:test"}
	// Qualified names and these other operands have identical meaning before
	// and after namespace adaptation. Test both truth values for and/or.
	for _, operand := range []string{".", "..", "child::*", "./m:Value", "./m:Value[1]", "(.)", "3.", ".5", "'text'"} {
		for _, suffix := range []string{" and true()", " and false()", " or true()", " or false()"} {
			expression := operand + suffix
			reference, err := xpath.CompileWithNS(expression, bindings)
			if err != nil {
				t.Fatalf("compile reference %q: %v", expression, err)
			}
			want := reference.Evaluate(&bodyNavigator{xmlquery.CreateXPathNavigator(p.root)})
			got, err := p.XPath(expression, bindings)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Errorf("%q: got %#v, %v; reference returned %#v", expression, got, err, want)
			}
		}
	}
}

func FuzzParsePlainResponse(f *testing.F) {
	for _, seed := range []string{wrap(`<m:Result>ok</m:Result>`), `not XML`, wrap(`<s:Fault/>`), wrap(`<m:Result><![CDATA[x]]></m:Result>`)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		parsed := Parse(200, body, "1.1", Limits{Bytes: 4096, Depth: 16, Nodes: 128, Attributes: 16})
		if parsed.OK && (parsed.Body == nil || parsed.Error != nil || parsed.Fault != nil) {
			t.Fatal("inconsistent success")
		}
		if parsed.Body == nil {
			if _, err := parsed.XPath(`//*`, nil); err == nil {
				t.Fatal("unaccepted content queried")
			}
		}
	})
}
func FuzzBodyXPath(f *testing.F) {
	for _, seed := range []string{`//m:Result`, `//*`, `name(//*)`, `//m:*`, `//*[`, `count(//Result)`, `1 and true()`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, expression string) {
		if len(expression) > 512 {
			return
		}
		p := Parse(200, wrap(`<m:Result>value</m:Result>`), "1.1", Limits{})
		_, _ = p.XPath(expression, map[string]string{"m": "urn:test"})
	})
}

func TestMalformedFaultStructure(t *testing.T) {
	for _, content := range []string{
		`<s:Fault><faultcode>s:Server</faultcode><faultcode>s:Client</faultcode><faultstring>bad</faultstring></s:Fault>`,
		`<x/><s:Fault><faultcode>s:Server</faultcode><faultstring>bad</faultstring></s:Fault>`,
	} {
		p := Parse(500, wrap(content), "1.1", Limits{})
		if p.Error == nil || p.Error.Code != "XML_INVALID" || p.Body != nil || p.Fault != nil {
			t.Fatalf("accepted malformed fault: %+v", p)
		}
	}
}

func TestMandatoryHeaderVersionMetadata(t *testing.T) {
	for _, ns := range []string{SOAP11, SOAP12} {
		version := "1.1"
		wrong := "role"
		if ns == SOAP12 {
			version = "1.2"
			wrong = "actor"
		}
		raw := `<s:Envelope xmlns:s="` + ns + `"><s:Header><h:Unknown xmlns:h="urn:h" s:mustUnderstand="1" s:` + wrong + `="urn:other"/></s:Header><s:Body/></s:Envelope>`
		got := Parse(200, raw, version, Limits{})
		if got.OK {
			t.Fatal("invalid role attribute bypassed targeted mandatory handling")
		}
	}
}
