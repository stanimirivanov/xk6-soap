package message

import (
	"reflect"
	"strings"
	"testing"
)

func TestSOAP12FaultProjection(t *testing.T) {
	const namespaces = `xmlns:s="` + SOAP12 + `" xmlns:m="urn:test"`
	const sender = `<s:Value>s:Sender</s:Value>`
	const codeField = `<s:Code>` + sender + `</s:Code>`
	const reasonText = `<s:Text xml:lang="en">Fault</s:Text>`
	const reasonField = `<s:Reason>` + reasonText + `</s:Reason>`
	withFault := func(fields string) string {
		return `<s:Body ` + namespaces + `><s:Fault>` + fields + `</s:Fault></s:Body>`
	}
	for _, entry := range []struct {
		name  string
		parse func(int, string) *Parsed
	}{
		{"plain", func(status int, body string) *Parsed {
			return Parse(status, `<s:Envelope xmlns:s="`+SOAP12+`">`+body+`</s:Envelope>`, "1.2", Limits{})
		}},
		{"accepted-body", func(status int, body string) *Parsed {
			return ParseAcceptedBody(status, body, "1.2", Limits{})
		}},
	} {
		t.Run(entry.name, func(t *testing.T) {
			for _, tc := range []struct {
				name   string
				fields string
			}{
				{"missing Code", reasonField},
				{"missing Reason", codeField},
				{"Reason before Code", reasonField + codeField},
				{"Role before Node", codeField + reasonField + `<s:Role>urn:role</s:Role><s:Node>urn:node</s:Node>`},
				{"duplicate Code Value", `<s:Code>` + sender + sender + `</s:Code>` + reasonField},
				{"duplicate nested Subcode Value", `<s:Code>` + sender + `<s:Subcode><s:Value>m:First</s:Value><s:Subcode><s:Value>m:Second</s:Value><s:Value>m:Third</s:Value></s:Subcode></s:Subcode></s:Code>` + reasonField},
				{"Subcode before Value", `<s:Code><s:Subcode><s:Value>m:First</s:Value></s:Subcode>` + sender + `</s:Code>` + reasonField},
				{"nested element in Value", `<s:Code><s:Value><m:value>s:Sender</m:value></s:Value></s:Code>` + reasonField},
				{"foreign Reason child", codeField + `<s:Reason>` + reasonText + `<m:Text xml:lang="en">Other</m:Text></s:Reason>`},
				{"character data in Reason", codeField + `<s:Reason>` + reasonText + `<![CDATA[unexpected]]></s:Reason>`},
				{"nested element in Reason Text", codeField + `<s:Reason><s:Text xml:lang="en"><m:text>Fault</m:text></s:Text></s:Reason>`},
				{"missing language", codeField + `<s:Reason><s:Text>Fault</s:Text></s:Reason>`},
				{"nested element in Node", codeField + reasonField + `<s:Node><m:id>urn:node</m:id></s:Node>`},
			} {
				t.Run(tc.name, func(t *testing.T) {
					p := entry.parse(500, withFault(tc.fields))
					code(t, p.Error, "XML_INVALID")
					if p.OK || p.Status != 500 || p.Body != nil || p.Fault != nil {
						t.Fatalf("unexpected rejection result: %+v", p)
					}
					value, err := p.XPath(".", nil)
					code(t, err, "CONTENT_UNAVAILABLE")
					if value != nil {
						t.Fatalf("rejected content available to XPath: %#v", value)
					}
				})
			}
			const valid = `<s:Code>` + sender + `<s:Subcode><s:Value>m:First</s:Value><s:Subcode><s:Value>m:Second</s:Value></s:Subcode></s:Subcode></s:Code>
				<!-- formatting is allowed --><s:Reason>
					<s:Text xml:lang="fr">Échec</s:Text><s:Text xml:lang="en"><![CDATA[Fault]]></s:Text><s:Text xml:lang="en">Other</s:Text>
				</s:Reason><s:Node>urn:node</s:Node><s:Role>urn:role</s:Role><s:Detail><m:data>detail</m:data></s:Detail>`
			for _, status := range []int{200, 500} {
				p := entry.parse(status, withFault(valid))
				code(t, p.Error, "SOAP_FAULT")
				wantSubcodes := []any{
					map[string]any{"namespace": "urn:test", "localName": "First"},
					map[string]any{"namespace": "urn:test", "localName": "Second"},
				}
				wantReasons := []any{
					map[string]any{"lang": "fr", "text": "Échec"},
					map[string]any{"lang": "en", "text": "Fault"},
					map[string]any{"lang": "en", "text": "Other"},
				}
				detail, _ := p.Fault["detail"].(string)
				if p.OK || p.Status != status || p.Body == nil || p.Fault["reason"] != "Fault" ||
					p.Fault["node"] != "urn:node" || p.Fault["role"] != "urn:role" || !strings.Contains(detail, "detail</m:data>") ||
					!reflect.DeepEqual(p.Fault["code"], map[string]any{"namespace": SOAP12, "localName": "Sender"}) ||
					!reflect.DeepEqual(p.Fault["subcodes"], wantSubcodes) || !reflect.DeepEqual(p.Fault["reasons"], wantReasons) {
					t.Fatalf("HTTP %d unexpected accepted Fault: %+v", status, p)
				}
				value, err := p.XPath("string(//m:data)", map[string]string{"m": "urn:test"})
				if err != nil || value != "detail" {
					t.Fatalf("HTTP %d accepted Fault XPath: %#v, %v", status, value, err)
				}
			}
		})
	}
}
