package wssec

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/knroy/go-xmlsec/v2"
	"github.com/stanimirivanov/xk6-soap/internal/keys"
	"github.com/stanimirivanov/xk6-soap/internal/message"
)

func TestEncryptedHeaderPolicy(t *testing.T) {
	material := policyKeys(t)
	for _, order := range []string{string(SignThenEncrypt), string(EncryptThenSign)} {
		t.Run(order, func(t *testing.T) {
			p, err := CompilePolicy(SecurityOptions{Sign: &SigningPolicy{}, Encrypt: &EncryptionPolicy{Target: "headers", Headers: []string{"trace"}}, Order: order, Verify: &ReceiveOptions{Order: order, EncryptedHeaders: []ExpandedName{{Namespace: "urn:trace", LocalName: "Trace"}}}}, material, fixedTime)
			if err != nil {
				t.Fatal(err)
			}
			if err := p.RequireAvailable(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEncryptRecoverSelectedHeaderBlocks(t *testing.T) {
	material := policyKeys(t)
	trace := ExpandedName{Namespace: "urn:trace", LocalName: "Trace"}
	context := ExpandedName{Namespace: "urn:trace", LocalName: "Context"}
	for _, version := range []string{"1.1", "1.2"} {
		ns := message.SOAP11
		attribute := "actor"
		if version == "1.2" {
			ns = message.SOAP12
			attribute = "role"
		}
		request, err := message.Build("Echo", `<Echo>visible-body</Echo>`, message.Options{Version: version, Headers: []message.Header{
			{Name: "trace", XML: `<h:Trace xmlns:h="urn:trace" xmlns:s="` + ns + `" s:` + attribute + `="urn:other-actor">hidden-trace</h:Trace>`},
			{Name: "clear", XML: `<h:Clear xmlns:h="urn:trace">visible-header</h:Clear>`},
			{Name: "ctx", XML: `<h:Context xmlns:h="urn:trace">hidden-context</h:Context>`},
		}})
		if err != nil {
			t.Fatal(err)
		}
		for _, order := range []ProtectionOrder{SignThenEncrypt, EncryptThenSign} {
			t.Run(version+"/"+string(order), func(t *testing.T) {
				options := SecurityOptions{
					Sign:    &SigningPolicy{Headers: []string{"trace", "clear"}},
					Encrypt: &EncryptionPolicy{Target: "headers", Headers: []string{"ctx", "trace"}},
					Order:   string(order),
					Verify:  &ReceiveOptions{Order: string(order), SignedHeaders: []ExpandedName{trace, {Namespace: "urn:trace", LocalName: "Clear"}}, EncryptedHeaders: []ExpandedName{trace, context}},
				}
				p, e := CompilePolicy(options, material, fixedTime)
				if e != nil {
					t.Fatal(e)
				}
				wire, e := BuildSecurity([]byte(request.Body), p, material, fixedTime, rand.Reader, nil, message.Limits{}, request.HeaderSelectors...)
				if e != nil {
					t.Fatal(e)
				}
				for _, v := range []string{"hidden-trace", "hidden-context", "urn:other-actor"} {
					if bytes.Contains(wire, []byte(v)) {
						t.Fatal("selected plaintext leaked")
					}
				}
				for _, v := range []string{"visible-body", "visible-header"} {
					if !bytes.Contains(wire, []byte(v)) {
						t.Fatal("clear sibling lost")
					}
				}
				parsed, actualNS, e := parsed(wire)
				if e != nil {
					t.Fatal(e)
				}
				graph, ok := inspectResponseEncryption(parsed, actualNS)
				if !ok || len(graph.headerSlots) != 2 || graph.data != nil {
					t.Fatal("wrong encryption graph")
				}
				wrapper := headerBlocks(parsed, actualNS)[graph.headerSlots[0]]
				data := wrapper.FirstElement(xmlsec.NSXEnc, "EncryptedData")
				value := data.FirstElement(xmlsec.NSXEnc, "CipherData").FirstElement(xmlsec.NSXEnc, "CipherValue").StringValue()
				replacement := "A"
				if value[0] == 'A' {
					replacement = "B"
				}
				tampered := strings.Replace(string(wire), value, replacement+value[1:], 1)
				calls := 0
				rejected := receiveWithDecryptor(200, tampered, version, message.Limits{}, p.Receive, material, fixedTime,
					func(g responseEncryption, doc *xmlsec.Document, k *keys.Material, now time.Time) ([]byte, string) {
						calls++
						return g.decrypt(doc, k, now)
					})
				assertHidden(t, rejected)
				if order == EncryptThenSign && (calls != 0 || rejected.Error.Code != "SIGNATURE_INVALID") {
					t.Fatal("tampered wrapper reached decryption", rejected.Error)
				}
				if order == SignThenEncrypt && (calls != 1 || rejected.Error.Code != "DECRYPTION_FAILED") {
					t.Fatal("tampered header passed decryption", rejected.Error)
				}
				graph.version = version
				recovered, code := graph.decrypt(parsed, material.Decryption, fixedTime)
				if code != "" {
					t.Fatal(code)
				}
				restored, code := parseRecoveredSnapshot(recovered, version, message.Limits{})
				if code != "" {
					t.Fatal(code)
				}
				blocks := headerBlocks(restored, actualNS)
				if !blocks[0].IsElement(trace.Namespace, trace.LocalName) || blocks[0].Attr(actualNS, attribute).Value() != "urn:other-actor" ||
					!blocks[1].IsElement("urn:trace", "Clear") || !blocks[2].IsElement(context.Namespace, context.LocalName) {
					t.Fatal("header order, names or original SOAP metadata lost")
				}
				valid := ReceiveWithKeys(200, string(wire), version, message.Limits{}, p.Receive, material, fixedTime)
				if !valid.OK || valid.SigVerified == nil || !*valid.SigVerified || !strings.Contains(*valid.Body, "visible-body") {
					t.Fatal(valid.Error)
				}

				if _, err := BuildSecurity([]byte(request.Body), p, material, fixedTime, rand.Reader, nil, message.Limits{}, request.HeaderSelectors[:2]...); err != ErrEncryptionBuild {
					t.Fatal("missing encryption selector", err)
				}
				duplicate := strings.Replace(string(wire), "</s:Header>", `<h:Trace xmlns:h="urn:trace">clear copy</h:Trace></s:Header>`, 1)
				assertHidden(t, ReceiveWithKeys(200, duplicate, version, message.Limits{}, p.Receive, material, fixedTime))
				conflict := append([]message.HeaderSelector{}, request.HeaderSelectors...)
				conflict = append(conflict, request.HeaderSelectors[0])
				if _, err := BuildSecurity([]byte(request.Body), p, material, fixedTime, rand.Reader, nil, message.Limits{}, conflict...); err != ErrEncryptionBuild {
					t.Fatal("ambiguous encryption selector", err)
				}
				required := p.Receive
				required.RequireEncryption = true
				assertHidden(t, ReceiveWithKeys(200, string(wire), version, message.Limits{}, required, material, fixedTime))
				required = p.Receive
				required.EncryptedHeaders = []ExpandedName{{Namespace: "urn:trace", LocalName: "Clear"}}
				assertHidden(t, ReceiveWithKeys(200, string(wire), version, message.Limits{}, required, material, fixedTime))

				wrongRole := strings.Replace(string(wire), "<wsse11:EncryptedHeader", "<wsse11:EncryptedHeader s:"+attribute+`="urn:wrong"`, 1)
				if wrongRole == string(wire) {
					t.Fatal("wrapper fixture did not match")
				}
				result := ReceiveWithKeys(200, wrongRole, version, message.Limits{}, p.Receive, material, fixedTime)
				assertHidden(t, result)
				if result.Error.Code != "POLICY_VIOLATION" {
					t.Fatal(result.Error)
				}
			})
		}
	}
}
