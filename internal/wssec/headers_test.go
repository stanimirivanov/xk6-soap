package wssec

import (
	"github.com/stanimirivanov/xk6-soap/internal/message"
	"strconv"
	"strings"
	"testing"
)

func TestHeaderSignatureCoverage(t *testing.T) {
	material := policyKeys(t)
	for _, version := range []string{"1.1", "1.2"} {
		p, e := CompilePolicy(SecurityOptions{Sign: &SigningPolicy{Headers: []string{"trace"}}, Verify: &ReceiveOptions{SignedHeaders: []ExpandedName{{Namespace: "urn:trace", LocalName: "Trace"}}}}, KeyMaterial{Signing: material.Signing, Trust: material.Trust}, fixedTime)
		if e != nil {
			t.Fatal(e)
		}
		if e = p.RequireAvailable(); e != nil {
			t.Fatal(e)
		}
		ns := message.SOAP11
		if version == "1.2" {
			ns = message.SOAP12
		}
		req, e := message.Build("Echo", `<Echo>synthetic</Echo>`, message.Options{Version: version, URL: "https://example.test", Headers: []message.Header{{Name: "trace", XML: `<h:Trace xmlns:h="urn:trace" xmlns:s="` + ns + `" s:mustUnderstand="1">original</h:Trace>`}}, Addressing: &message.Addressing{Action: "urn:echo", To: "https://example.test", MessageID: "urn:id", ReplyTo: "urn:reply"}})
		if e != nil {
			t.Fatal(e)
		}
		wire, e := BuildSecurity([]byte(req.Body), p, material, fixedTime, nil, nil, message.Limits{}, req.HeaderSelectors...)
		if e != nil {
			t.Fatal(e)
		}
		accepted := Receive(200, string(wire), version, message.Limits{}, p.Receive, material.Trust, fixedTime)
		if !accepted.OK {
			t.Fatal("signed headers rejected", accepted.Error)
		}
		for _, pair := range [][2]string{{"original", "changed"}, {"urn:echo", "urn:other"}, {"urn:id", "urn:other"}, {"urn:reply", "urn:other"}, {"https://example.test", "https://changed.test"}} {
			bad := strings.Replace(string(wire), pair[0], pair[1], 1)
			assertHidden(t, Receive(200, bad, version, message.Limits{}, p.Receive, material.Trust, fixedTime))
		}
		missing := p
		missing.Sign = &SigningPolicy{Headers: []string{"absent"}, Algorithm: p.Sign.Algorithm, Digest: p.Sign.Digest, Canonicalization: p.Sign.Canonicalization, KeyID: p.Sign.KeyID}
		if out, e := BuildSecurity([]byte(req.Body), missing, material, fixedTime, nil, nil, message.Limits{}, req.HeaderSelectors...); e == nil || out != nil {
			t.Fatal("missing selector accepted")
		}
		// A mathematically valid signature over Body/Timestamp cannot authenticate a header.
		unsigned := p
		unsigned.Sign = &SigningPolicy{Algorithm: p.Sign.Algorithm, Digest: p.Sign.Digest, Canonicalization: p.Sign.Canonicalization, KeyID: p.Sign.KeyID}
		noAddress, e := message.Build("Echo", `<Echo/>`, message.Options{Version: version, Headers: []message.Header{{Name: "trace", XML: `<h:Trace xmlns:h="urn:trace">original</h:Trace>`}}})
		if e != nil {
			t.Fatal(e)
		}
		weak, e := BuildSecurity([]byte(noAddress.Body), unsigned, material, fixedTime, nil, nil, message.Limits{}, noAddress.HeaderSelectors...)
		if e != nil {
			t.Fatal(e)
		}
		assertHidden(t, Receive(200, string(weak), version, message.Limits{}, p.Receive, material.Trust, fixedTime))
		ordinary, _ := receivePolicy(t)
		injected := strings.Replace(string(weak), "</s:Header>", `<wsa:Action xmlns:wsa="`+message.AddressingNS+`">urn:unsigned</wsa:Action></s:Header>`, 1)
		assertHidden(t, Receive(200, injected, version, message.Limits{}, ordinary, material.Trust, fixedTime))
		duplicate := strings.Replace(string(wire), "</s:Header>", `<h:Trace xmlns:h="urn:trace">decoy</h:Trace></s:Header>`, 1)
		assertHidden(t, Receive(200, duplicate, version, message.Limits{}, p.Receive, material.Trust, fixedTime))
		unknown := strings.Replace(string(wire), "</s:Header>", `<h:Unknown xmlns:h="urn:trace" s:mustUnderstand="1"/></s:Header>`, 1)
		assertHidden(t, Receive(200, unknown, version, message.Limits{}, p.Receive, material.Trust, fixedTime))
	}
}

func TestHeaderReferenceBudget(t *testing.T) {
	material := policyKeys(t)
	for _, count := range []int{14, 15} {
		var headers []message.Header
		var names []string
		for n := 0; n < count; n++ {
			name := "h" + strconv.Itoa(n)
			names = append(names, name)
			headers = append(headers, message.Header{Name: name, XML: `<h:` + name + ` xmlns:h="urn:budget"/>`})
		}
		p, e := CompilePolicy(SecurityOptions{Sign: &SigningPolicy{Headers: names}, Verify: &ReceiveOptions{Signature: boolp(false)}}, KeyMaterial{Signing: material.Signing}, fixedTime)
		if e != nil {
			t.Fatal(e)
		}
		req, e := message.Build("Echo", `<Echo/>`, message.Options{Headers: headers})
		if e != nil {
			t.Fatal(e)
		}
		wire, e := BuildSecurity([]byte(req.Body), p, material, fixedTime, nil, nil, message.Limits{}, req.HeaderSelectors...)
		if count == 14 {
			if e != nil || len(wire) == 0 {
				t.Fatal("16-reference boundary rejected", e)
			}
			receive, trust := receivePolicy(t)
			for _, h := range req.HeaderSelectors {
				receive.SignedHeaders = append(receive.SignedHeaders, ExpandedName{Namespace: h.Namespace, LocalName: h.LocalName})
			}
			if got := Receive(200, string(wire), "1.1", message.Limits{}, receive, trust, fixedTime); !got.OK {
				t.Fatal("16-reference receive rejected", got.Error)
			}
		} else if e == nil || wire != nil {
			t.Fatal("reference budget bypassed")
		}
	}
}
