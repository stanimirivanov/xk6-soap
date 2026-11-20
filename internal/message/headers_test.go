package message

import (
	"strings"
	"testing"
)

func TestHeaderInputs(t *testing.T) {
	for _, version := range []string{"1.1", "1.2"} {
		opts := Options{Version: version, URL: "https://example.test/soap", Headers: []Header{{Name: "trace", XML: `<h:Trace xmlns:h="urn:trace">one</h:Trace>`}}, Addressing: &Addressing{Action: "urn:echo", To: "https://example.test/soap", MessageID: "urn:uuid:one", ReplyTo: AddressingNS + "/anonymous"}}
		got, err := Build("Echo", `<Echo/>`, opts)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(got.Body, `<s:Header>`) || !strings.Contains(got.Body, "MessageID") || len(got.HeaderSelectors) != 5 {
			t.Fatal("missing generated headers")
		}
		if !strings.Contains(got.Headers["Content-Type"]+got.Headers["SOAPAction"], "urn:echo") {
			t.Fatal("action not propagated")
		}
		for _, bad := range []Header{
			{Name: "trace", XML: `<Trace/>`},
			{Name: "bad:name", XML: `<h:T xmlns:h="urn:t"/>`},
			{Name: "trace", XML: `<h:T xmlns:h="urn:t" Id="injected"/>`},
			{Name: "trace", XML: `<h:T xmlns:h="urn:t"><s:Body xmlns:s="` + SOAP11 + `"/></h:T>`},
			{Name: "trace", XML: `<h:T xmlns:h="urn:t" xmlns:s="` + SOAP11 + `" s:mustUnderstand="true"/>`},
			{Name: "trace", XML: `<h:T xmlns:h="urn:t"/><h:T xmlns:h="urn:t"/>`},
		} {
			opts.Headers = []Header{bad}
			if _, err := Build("Echo", `<Echo/>`, opts); err == nil {
				t.Fatalf("accepted invalid header: %s", bad.Name)
			}
		}
	}
}

func TestHeaderSelectorsAndAddressingConsistency(t *testing.T) {
	valid := Header{Name: "trace", XML: `<h:T xmlns:h="urn:t"/>`}
	for _, headers := range [][]Header{{valid, valid}, {valid, {Name: "other", XML: valid.XML}}, {{Name: "wsaAction", XML: valid.XML}}} {
		_, err := Build("Echo", `<Echo/>`, Options{Headers: headers})
		if err == nil {
			t.Fatal("accepted collision")
		}
	}
	for _, address := range []Addressing{
		{Action: "relative", To: "https://example.test", MessageID: "urn:id", ReplyTo: "urn:reply"},
		{Action: "urn:a", To: "https://other.test", MessageID: "urn:id", ReplyTo: "urn:reply"},
		{Action: "urn:a", To: "https://example.test", MessageID: "urn:id", ReplyTo: ""},
	} {
		if _, err := Build("Echo", `<Echo/>`, Options{URL: "https://example.test", Addressing: &address}); err == nil {
			t.Fatal("accepted invalid addressing")
		}
	}
	_, err := Build("Echo", `<Echo/>`, Options{URL: "https://example.test", Action: "urn:b", Addressing: &Addressing{Action: "urn:a", To: "https://example.test", MessageID: "urn:id", ReplyTo: "urn:reply"}})
	if err == nil {
		t.Fatal("accepted inconsistent action")
	}
}

func TestHeaderVersionMetadataAndBudgets(t *testing.T) {
	for _, version := range []string{"1.1", "1.2"} {
		ns := SOAP11
		role := "actor"
		mu := "1"
		wrong := "role"
		if version == "1.2" {
			ns = SOAP12
			role = "role"
			mu = "true"
			wrong = "actor"
		}
		good := `<h:T xmlns:h="urn:t" xmlns:s="` + ns + `" s:` + role + `="urn:receiver" s:mustUnderstand="` + mu + `"/>`
		if _, err := Build("Echo", `<Echo/>`, Options{Version: version, Headers: []Header{{Name: "h", XML: good}}}); err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{strings.Replace(good, "s:"+role, "s:"+wrong, 1), strings.Replace(good, `="urn:receiver"`, `="relative"`, 1), strings.Replace(good, "s:mustUnderstand", "mustUnderstand", 1)} {
			if _, err := Build("Echo", `<Echo/>`, Options{Version: version, Headers: []Header{{Name: "h", XML: bad}}}); err == nil {
				t.Fatal("accepted invalid metadata")
			}
		}
	}
	for _, limits := range []Limits{{Bytes: 80}, {Nodes: 7}, {Depth: 2}, {Attributes: 1}} {
		_, err := Build("Echo", `<Echo/>`, Options{Limits: limits, Headers: []Header{{Name: "h", XML: `<h:T xmlns:h="urn:t" a="a"><h:Child/></h:T>`}}})
		if err == nil {
			t.Fatal("header bypassed budget")
		}
	}
	_, err := Build("Echo", `<Echo/>`, Options{URL: "https://example.test", ActionSet: true, Addressing: &Addressing{Action: "urn:a", To: "https://example.test", MessageID: "urn:id", ReplyTo: "urn:r"}})
	if err == nil {
		t.Fatal("explicit empty action mismatch accepted")
	}
}

func TestAddressingRejectsMalformedURIs(t *testing.T) {
	for index, bad := range []string{"relative", "urn:bad value", "urn:bad\nvalue", "urn:bad%xx", `urn:bad"value`, `urn:bad<value`, "urn:bad\\value"} {
		a := &Addressing{Action: "urn:a", To: "https://example.test", MessageID: bad, ReplyTo: "urn:reply"}
		if _, e := Build("Echo", `<Echo/>`, Options{URL: a.To, Addressing: a}); e == nil {
			t.Fatalf("accepted malformed addressing URI case %d", index)
		}
	}
}
