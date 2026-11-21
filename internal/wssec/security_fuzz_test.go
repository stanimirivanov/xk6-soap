package wssec

import (
	"crypto/rand"
	"strings"
	"testing"

	"github.com/knroy/go-xml/v2/xdm"
	"github.com/knroy/go-xmlsec/v2/wss"
	"github.com/stanimirivanov/xk6-soap/internal/message"
)

var fuzzWireLimits = message.Limits{Bytes: 16 << 10, Depth: 24, Nodes: 1024, Attributes: 32}

func FuzzReceiveSecurity(f *testing.F) {
	material := policyKeys(f)
	outbound := material
	outbound.Decryption = nil
	for _, version := range []string{"1.1", "1.2"} {
		for _, order := range []ProtectionOrder{"", SignThenEncrypt, EncryptThenSign} {
			options := SecurityOptions{Sign: &SigningPolicy{}, Order: string(order)}
			if order != "" {
				options.Encrypt = &EncryptionPolicy{}
			}
			p, err := CompilePolicy(options, outbound, fixedTime)
			if err != nil {
				f.Fatal(err)
			}
			wire, err := BuildSecurity(envelope(version), p, outbound, fixedTime, rand.Reader, nil, fuzzWireLimits)
			if err != nil {
				f.Fatal(err)
			}
			plain := string(wire)
			f.Add(plain, version, string(order), order != "")
			f.Add(strings.Replace(plain, `URI="#body-1"`, `URI="https://example.invalid/PRIVATE_WIRE"`, 1), version, string(order), order != "")
			f.Add(strings.Replace(plain, `</s:Body>`, `<d xml:id="body-1">PRIVATE_WIRE</d></s:Body>`, 1), version, string(order), order != "")
		}
	}
	for _, order := range []ProtectionOrder{SignThenEncrypt, EncryptThenSign} {
		req, err := message.Build("Echo", `<Echo/>`, message.Options{Headers: []message.Header{{Name: "trace", XML: `<h:Trace xmlns:h="urn:trace">seed</h:Trace>`}}})
		if err != nil {
			f.Fatal(err)
		}
		p, err := CompilePolicy(SecurityOptions{Sign: &SigningPolicy{}, Encrypt: &EncryptionPolicy{Target: "headers", Headers: []string{"trace"}}, Order: string(order)}, outbound, fixedTime)
		if err != nil {
			f.Fatal(err)
		}
		wire, err := BuildSecurity([]byte(req.Body), p, outbound, fixedTime, rand.Reader, nil, fuzzWireLimits, req.HeaderSelectors...)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(string(wire), "1.1", string(order), false)
	}
	f.Add(`<!DOCTYPE Envelope SYSTEM "https://example.invalid/PRIVATE_WIRE"><Envelope/>`, "1.1", string(SignThenEncrypt), true)
	f.Fuzz(func(t *testing.T, raw, version, order string, requireBody bool) {
		if len(raw) > 32<<10 || len(version) > 3 || len(order) > 20 {
			return
		}
		policy := ReceivePolicy{Signature: true, Timestamp: true, Order: order, RequireEncryption: requireBody,
			SignatureAlgorithms: []string{"rsa-sha256"}, DigestAlgorithms: []string{"sha256"},
			ClockSkewSeconds: 60, MaxAgeSeconds: 300,
		}
		got := ReceiveWithKeys(200, raw, version, fuzzWireLimits, policy, material, fixedTime)
		if got.Error != nil && strings.Contains(got.Error.Error(), "PRIVATE_WIRE") {
			t.Fatal("reflected wire text")
		}
		if got.Body == nil {
			assertHidden(t, got)
		} else if got.SigVerified == nil || !*got.SigVerified || got.TimestampValid == nil || !*got.TimestampValid {
			t.Fatal("exposed content before signature and timestamp acceptance")
		}
		if got.SigVerified != nil && *got.SigVerified && strings.Contains(raw, `URI="https://example.invalid/PRIVATE_WIRE"`) {
			t.Fatal("external reference accepted")
		}
	})
}

func FuzzRecoveredXML(f *testing.F) {
	f.Add(string(envelope("1.1")))
	f.Add(`<!DOCTYPE s:Envelope SYSTEM "https://example.invalid/PRIVATE_RECOVERED"><s:Envelope/>`)
	f.Add(strings.Replace(string(envelope("1.1")), "<value>", `<value xml:id="probe"><d xml:id="probe"></d>`, 1))
	f.Add(strings.Replace(string(envelope("1.1")), "<value>", strings.Repeat("<d>", 40)+"<value>", 1))
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 32<<10 {
			return
		}
		doc, code := parseRecoveredSnapshot([]byte(raw), "1.1", fuzzWireLimits)
		if doc != nil {
			if code != "" || message.ValidateEnvelope(raw, "1.1", fuzzWireLimits) != nil ||
				wss.CheckUniqueIDs(doc.Root(), xdm.QName{Local: "Id"}) != nil {
				t.Fatal("recovered snapshot bypassed validation")
			}
		} else if code != "LIMIT_EXCEEDED" && code != "DECRYPTION_FAILED" {
			t.Fatal("unexpected recovered error code")
		}
	})
}

func TestRecoveredSnapshotResourceLimits(t *testing.T) {
	raw := envelope("1.1")
	for _, limits := range []message.Limits{
		{Bytes: len(raw) - 1},
		{Depth: 3},
		{Nodes: 8},
		{Attributes: 2},
	} {
		if doc, code := parseRecoveredSnapshot(raw, "1.1", limits); doc != nil || code != "LIMIT_EXCEEDED" {
			t.Fatalf("recovered XML escaped %+v: %s", limits, code)
		}
	}
}
