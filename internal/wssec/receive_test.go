package wssec

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stanimirivanov/xk6-soap/internal/keys"
	"github.com/stanimirivanov/xk6-soap/internal/message"
)

func receivePolicy(t *testing.T) (ReceivePolicy, []*keys.Material) {
	t.Helper()
	m := policyKeys(t)
	p, e := CompilePolicy(SecurityOptions{Verify: &ReceiveOptions{Signature: boolp(true)}}, KeyMaterial{Trust: m.Trust}, fixedTime)
	if e != nil {
		t.Fatal(e)
	}
	return p.Receive, m.Trust
}
func assertHidden(t *testing.T, p *message.Parsed) {
	t.Helper()
	if p.OK || p.Body != nil || p.Fault != nil || p.Error == nil {
		t.Fatal("failed acceptance exposed content", p)
	}
	if v, e := p.XPath("string(.)", nil); v != nil || e == nil || e.(*message.Error).Code != "CONTENT_UNAVAILABLE" {
		t.Fatal("unaccepted XPath available", v, e)
	}
}
func TestReceiveCoverageTrustAndWithholding(t *testing.T) {
	policy, trust := receivePolicy(t)
	for _, version := range []string{"1.1", "1.2"} {
		wire, e := Sign(envelope(version), identity(t), fixedTime, "q")
		if e != nil {
			t.Fatal(e)
		}
		p := Receive(200, string(wire), version, message.Limits{}, policy, trust, fixedTime)
		if !p.OK || p.SigVerified == nil || !*p.SigVerified || p.TimestampValid == nil || !*p.TimestampValid {
			t.Fatal("valid signed response", p.Error)
		}
		if v, e := p.XPath("string(m:echo/kind)", map[string]string{"m": "urn:xk6-soap:fixture"}); e != nil || v != "q:Thing" {
			t.Fatal("accepted Body projection", v, e)
		}
		if !strings.Contains(*p.Body, "urn:qualified-value") {
			t.Fatal("verified inclusive namespace lost")
		}
		for _, bad := range [][]byte{
			bytes.Replace(wire, []byte("synthetic"), []byte("PRIVATE_TAMPERED"), 1),
			bytes.Replace(wire, []byte("2030-01-02T03:04:05.000Z"), []byte("2030-01-02T03:04:06.000Z"), 1),
			bytes.Replace(wire, []byte("</s:Body>"), []byte(`<x xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="body-1"/></s:Body>`), 1),
			envelope(version),
		} {
			p = Receive(500, string(bad), version, message.Limits{}, policy, trust, fixedTime)
			assertHidden(t, p)
			if strings.Contains(p.Error.Error(), "PRIVATE") {
				t.Fatal("error reflected XML")
			}
		}
	}
	for _, mode := range []string{"body-only", "timestamp-only", "decoy"} {
		p := Receive(200, string(signAdversarial(t, identity(t), mode)), "1.1", message.Limits{}, policy, trust, fixedTime)
		assertHidden(t, p)
	}
	wire, _ := Sign(envelope("1.1"), identity(t), fixedTime)
	assertHidden(t, Receive(200, string(wire), "1.1", message.Limits{}, policy, nil, fixedTime))
	assertHidden(t, Receive(200, string(wire), "1.2", message.Limits{}, policy, trust, fixedTime))
	assertHidden(t, Receive(200, string(wire), "1.1", message.Limits{Bytes: 256}, policy, trust, fixedTime))
}

func TestReceiveExactDERAndOverlappingPins(t *testing.T) {
	policy, trust := receivePolicy(t)
	id := identity(t)
	template := *id.Certificate
	template.SerialNumber = big.NewInt(999)
	der, e := x509.CreateCertificate(rand.Reader, &template, &template, &id.Key.PublicKey, id.Key)
	if e != nil {
		t.Fatal(e)
	}
	alternate, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	wire, e := Sign(envelope("1.1"), Identity{Certificate: alternate, Key: id.Key}, fixedTime)
	if e != nil {
		t.Fatal(e)
	}
	assertHidden(t, Receive(200, string(wire), "1.1", message.Limits{}, policy, trust, fixedTime))
	pin, e := keys.NewCache().Load(keys.Input{Cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, keys.Trust, fixedTime)
	if e != nil {
		t.Fatal(e)
	}
	p := Receive(200, string(wire), "1.1", message.Limits{}, policy, append(trust, pin), fixedTime)
	if !p.OK {
		t.Fatal("overlapping exact pins failed", p.Error)
	}
}

func TestReceiveSignedFaultAndSkippedSignature(t *testing.T) {
	policy, trust := receivePolicy(t)
	raw := bytes.Replace(envelope("1.1"), []byte(`<m:echo><value>synthetic</value><kind>q:Thing</kind></m:echo>`), []byte(`<s:Fault><faultcode>s:Server</faultcode><faultstring>PRIVATE_FAULT</faultstring></s:Fault>`), 1)
	wire, e := Sign(raw, identity(t), fixedTime)
	if e != nil {
		t.Fatal(e)
	}
	p := Receive(500, string(wire), "1.1", message.Limits{}, policy, trust, fixedTime)
	if p.OK || p.Error == nil || p.Error.Code != "SOAP_FAULT" || p.Fault == nil || p.SigVerified == nil || !*p.SigVerified {
		t.Fatal("signed fault rejected", p.Error)
	}
	bad := bytes.Replace(wire, []byte("PRIVATE_FAULT"), []byte("UNAUTHENTICATED"), 1)
	assertHidden(t, Receive(500, string(bad), "1.1", message.Limits{}, policy, trust, fixedTime))
	policy.Signature = false
	policy.Timestamp = false
	p = Receive(500, string(bad), "1.1", message.Limits{}, policy, nil, fixedTime)
	if p.Fault == nil || p.SigVerified != nil || p.TimestampValid != nil {
		t.Fatal("explicit skip claimed authenticity", p.Error)
	}
	// Skipping authentication still cannot execute out-of-profile algorithms.
	bad = bytes.Replace(bad, []byte("rsa-sha256"), []byte("rsa-sha1"), 1)
	assertHidden(t, Receive(500, string(bad), "1.1", message.Limits{}, policy, nil, fixedTime))
}

func TestSkippedReceiveRejectsUnsupportedKeyInfo(t *testing.T) {
	policy, trust := receivePolicy(t)
	policy.Signature = false
	policy.Timestamp = false
	wire, e := Sign(envelope("1.1"), identity(t), fixedTime)
	if e != nil {
		t.Fatal(e)
	}
	// Skip means no cryptographic authentication, not executing arbitrary key resolvers.
	wire = bytes.Replace(wire, []byte(`URI="#bst-1"`), []byte(`URI="https://PRIVATE.invalid/cert"`), 1)
	assertHidden(t, Receive(200, string(wire), "1.1", message.Limits{}, policy, trust, fixedTime))
}

func TestReceiveRejectsCrossVersionSecurityRoleAndSkippedC14N(t *testing.T) {
	policy, trust := receivePolicy(t)
	wire, e := Sign(envelope("1.1"), identity(t), fixedTime)
	if e != nil {
		t.Fatal(e)
	}
	wrongRole := bytes.Replace(wire, []byte(`s:mustUnderstand="1"`), []byte(`s:mustUnderstand="1" s:actor="http://www.w3.org/2003/05/soap-envelope/role/ultimateReceiver"`), 1)
	assertHidden(t, Receive(200, string(wrongRole), "1.1", message.Limits{}, policy, trust, fixedTime))
	policy.Signature = false
	policy.Timestamp = false
	badC14N := bytes.Replace(wire, []byte(`<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"`), []byte(`<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"`), 1)
	assertHidden(t, Receive(200, string(badC14N), "1.1", message.Limits{}, policy, trust, fixedTime))
}

func TestReceiveTimestampSkipAndCanonicalBudget(t *testing.T) {
	policy, trust := receivePolicy(t)
	policy.Timestamp = false
	wire, e := Sign(envelope("1.1"), identity(t), fixedTime)
	if e != nil {
		t.Fatal(e)
	}
	p := Receive(200, string(wire), "1.1", message.Limits{}, policy, trust, fixedTime.Add(24*time.Hour))
	if !p.OK || p.SigVerified == nil || !*p.SigVerified || p.TimestampValid != nil {
		t.Fatal("explicit freshness skip failed", p.Error)
	}
	// The wire stays small because one ancestor binds the large namespace. Each
	// sibling renders it again under exclusive canonicalization of the Body.
	raw := []byte(`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:m="urn:` + strings.Repeat("x", 1000) + `"><s:Body>` + strings.Repeat(`<m:x/>`, 30) + `</s:Body></s:Envelope>`)
	wire, e = Sign(raw, identity(t), fixedTime)
	if e != nil {
		t.Fatal(e)
	}
	if len(wire) > 10000 {
		t.Fatal("expansion fixture is not a small wire message")
	}
	p = Receive(200, string(wire), "1.1", message.Limits{Bytes: 10000}, policy, trust, fixedTime)
	assertHidden(t, p)
	if p.Error.Code != "LIMIT_EXCEEDED" || p.SigVerified == nil || *p.SigVerified {
		t.Fatal("canonical expansion was not rejected before verification", p.Error)
	}
}

func TestSkippedReceiveRejectsDuplicateKeyInfo(t *testing.T) {
	policy, trust := receivePolicy(t)
	policy.Signature = false
	policy.Timestamp = false
	wire, e := Sign(envelope("1.1"), identity(t), fixedTime)
	if e != nil {
		t.Fatal(e)
	}
	wire = bytes.Replace(wire, []byte(`</ds:Signature>`), []byte(`<ds:KeyInfo/></ds:Signature>`), 1)
	assertHidden(t, Receive(200, string(wire), "1.1", message.Limits{}, policy, trust, fixedTime))
}
