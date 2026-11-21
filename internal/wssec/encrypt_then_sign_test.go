package wssec

import (
	"crypto/rand"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/knroy/go-xml/v2/c14n"
	"github.com/knroy/go-xmlsec/v2"
	"github.com/stanimirivanov/xk6-soap/internal/keys"
	"github.com/stanimirivanov/xk6-soap/internal/message"
)

func TestEncryptThenSignExchange(t *testing.T) {
	material := policyKeys(t)
	policy, err := CompilePolicy(SecurityOptions{
		Sign: &SigningPolicy{}, Encrypt: &EncryptionPolicy{}, Order: string(EncryptThenSign),
		Verify: &ReceiveOptions{Signature: boolp(true), RequireEncryption: boolp(true), Order: string(EncryptThenSign)},
	}, material, fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.RequireAvailable(); err != nil {
		t.Fatal(err)
	}
	wire, err := Protect(envelope("1.1"), identity(t), material.Recipient.Certificate(), fixedTime, EncryptThenSign, 128)
	if err != nil {
		t.Fatal(err)
	}
	result := ReceiveWithKeys(200, string(wire), "1.1", message.Limits{}, policy.Receive, material, fixedTime)
	if !result.OK || result.SigVerified == nil || !*result.SigVerified {
		t.Fatal(result.Error)
	}
}

func TestCiphertextSignatureGatesDecryption(t *testing.T) {
	material := policyKeys(t)
	receive, _ := receivePolicy(t)
	receive.RequireEncryption = true
	receive.Order = string(EncryptThenSign)
	outbound := material
	outbound.Decryption = nil
	policy, err := CompilePolicy(SecurityOptions{Sign: &SigningPolicy{}, Encrypt: &EncryptionPolicy{Target: "body"}, Order: string(EncryptThenSign)}, outbound, fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	raw := envelope("1.1")
	build := func(p Policy) string {
		t.Helper()
		wire, err := BuildSecurity(raw, p, outbound, fixedTime, rand.Reader, nil, message.Limits{})
		if err != nil {
			t.Fatal(err)
		}
		return string(wire)
	}
	wire := build(policy)
	ste := policy
	ste.Order = string(SignThenEncrypt)
	values := regexp.MustCompile(`<xenc:CipherValue>([^<]+)</xenc:CipherValue>`).FindAllStringSubmatch(wire, -1)
	if len(values) != 2 {
		t.Fatal("expected body and key ciphertext")
	}
	changed := func(value string) string {
		replacement := "A"
		if value[0] == 'A' {
			replacement = "B"
		}
		return strings.Replace(wire, value, replacement+value[1:], 1)
	}
	doc, ns, header, err := prepareSecurity(raw, identity(t), fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := encryptRequest(doc, ns, header, policy.Encrypt, outbound.Recipient.Certificate(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	doc, ns, err = parsed(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if err = signProbe(doc, ns, identity(t), []string{"body-1", "ts-1"}); err != nil {
		t.Fatal(err)
	}
	omittedKey, err := c14n.Bytes(signatureBeforeKey(doc.Root(), ns), c14n.Options{Algorithm: c14n.Inclusive10WithComments})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name  string
		wire  string
		calls int
	}{
		{"valid", wire, 1},
		{"wrapped key", changed(values[0][1]), 0},
		{"body ciphertext", changed(values[1][1]), 0},
		{"key omitted from valid signature", string(omittedKey), 0},
		{"wrong order", build(ste), 0},
	} {
		t.Run(row.name, func(t *testing.T) {
			calls := 0
			result := receiveWithDecryptor(200, row.wire, "1.1", message.Limits{}, receive, material, fixedTime,
				func(graph responseEncryption, doc *xmlsec.Document, key *keys.Material, now time.Time) ([]byte, string) {
					calls++
					return graph.decrypt(doc, key, now)
				})
			if calls != row.calls {
				t.Fatalf("decryption calls = %d, want %d", calls, row.calls)
			}
			if row.calls == 0 {
				assertHidden(t, result)
				if result.Error.Code != "SIGNATURE_INVALID" {
					t.Fatal(result.Error)
				}
			} else if !result.OK || result.Body == nil || !strings.Contains(*result.Body, "synthetic") {
				t.Fatal(result.Error)
			}
		})
	}
}
