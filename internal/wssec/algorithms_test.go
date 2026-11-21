package wssec

import (
	"crypto/rand"
	"testing"

	"github.com/knroy/go-xmlsec/v2"
	"github.com/knroy/go-xmlsec/v2/wss"
	"github.com/stanimirivanov/xk6-soap/internal/message"
)

func TestExpandedSignaturePolicy(t *testing.T) {
	material := policyKeys(t)
	for _, row := range []struct {
		algorithm    string
		digest       string
		signatureURI string
		digestURI    string
	}{
		{"rsa-sha384", "sha512", xmlsec.SigRSASHA384, xmlsec.DigestSHA512},
		{"rsa-sha512", "sha384", xmlsec.SigRSASHA512, xmlsec.DigestSHA384},
	} {
		t.Run(row.algorithm, func(t *testing.T) {
			p, err := CompilePolicy(SecurityOptions{Sign: &SigningPolicy{Algorithm: row.algorithm, Digest: row.digest}, Verify: &ReceiveOptions{SignatureAlgorithms: []string{"rsa-sha256", row.algorithm}, DigestAlgorithms: []string{row.digest}}}, KeyMaterial{Signing: material.Signing, Trust: material.Trust}, fixedTime)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := BuildSecurity(envelope("1.1"), p, material.Signing, fixedTime, rand.Reader, nil, message.Limits{})
			if err != nil {
				t.Fatal(err)
			}
			doc, ns, err := parsed(wire)
			if err != nil {
				t.Fatal(err)
			}
			security, err := wss.FindHeader(doc.Root(), ns, "")
			if err != nil {
				t.Fatal(err)
			}
			info := security.FirstElement(xmlsec.NSDSig, "Signature").FirstElement(xmlsec.NSDSig, "SignedInfo")
			if info.FirstElement(xmlsec.NSDSig, "SignatureMethod").AttrValue("Algorithm") != row.signatureURI {
				t.Fatal("wrong signature identifier")
			}
			for ref := range info.Children() {
				if ref.IsElement(xmlsec.NSDSig, "Reference") && ref.FirstElement(xmlsec.NSDSig, "DigestMethod").AttrValue("Algorithm") != row.digestURI {
					t.Fatal("wrong digest identifier")
				}
			}
			verify := func(policy ReceivePolicy) *message.Parsed {
				return Receive(200, string(wire), "1.1", message.Limits{}, policy, material.Trust, fixedTime)
			}
			if got := verify(p.Receive); !got.OK || got.SigVerified == nil || !*got.SigVerified {
				t.Fatal(got.Error)
			}
			wrong := p.Receive
			wrong.SignatureAlgorithms = []string{"rsa-sha256"}
			assertHidden(t, verify(wrong))
			wrong = p.Receive
			wrong.DigestAlgorithms = []string{"sha256"}
			assertHidden(t, verify(wrong))
		})
	}
}
