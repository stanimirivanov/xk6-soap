package wssec

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/knroy/go-xmlsec/v2"
	"github.com/stanimirivanov/xk6-soap/internal/keys"
	"github.com/stanimirivanov/xk6-soap/internal/message"
)

func TestSignatureKeyIdentifiers(t *testing.T) {
	material := policyKeys(t)
	for _, row := range []struct {
		id     string
		marker string
	}{
		{"direct", "BinarySecurityToken"},
		{"issuer-serial", "X509IssuerSerial"},
		{"x509keyidentifier", "#X509v3"},
		{"ski", "#X509SubjectKeyIdentifier"},
		{"ThumbprintSHA1", "#ThumbprintSHA1"},
	} {
		t.Run(row.id, func(t *testing.T) {
			p, err := CompilePolicy(SecurityOptions{Sign: &SigningPolicy{KeyID: row.id}}, KeyMaterial{Signing: material.Signing, Trust: material.Trust}, fixedTime)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := BuildSecurity(envelope("1.1"), p, material, fixedTime, rand.Reader, nil, message.Limits{})
			if err != nil {
				t.Fatal(err)
			}
			raw := string(wire)
			if !strings.Contains(raw, row.marker) || (row.id != "direct" && strings.Contains(raw, ":BinarySecurityToken")) {
				t.Fatal("unexpected key identifier shape")
			}
			verify := func(raw string, trust KeyMaterial) *message.Parsed {
				return Receive(200, raw, "1.1", message.Limits{}, p.Receive, trust.Trust, fixedTime)
			}
			if got := verify(raw, material); !got.OK {
				t.Fatal(got.Error)
			}
			assertHidden(t, verify(raw, KeyMaterial{}))
			assertHidden(t, verify(strings.Replace(raw, row.marker, "unsupported", 1), material))
			if row.id == "ski" {
				ski := material.Signing.Certificate().SubjectKeyId
				original := base64.StdEncoding.EncodeToString(ski)
				ski[0] ^= 1
				forged := strings.Replace(raw, original, base64.StdEncoding.EncodeToString(ski), 1)
				if forged == raw {
					t.Fatal("fixture missing SKI")
				}
				assertHidden(t, verify(forged, material))
			}
			if row.id == "ThumbprintSHA1" {
				for _, alg := range [][2]string{{xmlsec.SigRSASHA256, xmlsec.SigRSASHA1}, {xmlsec.DigestSHA256, xmlsec.DigestSHA1}} {
					got := verify(strings.Replace(raw, alg[0], alg[1], 1), material)
					assertHidden(t, got)
					if got.Error.Code != "POLICY_VIOLATION" {
						t.Fatal(got.Error)
					}
				}
			}
		})
	}
}

func TestSignatureIdentifierRequiresUniquePinnedLeaf(t *testing.T) {
	material := policyKeys(t)
	signer := identity(t)
	// A reissued leaf can share both identifiers and the public key while
	// differing in DER. Neither XMLDSig math nor key compatibility disambiguates it.
	template := *signer.Certificate
	template.NotAfter = template.NotAfter.Add(-time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &signer.Key.PublicKey, signer.Key)
	if err != nil {
		t.Fatal(err)
	}
	alternate, err := keys.NewCache().Load(keys.Input{Cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, keys.Trust, fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	if alternate.Certificate().Equal(signer.Certificate) {
		t.Fatal("fixture certificates must differ")
	}
	for _, id := range []string{"issuer-serial", "ski", "direct", "x509keyidentifier", "ThumbprintSHA1"} {
		t.Run(id, func(t *testing.T) {
			p, err := CompilePolicy(SecurityOptions{Sign: &SigningPolicy{KeyID: id}}, KeyMaterial{Signing: material.Signing, Trust: material.Trust}, fixedTime)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := BuildSecurity(envelope("1.1"), p, material, fixedTime, rand.Reader, nil, message.Limits{})
			if err != nil {
				t.Fatal(err)
			}
			both := append([]*keys.Material{alternate}, material.Trust...)
			got := Receive(200, string(wire), "1.1", message.Limits{}, p.Receive, both, fixedTime)
			if id == "ski" || id == "issuer-serial" {
				assertHidden(t, got)
				if got.Error.Code != "SIGNATURE_INVALID" {
					t.Fatal(got.Error)
				}
			} else if !got.OK {
				t.Fatal(got.Error)
			}
		})
	}
}
