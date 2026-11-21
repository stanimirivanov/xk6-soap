package wssec

import (
	"bytes"
	"strings"
	"testing"

	"github.com/knroy/go-xml/v2/c14n"
	"github.com/knroy/go-xml/v2/xdm"
	"github.com/knroy/go-xmlsec/v2"
	"github.com/knroy/go-xmlsec/v2/dsig"
	"github.com/knroy/go-xmlsec/v2/wss"
	"github.com/stanimirivanov/xk6-soap/internal/message"
)

func TestSignedSecurityCoverageAndSerialization(t *testing.T) {
	material := KeyMaterial{Signing: policyKeys(t).Signing}
	for _, version := range []string{"1.1", "1.2"} {
		for _, withToken := range []bool{false, true} {
			opts := SecurityOptions{Sign: &SigningPolicy{}, Verify: &ReceiveOptions{Signature: boolp(false)}}
			if withToken {
				opts.UsernameToken = &UsernameTokenPolicy{User: "synthetic-user", Password: "PRIVATE_PASSWORD"}
			}
			p, err := CompilePolicy(opts, material, fixedTime)
			if err != nil {
				t.Fatal(err)
			}
			build := func() []byte {
				t.Helper()
				wire, e := BuildSecurity(envelope(version), p, material.Signing, fixedTime, bytes.NewReader(make([]byte, 16)), nil, message.Limits{})
				if e != nil {
					t.Fatal(e)
				}
				return wire
			}
			wire := build()
			if !withToken {
				golden, e := Sign(envelope(version), identity(t), fixedTime)
				if e != nil || !bytes.Equal(wire, golden) {
					t.Fatal("public path diverged from deterministic accepted signature fixture", e)
				}
			}

			if !bytes.Equal(wire, build()) {
				t.Fatal("fixed RSA input was not deterministic")
			}
			doc, ns, err := parsed(wire)
			if err != nil {
				t.Fatal(err)
			}
			security, err := wss.FindHeader(doc.Root(), ns, "")
			if err != nil {
				t.Fatal(err)
			}
			signature := security.FirstElement(xmlsec.NSDSig, "Signature")
			coverage, err := dsig.Verify(doc.Root(), signature, dsig.VerifyOptions{
				Certificate: material.Signing.Certificate(), AllowedSignatureAlgorithms: []string{xmlsec.SigRSASHA256}, AllowedDigestAlgorithms: []string{xmlsec.DigestSHA256},
				AllowedCanonicalizationAlgorithms: []string{string(c14n.Exclusive10)}, MaxReferences: 3, StrictBSP: true, RequireExplicitCanonicalization: true, IDAttributes: []xdm.QName{dsig.IDAttrDSig},
			})
			if err != nil {
				t.Fatal("final wire digest verification", err)
			}
			required := []*xdm.Node{element(doc.Root()).FirstElement(ns, "Body"), security.FirstElement(xmlsec.NSWSU, "Timestamp")}
			if withToken {
				required = append(required, security.FirstElement(xmlsec.NSWSSE, "UsernameToken"))
			}
			if !coverage.CoversNodes(required...) {
				t.Fatal("actual nodes not covered")
			}
			for _, mutation := range []struct {
				old string
				new string
			}{{"synthetic</value>", "changed</value>"}, {"2030-01-02T03:04:05.000Z", "2030-01-02T03:04:06.000Z"}, {"synthetic-user", "tampered-user"}} {
				if !strings.Contains(string(wire), mutation.old) {
					if mutation.old == "synthetic-user" && !withToken {
						continue
					}
					t.Fatal("tamper target missing", mutation.old)
				}
				modified := bytes.Replace(wire, []byte(mutation.old), []byte(mutation.new), 1)
				changed, _, e := parsed(modified)
				if e != nil {
					t.Fatal(e)
				}
				sec, _ := wss.FindHeader(changed.Root(), ns, "")
				if _, e = dsig.Verify(changed.Root(), sec.FirstElement(xmlsec.NSDSig, "Signature"), dsig.VerifyOptions{Certificate: material.Signing.Certificate()}); e == nil {
					t.Fatal("covered mutation accepted")
				}
			}
			if out, e := BuildSecurity(envelope(version), p, material.Signing, fixedTime, bytes.NewReader(make([]byte, 16)), nil, message.Limits{Bytes: 2048}); e != ErrOutputLimit || out != nil {
				t.Fatal("signature exceeded wire budget", e)
			}
			if out, e := BuildSecurity(envelope(version), p, nil, fixedTime, nil, nil, message.Limits{}); e != ErrPolicyKey || out != nil {
				t.Fatal("missing key accepted", e)
			}
		}
	}
}

func TestSigningProfileActivation(t *testing.T) {
	material := KeyMaterial{Signing: policyKeys(t).Signing}
	for _, s := range []SigningPolicy{{}, {KeyID: "direct"}, {Algorithm: "rsa-sha384"}, {Digest: "sha384"}, {KeyID: "issuer-serial"}, {Headers: []string{"h"}}} {
		p, e := CompilePolicy(SecurityOptions{Sign: &s, Verify: &ReceiveOptions{Signature: boolp(false)}}, material, fixedTime)
		if e != nil {
			t.Fatal(e)
		}
		active := (s.KeyID == "" || s.KeyID == "direct")
		if (p.RequireAvailable() == nil) != active {
			t.Fatalf("wrong capability gate: %+v", s)
		}
	}
}

func TestSigningRejectsConflictingIDs(t *testing.T) {
	material := KeyMaterial{Signing: policyKeys(t).Signing}
	p, e := CompilePolicy(SecurityOptions{Sign: &SigningPolicy{}, UsernameToken: &UsernameTokenPolicy{User: "synthetic", Password: "synthetic"}, Verify: &ReceiveOptions{Signature: boolp(false)}}, material, fixedTime)
	if e != nil {
		t.Fatal(e)
	}
	for _, id := range []string{"body-1", "ts-1", "ut-1", "bst-1", "sig-1"} {
		raw := bytes.Replace(envelope("1.1"), []byte("<m:echo>"), []byte(`<m:echo xmlns:wsu="`+xmlsec.NSWSU+`" wsu:Id="`+id+`">`), 1)
		wire, e := BuildSecurity(raw, p, material.Signing, fixedTime, bytes.NewReader(make([]byte, 16)), nil, message.Limits{})
		if e == nil || wire != nil {
			t.Fatal("ambiguous generated ID emitted", id, e)
		}
	}
}

func TestSigningRejectsBodyIDDecoy(t *testing.T) {
	material := KeyMaterial{Signing: policyKeys(t).Signing}
	p, e := CompilePolicy(SecurityOptions{Sign: &SigningPolicy{}, Verify: &ReceiveOptions{Signature: boolp(false)}}, material, fixedTime)
	if e != nil {
		t.Fatal(e)
	}
	raw := bytes.Replace(envelope("1.1"), []byte("<s:Body>"), []byte(`<s:Body xmlns:wsu="`+xmlsec.NSWSU+`" wsu:Id="actual-body">`), 1)
	raw = bytes.Replace(raw, []byte("<m:echo>"), []byte(`<m:echo xmlns:wsu="`+xmlsec.NSWSU+`" wsu:Id="body-1">`), 1)
	if wire, e := BuildSecurity(raw, p, material.Signing, fixedTime, nil, nil, message.Limits{}); e == nil || wire != nil {
		t.Fatal("signed a decoy instead of the actual Body")
	}
}
