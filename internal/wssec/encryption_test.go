package wssec

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"strconv"
	"testing"

	"github.com/knroy/go-xml/v2/c14n"
	"github.com/knroy/go-xml/v2/xdm"
	"github.com/knroy/go-xmlsec/v2"
	"github.com/knroy/go-xmlsec/v2/dsig"
	"github.com/knroy/go-xmlsec/v2/wss"
	"github.com/knroy/go-xmlsec/v2/xenc"
)

func TestEncryptionOrders(t *testing.T) {
	for _, version := range []string{"1.1", "1.2"} {
		for _, order := range []ProtectionOrder{SignThenEncrypt, EncryptThenSign} {
			for _, bits := range []int{128, 256} {
				t.Run(version+"/"+string(order)+"/"+strconv.Itoa(bits), func(t *testing.T) {
					id := identity(t)
					wire, err := Protect(envelope(version), id, id.Certificate, fixedTime, order, bits)
					if err != nil {
						t.Fatal(err)
					}
					if bytes.Contains(wire, []byte(">synthetic<")) {
						t.Fatal("plaintext on wire")
					}
					if order == EncryptThenSign && bytes.Index(wire, []byte("<ds:Signature ")) > bytes.Index(wire, []byte("<xenc:EncryptedKey ")) {
						t.Fatal("ciphertext signature must precede key processing")
					}
					got, err := Open(wire, id.Certificate, id, fixedTime, order, bits)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Contains(got.Body, []byte("synthetic")) {
						t.Fatal("covered plaintext missing")
					}
					opposite := SignThenEncrypt
					if order == SignThenEncrypt {
						opposite = EncryptThenSign
					}
					if result, err := Open(wire, id.Certificate, id, fixedTime, opposite, bits); err == nil || result != nil {
						t.Fatal("wrong receive order accepted")
					}
				})
			}
		}
	}
}

// These failures must never publish even a partially recovered Body.
func TestEncryptionRejectsInvalidProtection(t *testing.T) {
	id := identity(t)
	for _, order := range []ProtectionOrder{SignThenEncrypt, EncryptThenSign} {
		t.Run(string(order), func(t *testing.T) {
			wire, err := Protect(envelope("1.1"), id, id.Certificate, fixedTime, order, 128)
			if err != nil {
				t.Fatal(err)
			}
			reject := func(t *testing.T, data []byte, recipient Identity, bits int) {
				t.Helper()
				got, err := Open(data, id.Certificate, recipient, fixedTime, order, bits)
				if err == nil || got != nil {
					t.Fatal("invalid protection published plaintext")
				}
			}
			mutations := map[string][]byte{
				"OAEP digest":       alterOAEPDigest(t, wire),
				"MGF":               bytes.Replace(wire, []byte(xmlsec.MGF1SHA256), []byte(xmlsec.MGF1SHA384), 1),
				"partial Body":      bytes.Replace(wire, []byte(`<xenc:EncryptedData`), []byte(`<plain>exposed</plain><xenc:EncryptedData`), 1),
				"unsupported graph": bytes.Replace(wire, []byte(`</s:Body>`), []byte(`<xenc:EncryptedData xmlns:xenc="`+xmlsec.NSXEnc+`"/></s:Body>`), 1),
				"external key":      bytes.Replace(wire, []byte(`URI="#ek-1"`), []byte(`URI="https://invalid.example/key"`), 1),
				"external data":     bytes.Replace(wire, []byte(`URI="#ed-1"`), []byte(`URI="https://invalid.example/data"`), 1),
				"wrong Type":        bytes.Replace(wire, []byte(xenc.TypeContent), []byte(xenc.TypeElement), 1),
				"tag":               tamperCipher(t, wire),
			}
			for name, data := range mutations {
				t.Run(name, func(t *testing.T) {
					if bytes.Equal(wire, data) {
						t.Fatal("mutation missed wire")
					}
					reject(t, data, id, 128)
				})
			}
			t.Run("wrong AES size", func(t *testing.T) { reject(t, wire, id, 256) })
			t.Run("wrong key", func(t *testing.T) {
				wrong, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatal(err)
				}
				cert := *id.Certificate
				cert.PublicKey = &wrong.PublicKey
				reject(t, wire, Identity{Certificate: &cert, Key: wrong}, 128)
			})
		})
	}
}

func tamperCipher(t *testing.T, wire []byte) []byte {
	t.Helper()
	// The final CipherValue is Body data, not the transported session key.
	start := bytes.LastIndex(wire, []byte(`<xenc:CipherValue>`)) + len(`<xenc:CipherValue>`)
	end := bytes.Index(wire[start:], []byte(`</xenc:CipherValue>`)) + start
	if start < len(`<xenc:CipherValue>`) || end < start {
		t.Fatal("ciphertext missing")
	}
	decoded, err := base64.StdEncoding.DecodeString(string(wire[start:end]))
	if err != nil {
		t.Fatal(err)
	}
	decoded[len(decoded)-1] ^= 1
	return bytes.Replace(wire, wire[start:end], []byte(base64.StdEncoding.EncodeToString(decoded)), 1)
}

func TestEncryptionRejectsRecoveredSecurityGraph(t *testing.T) {
	id := identity(t)
	for _, order := range []ProtectionOrder{SignThenEncrypt, EncryptThenSign} {
		raw := bytes.Replace(envelope("1.1"), []byte(`</m:echo>`), []byte(`<ds:Signature xmlns:ds="`+xmlsec.NSDSig+`"/></m:echo>`), 1)
		wire, err := Protect(raw, id, id.Certificate, fixedTime, order, 128)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := Open(wire, id.Certificate, id, fixedTime, order, 128); err == nil || got != nil {
			t.Fatalf("%s exposed unsupported recovered graph", order)
		}
	}
}

func TestEncryptionRecipientKeyUsage(t *testing.T) {
	id := identity(t)
	signingOnly := *id.Certificate
	signingOnly.KeyUsage = x509.KeyUsageDigitalSignature
	if wire, err := Protect(envelope("1.1"), id, &signingOnly, fixedTime, SignThenEncrypt, 128); err == nil || wire != nil {
		t.Fatal("signing-only recipient accepted")
	}
	encryptionOnly := *id.Certificate
	encryptionOnly.KeyUsage = x509.KeyUsageKeyEncipherment
	wire, err := Protect(envelope("1.1"), id, &encryptionOnly, fixedTime, SignThenEncrypt, 128)
	if err != nil {
		t.Fatal("encryption-capable recipient refused", err)
	}
	if _, err := Open(wire, id.Certificate, Identity{Certificate: &encryptionOnly, Key: id.Key}, fixedTime, SignThenEncrypt, 128); err != nil {
		t.Fatal(err)
	}
}

func TestEncryptThenSignRequiresExactKeyCoverage(t *testing.T) {
	id := identity(t)
	wire, err := Protect(envelope("1.1"), id, id.Certificate, fixedTime, EncryptThenSign, 128)
	if err != nil {
		t.Fatal(err)
	}
	doc, ns, err := parsed(wire)
	if err != nil {
		t.Fatal(err)
	}
	// Valid trusted math over Body, Timestamp and a ciphertext decoy. The
	// transported EncryptedKey is deliberately not one of the covered nodes.
	doc = xmlsec.NewDocument(xdm.CopyPruned(doc.Root(), func(n *xdm.Node) bool { return n.IsElement(xmlsec.NSDSig, "Signature") }))
	if err := signProbe(doc, ns, id, []string{"body-1", "ts-1", "ed-1"}); err != nil {
		t.Fatal(err)
	}
	sec, _ := wss.FindHeader(doc.Root(), ns, "")
	sig := sec.FirstElement(xmlsec.NSDSig, "Signature")
	if _, err := dsig.Verify(doc.Root(), sig, dsig.VerifyOptions{Certificate: id.Certificate, IDAttributes: []xdm.QName{dsig.IDAttrDSig}}); err != nil {
		t.Fatal("negative must retain valid signature math", err)
	}
	wire, err = c14n.Bytes(signatureBeforeKey(doc.Root(), ns), c14n.Options{Algorithm: c14n.Inclusive10WithComments})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := Open(wire, id.Certificate, id, fixedTime, EncryptThenSign, 128); err == nil || result != nil {
		t.Fatal("unsigned transported key accepted")
	}
}

func TestEncryptionRejectsKeyReferenceGraph(t *testing.T) {
	id := identity(t)
	wire, err := Protect(envelope("1.1"), id, id.Certificate, fixedTime, SignThenEncrypt, 128)
	if err != nil {
		t.Fatal(err)
	}
	wire = bytes.Replace(wire, []byte(`</xenc:ReferenceList>`), []byte(`<xenc:KeyReference URI="#ek-1"/></xenc:ReferenceList>`), 1)
	if result, err := Open(wire, id.Certificate, id, fixedTime, SignThenEncrypt, 128); err == nil || result != nil {
		t.Fatal("key-reference graph accepted")
	}
}

func alterOAEPDigest(t *testing.T, wire []byte) []byte {
	t.Helper()
	start := bytes.Index(wire, []byte("<xenc:EncryptedKey"))
	if start < 0 {
		t.Fatal("key missing")
	}
	out := append([]byte(nil), wire[:start]...)
	return append(out, bytes.Replace(wire[start:], []byte(xmlsec.DigestSHA256), []byte(xmlsec.DigestSHA384), 1)...)
}
