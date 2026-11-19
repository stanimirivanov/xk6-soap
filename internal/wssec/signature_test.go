package wssec

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"github.com/knroy/go-xml/v2/c14n"
	"github.com/knroy/go-xmlsec/v2"
	"github.com/knroy/go-xmlsec/v2/dsig"
	"github.com/knroy/go-xmlsec/v2/wss"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

var fixedTime = time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)

func identity(t *testing.T) Identity {
	t.Helper()
	certPEM, err := os.ReadFile("testdata/signing-cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile("testdata/signing-key.pem")
	if err != nil {
		t.Fatal(err)
	}
	certBlock, _ := pem.Decode(certPEM)
	keyBlock, _ := pem.Decode(keyPEM)
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return Identity{Certificate: cert, Key: key.(*rsa.PrivateKey)}
}
func envelope(version string) []byte {
	ns := "http://schemas.xmlsoap.org/soap/envelope/"
	if version == "1.2" {
		ns = "http://www.w3.org/2003/05/soap-envelope"
	}
	return []byte(`<s:Envelope xmlns:s="` + ns + `" xmlns:m="urn:xk6-soap:fixture" xmlns:q="urn:qualified-value"><s:Body><m:echo><value>synthetic</value><kind>q:Thing</kind></m:echo></s:Body></s:Envelope>`)
}
func TestSignVerifyCoverage(t *testing.T) {
	key := identity(t)
	for _, version := range []string{"1.1", "1.2"} {
		wire, err := Sign(envelope(version), key, fixedTime)
		if err != nil {
			t.Fatal(err)
		}
		verified, err := Verify(wire, key.Certificate, fixedTime)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(verified.Body, []byte("synthetic")) || !verified.Created.Equal(fixedTime) || !verified.Expires.Equal(fixedTime.Add(5*time.Minute)) {
			t.Fatalf("consumed content differs: %+v", verified)
		}
		again, err := Sign(envelope(version), key, fixedTime)
		if err != nil || !bytes.Equal(wire, again) {
			t.Fatalf("unstable serialization: %v", err)
		}
		for _, bad := range [][]byte{
			bytes.Replace(wire, []byte("synthetic"), []byte("tampered"), 1),
			bytes.Replace(wire, []byte(`URI="#body-1"`), []byte(`URI="https://example.test/SECRET"`), 1),
			bytes.Replace(wire, []byte(`</s:Body>`), []byte(`<m:duplicate xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="body-1"/></s:Body>`), 1),
		} {
			if _, err := Verify(bad, key.Certificate, fixedTime); err == nil || strings.Contains(err.Error(), "SECRET") {
				t.Fatalf("bad input accepted or reflected: %v", err)
			}
		}
		if _, err := Verify(wire, nil, fixedTime); err == nil {
			t.Fatal("nil trust accepted")
		}
	}
}
func TestMissingAndDecoyCoverage(t *testing.T) {
	key := identity(t)
	// These inputs are correctly signed by the trusted identity, but target the
	// wrong nodes. The adapter must reject them despite valid signature math.
	for _, mode := range []string{"body-only", "timestamp-only", "decoy"} {
		wire := signAdversarial(t, key, mode)
		_, err := Verify(wire, key.Certificate, fixedTime)
		if err == nil {
			t.Fatalf("accepted %s", mode)
		}
		if mode == "decoy" && !errors.Is(err, ErrCoverage) {
			t.Fatalf("decoy signature should pass cryptography then fail exact-node coverage: %v", err)
		}
	}
}

func signAdversarial(t *testing.T, key Identity, mode string) []byte {
	t.Helper()
	raw := envelope("1.1")
	if mode == "decoy" {
		raw = bytes.Replace(raw, []byte("<s:Body>"), []byte(`<s:Header><m:decoy xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="decoy"/></s:Header><s:Body>`), 1)
	}
	doc, ns, err := prepare(raw, key, fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	security, err := wss.FindHeader(doc.Root(), ns, "")
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{"body-1"}
	if mode == "timestamp-only" {
		ids = []string{"ts-1"}
	}
	if mode == "decoy" {
		ids = []string{"decoy", "ts-1"}
	}
	var refs []dsig.Reference
	for _, id := range ids {
		refs = append(refs, dsig.Reference{URI: "#" + id, DigestAlgorithm: xmlsec.DigestSHA256, Transforms: []dsig.TransformSpec{{Algorithm: string(c14n.Exclusive10)}}})
	}
	_, err = dsig.Sign(doc, xmlsec.KeyProvider{Signer: key.Key, Certificate: key.Certificate}, dsig.SignOptions{SignatureAlgorithm: xmlsec.SigRSASHA256, CanonicalizationAlgorithm: string(c14n.Exclusive10), References: refs, KeyInfo: dsig.KeyInfoSecurityTokenReference, SecurityTokenID: "bst-1", Parent: security})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := c14n.Bytes(doc.Root(), c14n.Options{Algorithm: c14n.Inclusive10WithComments})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestInclusiveNamespaceProtection(t *testing.T) {
	key := identity(t)
	wire, err := Sign(envelope("1.1"), key, fixedTime, "q")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(wire, []byte("InclusiveNamespaces")) {
		t.Fatal("prefix list absent")
	}
	verified, err := Verify(wire, key.Certificate, fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(verified.Body, []byte(`xmlns:q="urn:qualified-value"`)) {
		t.Fatal("consumed Body lost the signed QName namespace binding")
	}
	// q appears only in a QName-valued text node: without an explicit inclusive
	// prefix its binding would be outside Exclusive C14N's visible-use rules.
	rebound := bytes.Replace(wire, []byte(`urn:qualified-value`), []byte(`urn:attacker`), 1)
	if _, err := Verify(rebound, key.Certificate, fixedTime); err == nil {
		t.Fatal("namespace rebinding accepted")
	}
}

func TestGoldenSerialization(t *testing.T) {
	key := identity(t)
	original := envelope("1.1")
	wire, err := Sign(original, key, fixedTime, "q")
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
	stamp, err := wss.FindTimestamp(security)
	if err != nil {
		t.Fatal(err)
	}
	body := element(doc.Root()).FirstElement(ns, "Body")
	bodyBytes, err := c14n.Bytes(body, c14n.Options{Algorithm: c14n.Exclusive10, InclusiveNamespacePrefixes: []string{"q"}})
	if err != nil {
		t.Fatal(err)
	}
	timeBytes, err := c14n.Bytes(stamp, c14n.Options{Algorithm: c14n.Exclusive10, InclusiveNamespacePrefixes: []string{"q"}})
	if err != nil {
		t.Fatal(err)
	}
	artifacts := map[string][]byte{"request.original.xml": original, "request.signed.xml": wire, "body.c14n": bodyBytes, "timestamp.c14n": timeBytes}
	for name, got := range artifacts {
		path := "testdata/" + name
		if os.Getenv("SOAP_UPDATE_GOLDEN") == "1" {
			if err := os.WriteFile(path, got, 0600); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s byte stability changed; review before explicitly refreshing synthetic artifacts", name)
		}
	}
	info := security.FirstElement(xmlsec.NSDSig, "Signature").FirstElement(xmlsec.NSDSig, "SignedInfo")
	for ref := range info.Children() {
		if !ref.IsElement(xmlsec.NSDSig, "Reference") {
			continue
		}
		target := bodyBytes
		if ref.AttrValue("URI") == "#ts-1" {
			target = timeBytes
		}
		digest := sha256.Sum256(target)
		if base64.StdEncoding.EncodeToString(digest[:]) != ref.FirstElement(xmlsec.NSDSig, "DigestValue").StringValue() {
			t.Fatal("recorded canonical octets differ from signed digest")
		}
	}
}

func TestTrustAndMalformedInputs(t *testing.T) {
	key := identity(t)
	rogue, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := *key.Certificate
	template.SerialNumber = big.NewInt(99)
	template.PublicKey = &rogue.PublicKey
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &rogue.PublicKey, rogue)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := Sign(envelope("1.1"), Identity{Certificate: cert, Key: rogue}, fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(wire, key.Certificate, fixedTime); err == nil {
		t.Fatal("untrusted signing key accepted")
	}
	for _, raw := range [][]byte{[]byte(`<!DOCTYPE s:Envelope><s:Envelope/>`), []byte(`<x/>`), []byte(strings.Repeat("x", 4<<20+1))} {
		if _, err := Verify(raw, key.Certificate, fixedTime); err == nil {
			t.Fatal("invalid/oversized XML accepted")
		}
	}
}

func TestWrappedSOAPBody(t *testing.T) {
	key := identity(t)
	wire, err := Sign(envelope("1.1"), key, fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	start := bytes.Index(wire, []byte("<s:Body"))
	end := bytes.Index(wire, []byte("</s:Body>")) + len("</s:Body>")
	if start < 0 || end <= start {
		t.Fatal("missing Body")
	}
	covered := append([]byte(nil), wire[start:end]...)
	wrapped := bytes.Replace(wire, covered, []byte(`<s:Body><m:echo><value>forged</value></m:echo></s:Body>`), 1)
	wrapped = bytes.Replace(wrapped, []byte("</s:Header>"), append(covered, []byte("</s:Header>")...), 1)
	tree, err := xmlsec.Parse(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	security, err := wss.FindHeader(tree.Root, xmlsec.NSSOAP11, "")
	if err != nil {
		t.Fatal(err)
	}
	// The moved original Body retains a valid signature: cryptography alone must
	// not authorize the fresh unsigned Body at the application-consumed location.
	if _, err := dsig.Verify(tree.Root, security.FirstElement(xmlsec.NSDSig, "Signature"), dsig.VerifyOptions{Certificate: key.Certificate}); err != nil {
		t.Fatalf("wrapping vector lost signature validity: %v", err)
	}
	if _, err := Verify(wrapped, key.Certificate, fixedTime); err == nil {
		t.Fatal("wrapped SOAP Body accepted")
	}
}
