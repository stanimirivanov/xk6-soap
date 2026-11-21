package wssec

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/knroy/go-xmlsec/v2"
	"github.com/knroy/go-xmlsec/v2/wss"
	"github.com/knroy/go-xmlsec/v2/xenc"
	"github.com/stanimirivanov/xk6-soap/internal/message"
)

func TestSignThenEncryptRequest(t *testing.T) {
	material := policyKeys(t)
	material.Decryption = nil
	for _, target := range []string{"content", "body"} {
		for _, algorithm := range []string{"aes-128-gcm", "aes-256-gcm"} {
			t.Run(target+"/"+algorithm, func(t *testing.T) {
				policy, err := CompilePolicy(SecurityOptions{Sign: &SigningPolicy{}, Encrypt: &EncryptionPolicy{Algorithm: algorithm, Target: target}}, material, fixedTime)
				if err != nil {
					t.Fatal(err)
				}
				if err := policy.RequireAvailable(); err != nil {
					t.Fatal(err)
				}
				raw := bytes.ReplaceAll(envelope("1.1"), []byte("synthetic"), []byte("REQUEST_PRIVATE_SENTINEL"))
				build := func() ([]byte, []byte) {
					t.Helper()
					wire, err := BuildSecurity(raw, policy, material, fixedTime, rand.Reader, nil, message.Limits{})
					if err != nil {
						t.Fatal(err)
					}
					if bytes.Contains(wire, []byte("REQUEST_PRIVATE_SENTINEL")) {
						t.Fatal("encrypted plaintext on the wire")
					}
					doc, ns, err := parsed(wire)
					if err != nil {
						t.Fatal(err)
					}
					body := element(doc.Root()).FirstElement(ns, "Body")
					if body == nil || body.Attr(xmlsec.NSWSU, "Id") == nil || len(body.ChildElements()) != 1 {
						t.Fatal("wrong SOAP Body shape")
					}
					ed := body.FirstElement(xmlsec.NSXEnc, "EncryptedData")
					wantType := xenc.TypeContent
					wantAlgorithm := xmlsec.EncAES256GCM
					if target == "body" {
						wantType = xenc.TypeElement
					}
					if algorithm == "aes-128-gcm" {
						wantAlgorithm = xmlsec.EncAES128GCM
					}
					if ed == nil || ed.AttrValue("Type") != wantType || ed.FirstElement(xmlsec.NSXEnc, "EncryptionMethod").AttrValue("Algorithm") != wantAlgorithm {
						t.Fatal("wrong encryption target or algorithm")
					}
					security, err := wss.FindHeader(doc.Root(), ns, "")
					if err != nil {
						t.Fatal(err)
					}
					ek := security.FirstElement(xmlsec.NSXEnc, "EncryptedKey")
					if ek == nil {
						t.Fatal("missing wrapped key")
					}
					options := xenc.DecryptOptions{StrictBSP: true, AllowedDataAlgorithms: []string{wantAlgorithm}, AllowedKeyTransportAlgorithms: []string{xmlsec.KeyTransportRSAOAEP}, AllowedDigestAlgorithms: []string{xmlsec.DigestSHA256}, AllowedMGFAlgorithms: []string{xmlsec.MGF1SHA256}}
					key, err := xenc.DecryptEncryptedKey(ek, identity(t).Key, options)
					if err != nil {
						t.Fatal(err)
					}
					plain, err := xenc.DecryptAndReplace(doc.Root(), ed, key, options)
					if err != nil {
						t.Fatal(err)
					}
					recovered, recoveredNS, err := parsed(plain)
					if err != nil {
						t.Fatal(err)
					}
					verified, err := verifyRecovered(recovered, recoveredNS, material.Signing.Certificate(), fixedTime)
					if err != nil || !bytes.Contains(verified.Body, []byte("REQUEST_PRIVATE_SENTINEL")) {
						t.Fatal("recovered Body signature", err)
					}
					cipherValue := ed.FirstElement(xmlsec.NSXEnc, "CipherData").FirstElement(xmlsec.NSXEnc, "CipherValue").StringValue()
					cipherBytes, err := base64.StdEncoding.DecodeString(cipherValue)
					if err != nil || len(cipherBytes) <= 12 {
						t.Fatal("bad GCM wire")
					}
					return key, cipherBytes[:12]
				}
				firstKey, firstIV := build()
				nextKey, nextIV := build()
				if bytes.Equal(firstKey, nextKey) || bytes.Equal(firstIV, nextIV) {
					t.Fatal("successive requests reused key or IV")
				}
				clear(firstKey)
				clear(nextKey)
				for _, rng := range []io.Reader{nil, strings.NewReader("short"), iotest.ErrReader(ErrRandom)} {
					if wire, err := BuildSecurity(raw, policy, material, fixedTime, rng, nil, message.Limits{}); wire != nil || err != ErrRandom {
						t.Fatal("RNG failure returned wire or wrong error", err)
					}
				}
				if wire, err := BuildSecurity(raw, policy, material, fixedTime, rand.Reader, nil, message.Limits{Bytes: 1024}); wire != nil || err != ErrOutputLimit {
					t.Fatal("wire limit failed", err)
				}

			})
		}
	}
}
