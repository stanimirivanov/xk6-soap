//go:build interop

package interop

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stanimirivanov/xk6-soap/internal/wssec"
)

func TestApacheEncryptionGate(t *testing.T) {
	base := os.Getenv("SOAP_INTEROP_URL")
	trustPath := os.Getenv("SOAP_INTEROP_SIGNATURE_TRUST")
	if base == "" || trustPath == "" {
		t.Fatal("encryption fixture unavailable; use make interop")
	}
	readCert := func(path string) *x509.Certificate {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(b)
		if block == nil {
			t.Fatal("missing PEM certificate")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	clientCert := readCert("../../internal/wssec/testdata/signing-cert.pem")
	trust := readCert(trustPath)
	keyPEM, err := os.ReadFile("../../internal/wssec/testdata/signing-key.pem")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(keyPEM)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	id := wssec.Identity{Certificate: clientCert, Key: key.(*rsa.PrivateKey)}
	client := &http.Client{Timeout: 5 * time.Second}
	waitApache(t, client, base, []string{"/ste12811", "/ets25612"})
	for _, version := range []string{"11", "12"} {
		ns := "http://schemas.xmlsoap.org/soap/envelope/"
		contentType := "text/xml; charset=utf-8"
		if version == "12" {
			ns = "http://www.w3.org/2003/05/soap-envelope"
			contentType = "application/soap+xml; charset=utf-8"
		}
		for _, order := range []wssec.ProtectionOrder{wssec.SignThenEncrypt, wssec.EncryptThenSign} {
			for _, bits := range []int{128, 256} {
				endpoint := "/ste" + strconv.Itoa(bits) + version
				if order == wssec.EncryptThenSign {
					endpoint = "/ets" + strconv.Itoa(bits) + version
				}
				t.Run(endpoint, func(t *testing.T) {
					raw := []byte(`<s:Envelope xmlns:s="` + ns + `" xmlns:m="urn:xk6-soap:fixture"><s:Body><m:echo><value>synthetic</value></m:echo></s:Body></s:Envelope>`)
					wire, err := wssec.Protect(raw, id, trust, time.Now(), order, bits)
					if err != nil {
						t.Fatal(err)
					}
					post := func(data []byte) (int, []byte) {
						req, err := http.NewRequest(http.MethodPost, base+endpoint, bytes.NewReader(data))
						if err != nil {
							t.Fatal(err)
						}
						req.Header.Set("Content-Type", contentType)
						req.Header.Set("SOAPAction", `"urn:echo"`)
						res, err := client.Do(req)
						if err != nil {
							t.Fatal(err)
						}
						response, err := io.ReadAll(io.LimitReader(res.Body, 4<<20+1))
						res.Body.Close()
						if err != nil || len(response) > 4<<20 {
							t.Fatal("response limit/error")
						}
						return res.StatusCode, response
					}
					status, response := post(wire)
					if status != 200 {
						t.Fatalf("Apache rejected encryption: %d %s", status, response)
					}
					got, err := wssec.Open(response, trust, id, time.Now(), order, bits)
					if err != nil {
						t.Fatalf("Apache response rejected: %v\n%s", err, response)
					}
					if !bytes.Contains(got.Body, []byte("synthetic")) || bytes.Contains(response, []byte(">synthetic<")) {
						t.Fatal("incorrect protected Body")
					}
					opposite := wssec.SignThenEncrypt
					if order == wssec.SignThenEncrypt {
						opposite = wssec.EncryptThenSign
					}
					for name, mutated := range map[string][]byte{
						"tag":          alterCipherTag(t, response),
						"OAEP digest":  alterOAEPDigest(t, response),
						"MGF":          bytes.Replace(response, []byte("mgf1sha256"), []byte("mgf1sha384"), 1),
						"partial Body": bytes.Replace(response, []byte("<xenc:EncryptedData"), []byte("<plain>exposed</plain><xenc:EncryptedData"), 1),
					} {
						t.Run(name, func(t *testing.T) {
							if bytes.Equal(mutated, response) {
								t.Fatal("mutation missed wire")
							}
							if result, err := wssec.Open(mutated, trust, id, time.Now(), order, bits); err == nil || result != nil {
								t.Fatal("invalid Apache response published plaintext")
							}
						})
					}
					if result, err := wssec.Open(response, trust, id, time.Now(), opposite, bits); err == nil || result != nil {
						t.Fatal("Apache response accepted under wrong order")
					}
					// Build a fresh request so a rejection cannot be attributed to replay.
					fresh, err := wssec.Protect(raw, id, trust, time.Now(), order, bits)
					if err != nil {
						t.Fatal(err)
					}
					if status, response := post(alterCipherTag(t, fresh)); status != 500 || !bytes.Contains(response, []byte("Fault")) {
						t.Fatal("Apache accepted altered tag")
					}

				})
			}
		}
	}
}

func alterCipherTag(t *testing.T, wire []byte) []byte {
	t.Helper()
	marker := []byte("<xenc:CipherValue>")
	start := bytes.LastIndex(wire, marker)
	if start < 0 {
		t.Fatal("Body ciphertext missing")
	}
	start += len(marker)
	length := bytes.Index(wire[start:], []byte("</xenc:CipherValue>"))
	if length < 0 {
		t.Fatal("unterminated ciphertext")
	}
	value, err := base64.StdEncoding.DecodeString(string(wire[start : start+length]))
	if err != nil || len(value) < 28 {
		t.Fatal("invalid GCM ciphertext")
	}
	value[len(value)-1] ^= 1
	return bytes.Replace(wire, wire[start:start+length], []byte(base64.StdEncoding.EncodeToString(value)), 1)
}

func alterOAEPDigest(t *testing.T, wire []byte) []byte {
	t.Helper()
	start := bytes.Index(wire, []byte("<xenc:EncryptedKey"))
	if start < 0 {
		t.Fatal("key missing")
	}
	out := append([]byte(nil), wire[:start]...)
	return append(out, bytes.Replace(wire[start:], []byte("http://www.w3.org/2001/04/xmlenc#sha256"), []byte("http://www.w3.org/2001/04/xmldsig-more#sha384"), 1)...)
}
