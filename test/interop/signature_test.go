//go:build interop

package interop

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stanimirivanov/xk6-soap/internal/wssec"
)

func TestApacheSignatureGate(t *testing.T) {
	base := os.Getenv("SOAP_INTEROP_URL")
	trustPath := os.Getenv("SOAP_INTEROP_SIGNATURE_TRUST")
	if base == "" || trustPath == "" {
		t.Fatal("signature fixture unavailable; use make interop")
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
	client := &http.Client{Timeout: 5 * time.Second}
	waitApache(t, client, base, []string{"/sig11", "/sig12"})
	for _, version := range []string{"11", "12"} {
		t.Run(version, func(t *testing.T) {
			ns := "http://schemas.xmlsoap.org/soap/envelope/"
			contentType := "text/xml; charset=utf-8"
			if version == "12" {
				ns = "http://www.w3.org/2003/05/soap-envelope"
				contentType = "application/soap+xml; charset=utf-8"
			}
			raw := []byte(`<s:Envelope xmlns:s="` + ns + `" xmlns:m="urn:xk6-soap:fixture"><s:Body><m:echo><value>synthetic</value></m:echo></s:Body></s:Envelope>`)
			wire, err := wssec.Sign(raw, wssec.Identity{Certificate: clientCert, Key: key.(*rsa.PrivateKey)}, time.Now(), "s", "m")
			if err != nil {
				t.Fatal(err)
			}
			for _, tamper := range []bool{false, true} {
				data := wire
				if tamper {
					data = bytes.Replace(wire, []byte("synthetic"), []byte("tampered"), 1)
				}
				req, err := http.NewRequest(http.MethodPost, base+"/sig"+version, bytes.NewReader(data))
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
				if tamper {
					if res.StatusCode != 500 || !strings.Contains(string(response), "Fault") {
						t.Fatalf("Apache accepted tamper: %d", res.StatusCode)
					}
					continue
				}
				if res.StatusCode != 200 {
					t.Fatalf("Apache rejected signature: %d %s", res.StatusCode, response)
				}
				verified, err := wssec.Verify(response, trust, time.Now())
				if err != nil {
					t.Fatalf("Apache response did not verify: %v\n%s", err, response)
				}
				if !bytes.Contains(verified.Body, []byte("synthetic")) {
					t.Fatal("verified response Body differs")
				}
				if !bytes.Contains(response, []byte("InclusiveNamespaces")) {
					t.Fatal("independent InclusiveNamespaces coverage absent")
				}
				if _, err := wssec.Verify(response, clientCert, time.Now()); err == nil {
					t.Fatal("untrusted signer accepted")
				}
				if _, err := wssec.Verify(bytes.Replace(response, []byte("synthetic"), []byte("tampered"), 1), trust, time.Now()); err == nil {
					t.Fatal("tampered Apache response accepted")
				}
			}
		})
	}
}
