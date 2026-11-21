package wssec

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"regexp"
	"strings"
	"testing"

	"github.com/stanimirivanov/xk6-soap/internal/keys"
	"github.com/stanimirivanov/xk6-soap/internal/message"
)

func TestReceiveSignThenEncrypt(t *testing.T) {
	material := policyKeys(t)
	policy, err := CompilePolicy(SecurityOptions{Verify: &ReceiveOptions{Signature: boolp(true), RequireEncryption: boolp(true), Order: string(SignThenEncrypt)}}, KeyMaterial{Decryption: material.Decryption, Trust: material.Trust}, fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.RequireAvailable(); err != nil {
		t.Fatal(err)
	}
	wire, err := Protect(envelope("1.1"), identity(t), material.Recipient.Certificate(), fixedTime, SignThenEncrypt, 128)
	if err != nil {
		t.Fatal(err)
	}
	result := ReceiveWithKeys(200, string(wire), "1.1", message.Limits{}, policy.Receive, material, fixedTime)
	if !result.OK {
		t.Fatal(result.Error)
	}
}

func TestEncryptedResponseRejectsBeforeProjection(t *testing.T) {
	material := policyKeys(t)
	receive, trust := receivePolicy(t)
	receive.Order = string(SignThenEncrypt)
	receive.RequireEncryption = true
	const version = "1.1"
	raw := []byte(`<s:Envelope xmlns:s="` + message.SOAP11 + `"><s:Body><Echo>` + strings.Repeat("<item>PRIVATE_RECOVERED</item>", 100) + `</Echo></s:Body></s:Envelope>`)
	wire, err := Protect(raw, identity(t), material.Recipient.Certificate(), fixedTime, SignThenEncrypt, 256)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := Sign(raw, identity(t), fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := *identity(t).Certificate
	tmpl.PublicKey = &otherKey.PublicKey
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &otherKey.PublicKey, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(otherKey)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey, err := keys.NewCache().Load(keys.Input{Cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), Key: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})}, keys.Decryption, fixedTime)
	if err != nil {
		t.Fatal(err)
	}

	// Change the last GCM byte while keeping the wrapped key and wire shape intact.
	cipherValues := regexp.MustCompile(`<xenc:CipherValue>([^<]+)</xenc:CipherValue>`).FindAllStringSubmatch(string(wire), -1)
	if len(cipherValues) != 2 {
		t.Fatal("fixture requires two ciphertexts")
	}
	ct, err := base64.StdEncoding.DecodeString(cipherValues[1][1])
	if err != nil {
		t.Fatal(err)
	}
	ct[len(ct)-1] ^= 1
	badTag := strings.Replace(string(wire), cipherValues[1][1], base64.StdEncoding.EncodeToString(ct), 1)
	partial := strings.Replace(string(wire), "</s:Body>", "<Visible/></s:Body>", 1)
	wrongOrder, err := Protect(raw, identity(t), material.Recipient.Certificate(), fixedTime, EncryptThenSign, 256)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name      string
		wire      string
		recipient *keys.Material
		limits    message.Limits
		code      string
	}{
		{"plain", string(plain), material.Decryption, message.Limits{}, "POLICY_VIOLATION"},
		{"partial", partial, material.Decryption, message.Limits{}, "POLICY_VIOLATION"},
		{"bad tag", badTag, material.Decryption, message.Limits{}, "DECRYPTION_FAILED"},
		{"wrong key", string(wire), wrongKey, message.Limits{}, "DECRYPTION_FAILED"},
		{"recovered node limit", string(wire), material.Decryption, message.Limits{Nodes: 200}, "LIMIT_EXCEEDED"},
		{"wrong order", string(wrongOrder), material.Decryption, message.Limits{}, "SIGNATURE_INVALID"},
	} {
		t.Run(row.name, func(t *testing.T) {
			if e := message.ValidateEnvelope(row.wire, version, row.limits); e != nil {
				t.Fatal("wire should fit limits", e)
			}
			got := ReceiveWithKeys(500, row.wire, version, row.limits, receive, KeyMaterial{Decryption: row.recipient, Trust: trust}, fixedTime)
			assertHidden(t, got)
			if got.Error.Code != row.code || strings.Contains(got.Error.Error(), "PRIVATE_RECOVERED") {
				t.Fatal(got.Error)
			}
		})
	}
	receive.RequireEncryption = false
	for _, payload := range []string{string(plain), string(wire)} {
		got := ReceiveWithKeys(200, payload, version, message.Limits{}, receive, material, fixedTime)
		if !got.OK || got.SigVerified == nil || !*got.SigVerified {
			t.Fatal("optional encryption lost signature acceptance", got.Error)
		}
	}
}

func TestReceiveEncryptedOperationElement(t *testing.T) {
	material := policyKeys(t)
	material.Decryption = nil
	outbound, err := CompilePolicy(SecurityOptions{Sign: &SigningPolicy{}, Encrypt: &EncryptionPolicy{Target: "body"}}, material, fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := BuildSecurity(envelope("1.2"), outbound, material, fixedTime, rand.Reader, nil, message.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	receive, trust := receivePolicy(t)
	receive.Order = string(SignThenEncrypt)
	receive.RequireEncryption = true
	result := ReceiveWithKeys(200, string(wire), "1.2", message.Limits{}, receive, KeyMaterial{Decryption: material.Recipient, Trust: trust}, fixedTime)
	if !result.OK || result.Body == nil || !strings.Contains(*result.Body, "synthetic") {
		t.Fatal(result.Error)
	}
}
