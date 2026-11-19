package wssec

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stanimirivanov/xk6-soap/internal/keys"
)

func boolp(v bool) *bool { return &v }
func intp(v int) *int    { return &v }
func policyKeys(t *testing.T) KeyMaterial {
	t.Helper()
	cache := keys.NewCache()
	in := keys.Input{Cert: readPolicyFixture(t, "signing-cert.pem"), Key: readPolicyFixture(t, "signing-key.pem")}
	m, err := cache.Load(in, keys.Signing, fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	return KeyMaterial{Signing: m, Decryption: m, Recipient: m, Trust: []*keys.Material{m}}
}
func readPolicyFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func TestPolicyDefaultsAndCapabilityGate(t *testing.T) {
	material := policyKeys(t)
	plain, err := CompilePolicy(SecurityOptions{}, KeyMaterial{}, fixedTime)
	if err != nil || plain.Receive.Signature || plain.Receive.Timestamp || plain.RequireAvailable() != nil {
		t.Fatal("plain default", err)
	}
	p, err := CompilePolicy(SecurityOptions{Sign: &SigningPolicy{}, Encrypt: &EncryptionPolicy{}, Verify: &ReceiveOptions{Order: string(EncryptThenSign)}}, material, fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	if p.Sign.Algorithm != "rsa-sha256" || p.Sign.Digest != "sha256" || p.Sign.Canonicalization != "exclusive-c14n" || p.Sign.KeyID != "binary-security-token" || p.Timestamp.TTLSeconds != 300 || p.Order != string(SignThenEncrypt) {
		t.Fatal("outbound defaults")
	}
	if !p.Receive.Signature || !p.Receive.Timestamp || p.Receive.RequireEncryption || p.Receive.Order != string(EncryptThenSign) || p.Receive.ClockSkewSeconds != 60 || p.Receive.MaxAgeSeconds != 300 {
		t.Fatal("receive defaults")
	}
	if p.RequireAvailable() != ErrUnavailable {
		t.Fatal("unimplemented policy accepted")
	}
	ut, err := CompilePolicy(SecurityOptions{UsernameToken: &UsernameTokenPolicy{User: "synthetic", Password: "synthetic"}}, KeyMaterial{}, fixedTime)
	if err != nil || ut.Timestamp == nil || ut.UsernameToken.PasswordType != "PasswordDigest" {
		t.Fatal("UsernameToken timestamp/default", err)
	}
}
func TestInvalidPolicyMatrix(t *testing.T) {
	material := policyKeys(t)
	material.Decryption = nil
	cases := map[string]SecurityOptions{
		"invalid UTF-8 selector":          {Sign: &SigningPolicy{Headers: []string{"h\xff"}}},
		"invalid UTF-8 expanded name":     {Verify: &ReceiveOptions{Signature: boolp(true), SignedHeaders: []ExpandedName{{Namespace: "urn:test", LocalName: "h\xff"}}}},
		"invalid UTF-8 password":          {UsernameToken: &UsernameTokenPolicy{User: "u", Password: "p\xff"}},
		"legacy algorithm":                {Sign: &SigningPolicy{Algorithm: "rsa-sha1"}},
		"digest":                          {Sign: &SigningPolicy{Digest: "sha1"}},
		"c14n":                            {Sign: &SigningPolicy{Canonicalization: "inclusive-c14n"}},
		"key ID":                          {Sign: &SigningPolicy{KeyID: "untrusted"}},
		"user":                            {UsernameToken: &UsernameTokenPolicy{}},
		"password type":                   {UsernameToken: &UsernameTokenPolicy{User: "u", Password: "SECRET", PasswordType: "SECRET"}},
		"TTL zero":                        {Timestamp: &TimestampOptions{TTLSeconds: intp(0)}},
		"TTL high":                        {Timestamp: &TimestampOptions{TTLSeconds: intp(3601)}},
		"offset":                          {Timestamp: &TimestampOptions{ClockOffsetSeconds: intp(-301)}},
		"order without pair":              {Order: string(SignThenEncrypt)},
		"bad order":                       {Sign: &SigningPolicy{}, Encrypt: &EncryptionPolicy{}, Order: "SECRET"},
		"CBC":                             {Encrypt: &EncryptionPolicy{Algorithm: "aes-256-cbc"}},
		"transport":                       {Encrypt: &EncryptionPolicy{KeyTransport: "rsa-1_5"}},
		"header target missing selectors": {Encrypt: &EncryptionPolicy{Target: "headers"}},
		"selectors wrong target":          {Encrypt: &EncryptionPolicy{Target: "body", Headers: []string{}}},
		"duplicate selectors":             {Sign: &SigningPolicy{Headers: []string{"h", "h"}}},
		"invalid selector":                {Sign: &SigningPolicy{Headers: []string{"x:y"}}},
		"unsigned timestamp":              {Verify: &ReceiveOptions{Timestamp: boolp(true), Signature: boolp(false)}},
		"unsigned encryption":             {Verify: &ReceiveOptions{RequireEncryption: boolp(true)}},
		"skew":                            {Verify: &ReceiveOptions{ClockSkewSeconds: intp(301)}},
		"age":                             {Verify: &ReceiveOptions{MaxAgeSeconds: intp(0)}},
		"receive order without decryptor": {Verify: &ReceiveOptions{Order: string(SignThenEncrypt)}},
		"empty signature allowlist":       {Verify: &ReceiveOptions{SignatureAlgorithms: []string{}}},
		"legacy receive digest":           {Verify: &ReceiveOptions{DigestAlgorithms: []string{"sha1"}}},
		"duplicate expanded names":        {Verify: &ReceiveOptions{SignedHeaders: []ExpandedName{{Namespace: "urn:test", LocalName: "h"}, {Namespace: "urn:test", LocalName: "h"}}}},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := CompilePolicy(opts, material, fixedTime)
			if err != ErrPolicy {
				t.Fatal("invalid policy not rejected semantically", err)
			}
			if strings.Contains(err.Error(), "SECRET") {
				t.Fatal("input reflected in error")
			}
		})
	}
}

func TestPolicyKeysEnumsAndIndependentReceiveDefaults(t *testing.T) {
	material := policyKeys(t)
	material.Decryption = nil
	for _, algorithm := range []string{"rsa-sha256", "rsa-sha384", "rsa-sha512"} {
		for _, digest := range []string{"sha256", "sha384", "sha512"} {
			for _, keyID := range []string{"binary-security-token", "direct", "issuer-serial", "x509keyidentifier", "ski", "ThumbprintSHA1"} {
				p, err := CompilePolicy(SecurityOptions{Sign: &SigningPolicy{Algorithm: algorithm, Digest: digest, KeyID: keyID}}, material, fixedTime)
				if err != nil {
					t.Fatal(algorithm, digest, keyID, err)
				}
				if p.Receive.SignatureAlgorithms[0] != "rsa-sha256" || p.Receive.DigestAlgorithms[0] != "sha256" {
					t.Fatal("receive algorithms inherited outbound choice")
				}
				if keyID == "direct" && p.Sign.KeyID != "binary-security-token" {
					t.Fatal("direct alias not normalized")
				}
			}
		}
	}
	for _, algorithm := range []string{"aes-128-gcm", "aes-256-gcm"} {
		for _, target := range []string{"body", "content", "headers"} {
			enc := &EncryptionPolicy{Algorithm: algorithm, Target: target}
			if target == "headers" {
				enc.Headers = []string{"custom"}
			}
			p, err := CompilePolicy(SecurityOptions{Encrypt: enc}, material, fixedTime)
			if err != nil || p.Encrypt.Target != target {
				t.Fatal(err)
			}
		}
	}
	for _, tc := range []struct {
		opts     SecurityOptions
		material KeyMaterial
	}{
		{SecurityOptions{Sign: &SigningPolicy{}, Verify: &ReceiveOptions{Signature: boolp(false)}}, KeyMaterial{}},
		{SecurityOptions{Encrypt: &EncryptionPolicy{}}, KeyMaterial{}},
		{SecurityOptions{Verify: &ReceiveOptions{Signature: boolp(true)}}, KeyMaterial{}},
		{SecurityOptions{Verify: &ReceiveOptions{Signature: boolp(true), SignatureAlgorithms: []string{"ecdsa-sha256"}}}, material},
	} {
		if _, err := CompilePolicy(tc.opts, tc.material, fixedTime); err != ErrPolicyKey {
			t.Fatal("required key role/algorithm not checked", err)
		}
	}
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		private, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cert := &x509.Certificate{SerialNumber: big.NewInt(700), NotBefore: fixedTime.Add(-time.Hour), NotAfter: fixedTime.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		der, err := x509.CreateCertificate(rand.Reader, cert, cert, &private.PublicKey, private)
		if err != nil {
			t.Fatal(err)
		}
		privateDER, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			t.Fatal(err)
		}
		m, err := keys.NewCache().Load(keys.Input{Cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), Key: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})}, keys.Signing, fixedTime)
		if err != nil {
			t.Fatal(err)
		}
		ecMaterial := material
		ecMaterial.Signing = m
		algorithm := map[int]string{256: "ecdsa-sha256", 384: "ecdsa-sha384", 521: "ecdsa-sha512"}[curve.Params().BitSize]
		p, err := CompilePolicy(SecurityOptions{Sign: &SigningPolicy{Algorithm: algorithm}}, ecMaterial, fixedTime)
		if err != nil || p.Receive.SignatureAlgorithms[0] != "rsa-sha256" {
			t.Fatal("independent EC/RSA receive policy", err)
		}
		if _, err := CompilePolicy(SecurityOptions{Sign: &SigningPolicy{Algorithm: algorithm, KeyID: "ski"}}, ecMaterial, fixedTime); err != ErrPolicyKey {
			t.Fatal("missing SKI accepted", err)
		}
		if _, err := CompilePolicy(SecurityOptions{Sign: &SigningPolicy{Algorithm: "rsa-sha256"}}, ecMaterial, fixedTime); err != ErrPolicyKey {
			t.Fatal("wrong signing key algorithm accepted", err)
		}
		if curve != elliptic.P256() {
			if _, err := CompilePolicy(SecurityOptions{Sign: &SigningPolicy{Algorithm: "ecdsa-sha256"}}, ecMaterial, fixedTime); err != ErrPolicyKey {
				t.Fatal("wrong curve/hash pair accepted", err)
			}
		}
	}
}
func TestPolicyBoundariesCopiesAndMetadata(t *testing.T) {
	material := policyKeys(t)
	material.Decryption = nil
	for _, ttl := range []int{1, 3600} {
		for _, offset := range []int{-300, 300} {
			p, err := CompilePolicy(SecurityOptions{Timestamp: &TimestampOptions{TTLSeconds: intp(ttl), ClockOffsetSeconds: intp(offset)}}, KeyMaterial{}, fixedTime)
			if err != nil || p.Timestamp.TTLSeconds != ttl || p.Timestamp.ClockOffsetSeconds != offset {
				t.Fatal(err)
			}
		}
	}
	for _, skew := range []int{0, 300} {
		for _, age := range []int{1, 3600} {
			_, err := CompilePolicy(SecurityOptions{Verify: &ReceiveOptions{Signature: boolp(true), ClockSkewSeconds: intp(skew), MaxAgeSeconds: intp(age)}}, material, fixedTime)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	opts := SecurityOptions{UsernameToken: &UsernameTokenPolicy{User: "SECRET_USER", Password: "SECRET_PASSWORD"}, Sign: &SigningPolicy{Headers: []string{"custom"}}, Verify: &ReceiveOptions{SignatureAlgorithms: []string{"rsa-sha256"}, SignedHeaders: []ExpandedName{{Namespace: "urn:private", LocalName: "Header"}}}}
	p, err := CompilePolicy(opts, material, fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	opts.UsernameToken.Password = "changed"
	opts.Sign.Headers[0] = "changed"
	opts.Verify.SignatureAlgorithms[0] = "changed"
	opts.Verify.SignedHeaders[0].LocalName = "changed"
	if p.UsernameToken.Password != "SECRET_PASSWORD" || p.Sign.Headers[0] != "custom" || p.Receive.SignatureAlgorithms[0] != "rsa-sha256" || p.Receive.SignedHeaders[0].LocalName != "Header" {
		t.Fatal("policy retains mutable option state")
	}
	if p.DiagnosticAlgorithm() != "rsa-sha256" {
		t.Fatal("unexpected metadata algorithm")
	}
	p.Sign.Algorithm = "SECRET_ALGORITHM"
	if strings.Contains(p.DiagnosticAlgorithm(), "SECRET") {
		t.Fatal("metadata reflects unchecked input")
	}
}

func TestRequiredEncryptionNeedsDecryptionRoleAndExplicitOrder(t *testing.T) {
	material := policyKeys(t)
	if _, err := CompilePolicy(SecurityOptions{}, material, fixedTime); err != ErrPolicy {
		t.Fatal("decryptor without explicit receive order accepted", err)
	}
	material.Decryption = nil
	if _, err := CompilePolicy(SecurityOptions{Verify: &ReceiveOptions{Signature: boolp(true), RequireEncryption: boolp(true), Order: string(SignThenEncrypt)}}, material, fixedTime); err != ErrPolicyKey {
		t.Fatal("missing decryptor not reported as key requirement", err)
	}
}
