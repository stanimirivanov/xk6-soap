package keys

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

var testTime = time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func pemInput(t *testing.T) Input {
	t.Helper()
	return Input{Cert: fixture(t, "../wssec/testdata/signing-cert.pem"), Key: fixture(t, "../wssec/testdata/signing-key.pem")}
}

func TestZeroValueCacheRejectsLoad(t *testing.T) {
	var cache Cache
	material, err := cache.Load(pemInput(t), Signing, testTime)
	if material != nil || !errors.Is(err, ErrInvalid) {
		t.Fatal("expected no material and ErrInvalid from a zero-value cache")
	}
}

func TestLoadAndRevalidate(t *testing.T) {
	cache := NewCache()
	input := pemInput(t)
	first, err := cache.Load(input, Signing, testTime)
	if err != nil {
		t.Fatal(err)
	}
	second, err := cache.Load(input, Signing, testTime)
	if err != nil || first != second {
		t.Fatal("same material was not deduplicated", err)
	}
	if _, err := cache.Load(input, Signing, testTime.AddDate(20, 0, 0)); err == nil {
		t.Fatal("expired cached material accepted")
	}
	input.Cert[0] = 'X'
	input.Key[0] = 'X'
	if err := first.Validate(Signing, testTime); err != nil {
		t.Fatal("caller mutation reached cached material", err)
	}
	cert := first.Certificate()
	cert.Raw[0] ^= 1
	if first.Certificate().Raw[0] == cert.Raw[0] {
		t.Fatal("certificate accessor leaks mutable cache state")
	}
}

func TestPKCS12PasswordIsolation(t *testing.T) {
	c := NewCache()
	in := Input{PKCS12: fixture(t, "testdata/openssl3.p12"), Password: "wrong-synthetic"}
	for _, password := range []string{"wrong-synthetic", "synthetic-only", "wrong-synthetic", ""} {
		in.Password = password
		m, err := c.Load(in, Signing, testTime)
		if password == "synthetic-only" {
			if err != nil || m == nil {
				t.Fatal(err)
			}
		} else if err == nil || m != nil {
			t.Fatal("incorrect decoding password accepted")
		}
	}
}

func TestConcreteKeysConcurrentAndPrivate(t *testing.T) {
	for _, in := range []Input{pemInput(t), {PKCS12: fixture(t, "testdata/openssl3.p12"), Password: "synthetic-only"}} {
		c := NewCache()
		first, err := c.Load(in, Signing, testTime)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256([]byte("synthetic-message"))
		var wg sync.WaitGroup
		for range 32 {
			wg.Go(func() {
				m, err := c.Load(in, Signing, testTime)
				if err != nil || m != first {
					t.Error("concurrent cache miss", err)
					return
				}
				sig, err := m.Sign(rand.Reader, digest[:], crypto.SHA256)
				if err != nil {
					t.Error(err)
					return
				}
				pub := m.Public().(*rsa.PublicKey)
				if rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig) != nil {
					t.Error("signature does not verify")
				}
				pub.N.SetInt64(1)
				ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, m.Public().(*rsa.PublicKey), []byte("synthetic"), nil)
				if err != nil {
					t.Error(err)
					return
				}
				plain, err := m.Decrypt(rand.Reader, ciphertext, &rsa.OAEPOptions{Hash: crypto.SHA256})
				if err != nil || string(plain) != "synthetic" {
					t.Error("concurrent RSA decrypt failed", err)
				}
			})
		}
		wg.Wait()
	}
}

func generatedInput(t *testing.T, key crypto.Signer, usage x509.KeyUsage, serial int64) Input {
	t.Helper()
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC), KeyUsage: usage}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return Input{Cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), Key: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})}
}
func rsaSigner(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	b, _ := pem.Decode(pemInput(t).Key)
	key, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return key.(*rsa.PrivateKey)
}
func TestFormatsRolesAndCurves(t *testing.T) {
	rsaKey := rsaSigner(t)
	input := generatedInput(t, rsaKey, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, 1)
	for _, kind := range []string{"pkcs8", "pkcs1"} {
		in := input
		if kind == "pkcs1" {
			in.Key = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)})
		}
		for _, role := range []Role{Signing, Decryption, Recipient, Trust} {
			if _, err := NewCache().Load(in, role, testTime); err != nil {
				t.Fatal(kind, role, err)
			}
		}
	}
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			input := generatedInput(t, key, x509.KeyUsageDigitalSignature, 2)
			for _, sec1 := range []bool{false, true} {
				in := input
				if sec1 {
					der, err := x509.MarshalECPrivateKey(key)
					if err != nil {
						t.Fatal(err)
					}
					in.Key = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
				}
				c := NewCache()
				m, err := c.Load(in, Signing, testTime)
				if err != nil {
					t.Fatal(err)
				}
				for _, role := range []Role{Recipient, Decryption} {
					if _, err := c.Load(in, role, testTime); err == nil {
						t.Fatal("EC transport accepted")
					}
				}
				digest := sha256.Sum256([]byte("synthetic"))
				var wg sync.WaitGroup
				for range 8 {
					wg.Go(func() {
						sig, err := m.Sign(rand.Reader, digest[:], crypto.SHA256)
						if err != nil || !ecdsa.VerifyASN1(m.Public().(*ecdsa.PublicKey), digest[:], sig) {
							t.Error("concurrent ECDSA sign failed", err)
						}
					})
				}
				wg.Wait()
			}
		})
	}
	signing := generatedInput(t, rsaKey, x509.KeyUsageDigitalSignature, 3)
	c := NewCache()
	if _, err := c.Load(signing, Signing, testTime); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Load(signing, Decryption, testTime); err == nil {
		t.Fatal("role bypass on cache hit")
	}
	encrypting := generatedInput(t, rsaKey, x509.KeyUsageKeyEncipherment, 4)
	if _, err := c.Load(encrypting, Decryption, testTime); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Load(encrypting, Signing, testTime); err == nil {
		t.Fatal("encryption-only key used for signing")
	}
}
func TestRejectInvalidMaterial(t *testing.T) {
	input := pemInput(t)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	wrong := generatedInput(t, other, 0, 5)
	wrong.Cert = input.Cert
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	ec, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]Input{
		"unsupported algorithm": generatedInput(t, ed, 0, 8),
		"mismatch":              wrong,
		"weak RSA":              generatedInput(t, weak, 0, 6),
		"unsupported curve":     generatedInput(t, ec, 0, 7),
		"ambiguous PEM":         {Cert: append(bytes.Clone(input.Cert), input.Cert...), Key: input.Key},
		"trailing garbage":      {Cert: append(bytes.Clone(input.Cert), []byte("synthetic-secret")...), Key: input.Key},
		"malformed preamble":    {Cert: append([]byte("-----BEGIN CERTIFICATE-----\nbroken\n"), input.Cert...), Key: input.Key},
		"encrypted PEM":         {Cert: input.Cert, Key: pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("synthetic-secret")})},
		"PEM password":          {Cert: input.Cert, Key: input.Key, Password: "synthetic-secret"},
		"mixed format":          {Cert: input.Cert, PKCS12: []byte("synthetic-secret")},
		"missing private key":   {Cert: input.Cert},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			m, err := NewCache().Load(in, Signing, testTime)
			if err == nil || m != nil {
				t.Fatal("invalid material accepted")
			}
			if strings.Contains(err.Error(), "synthetic-secret") {
				t.Fatal("input leaked in error")
			}
		})
	}
}
func TestCacheBounds(t *testing.T) {
	key := rsaSigner(t)
	t.Run("per input", func(t *testing.T) {
		if _, err := NewCache().Load(Input{Cert: make([]byte, MaxInput+1)}, Trust, testTime); err != ErrLimit {
			t.Fatal(err)
		}
	})
	for _, byteLimit := range []bool{false, true} {
		name := "entries"
		count := MaxEntries
		if byteLimit {
			name = "encoded bytes"
			count = MaxEncodedBytes / (2 * MaxInput)
		}
		t.Run(name, func(t *testing.T) {
			c := NewCache()
			var first Input
			for n := 0; n <= count; n++ {
				in := generatedInput(t, key, 0, int64(n+1))
				if byteLimit {
					in.Cert = append(in.Cert, bytes.Repeat([]byte(" "), MaxInput-len(in.Cert))...)
					in.Key = append(in.Key, bytes.Repeat([]byte(" "), MaxInput-len(in.Key))...)
				}
				if n == 0 {
					first = in
				}
				_, err := c.Load(in, Signing, testTime)
				if n < count && err != nil {
					t.Fatal(n, err)
				}
				if n == count && err != ErrLimit {
					t.Fatal("capacity not enforced", err)
				}
			}
			if _, err := c.Load(first, Signing, testTime); err != nil {
				t.Fatal("full cache rejected existing key", err)
			}
		})
	}
}

func TestAmbiguousPKCS12(t *testing.T) {
	if material, err := NewCache().Load(Input{PKCS12: fixture(t, "testdata/ambiguous.p12"), Password: "synthetic-only"}, Signing, testTime); err == nil || material != nil {
		t.Fatal("multiple private key identities accepted")
	}
}
func TestExpiredMaterialCannotPerformCrypto(t *testing.T) {
	key := rsaSigner(t)
	in := generatedInput(t, key, 0, 400)
	block, _ := pem.Decode(in.Cert)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	cert.NotBefore = time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)
	cert.NotAfter = time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	in.Cert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	m, err := NewCache().Load(in, Signing, time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("synthetic"))
	if _, err := m.Sign(rand.Reader, digest[:], crypto.SHA256); err != ErrExpired {
		t.Fatal("expired signer used", err)
	}
	if _, err := m.Decrypt(rand.Reader, []byte("synthetic"), &rsa.OAEPOptions{Hash: crypto.SHA256}); err != ErrExpired {
		t.Fatal("expired decryptor used", err)
	}
}

func TestExplicitEmptyKeyUsageIsNotUnrestricted(t *testing.T) {
	key := rsaSigner(t)
	template := &x509.Certificate{SerialNumber: big.NewInt(600), NotBefore: testTime.Add(-time.Hour), NotAfter: testTime.Add(time.Hour), ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Critical: true, Value: []byte{3, 1, 0}}}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	input := pemInput(t)
	input.Cert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if m, err := NewCache().Load(input, Signing, testTime); err == nil || m != nil {
		t.Fatal("present empty KeyUsage treated as unrestricted")
	}
}

func TestInvalidKeyInputsDoNotConsumeCacheBudget(t *testing.T) {
	cache := NewCache()
	for n := range MaxEntries + 1 {
		input := Input{Cert: []byte(strconv.Itoa(n) + " private invalid certificate")}
		_, err := cache.Load(input, Trust, testTime)
		if !errors.Is(err, ErrInvalid) {
			t.Fatal("unexpected malformed key result", err)
		}
	}
	if len(cache.entries) != 0 || cache.encodedBytes != 0 {
		t.Fatal("malformed keys consumed cache budget")
	}
}
