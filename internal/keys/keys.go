// Package keys decodes byte inputs and privately owns immutable concrete keys.
// It has no filesystem, network, runtime or provider dependencies.
package keys

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"sync"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

const (
	MaxInput        = 1 << 20
	MaxEntries      = 256
	MaxEncodedBytes = 32 << 20
)

var (
	ErrInvalid = errors.New("SOAP_KEY_INVALID")
	ErrRole    = errors.New("SOAP_KEY_ROLE")
	ErrExpired = errors.New("SOAP_KEY_VALIDITY")
	ErrLimit   = errors.New("SOAP_KEY_LIMIT")
)

type Role uint8

const (
	Signing Role = iota + 1
	Decryption
	Recipient
	Trust
)

type Input struct {
	Cert     []byte
	Key      []byte
	PKCS12   []byte
	Password string
}

// Material never exposes its concrete private key or internal certificate.
// RSA validation and precomputation finish before the object is published.
type Material struct {
	cert *x509.Certificate
	key  crypto.PrivateKey
}

func (m *Material) Certificate() *x509.Certificate {
	if m == nil || m.cert == nil {
		return nil
	}
	cert, _ := x509.ParseCertificate(bytes.Clone(m.cert.Raw))
	return cert
}
func (m *Material) Validate(role Role, now time.Time) error {
	if m == nil || m.cert == nil {
		return ErrInvalid
	}
	if now.Before(m.cert.NotBefore) || !now.Before(m.cert.NotAfter) {
		return ErrExpired
	}
	usage := x509.KeyUsageDigitalSignature
	switch role {
	case Signing:
		if m.key == nil {
			return ErrRole
		}
	case Decryption:
		if m.key == nil {
			return ErrRole
		}
		usage = x509.KeyUsageKeyEncipherment
	case Recipient:
		usage = x509.KeyUsageKeyEncipherment
	case Trust:
	default:
		return ErrRole
	}
	hasUsage := m.cert.KeyUsage != 0
	for _, extension := range m.cert.Extensions {
		if extension.Id.Equal([]int{2, 5, 29, 15}) {
			hasUsage = true
			break
		}
	}
	if hasUsage && m.cert.KeyUsage&usage == 0 {
		return ErrRole
	}
	switch pub := m.cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if pub.N.BitLen() < 2048 {
			return ErrInvalid
		}
	case *ecdsa.PublicKey:
		if role == Recipient || role == Decryption {
			return ErrRole
		}
		if pub.Curve != elliptic.P256() && pub.Curve != elliptic.P384() && pub.Curve != elliptic.P521() {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

// Cache serializes construction-time decoding: concurrent hits are deduplicated
// without an unbounded in-flight map. Failed loads consume no cache capacity.
// Encoded-byte accounting is conservative even though original inputs/passwords
// are not retained. There is no eviction that could conceal exhaustion.
// Construct a Cache with NewCache. Its zero value cannot load material.
type Cache struct {
	mu           sync.Mutex
	secret       [32]byte
	entries      map[[32]byte]*Material
	encodedBytes int
}

func NewCache() *Cache {
	c := &Cache{entries: make(map[[32]byte]*Material)}
	rand.Read(c.secret[:])
	return c
}

// Load returns ErrInvalid when the cache was not initialized by NewCache.
func (c *Cache) Load(in Input, role Role, now time.Time) (*Material, error) {
	if c.entries == nil {
		return nil, ErrInvalid
	}
	for _, n := range []int{len(in.Cert), len(in.Key), len(in.PKCS12), len(in.Password)} {
		if n > MaxInput {
			return nil, ErrLimit
		}
	}
	format := "pem"
	if len(in.PKCS12) > 0 {
		if len(in.Cert) > 0 || len(in.Key) > 0 {
			return nil, ErrInvalid
		}
		format = "pkcs12"
	} else if len(in.Cert) == 0 || in.Password != "" {
		return nil, ErrInvalid
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// Copy before hashing/decoding; callers must not concurrently mutate inputs
	// while Load is copying them, just as with any Go byte-slice API.
	in.Cert = bytes.Clone(in.Cert)
	in.Key = bytes.Clone(in.Key)
	in.PKCS12 = bytes.Clone(in.PKCS12)
	defer clear(in.Key)
	defer clear(in.PKCS12)
	hash := hmac.New(sha256.New, c.secret[:])
	for _, part := range [][]byte{[]byte(format), in.Cert, in.Key, in.PKCS12, []byte(in.Password)} {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(part)))
		hash.Write(size[:])
		hash.Write(part)
	}
	var id [32]byte
	copy(id[:], hash.Sum(nil))
	if entry := c.entries[id]; entry != nil {
		if err := entry.Validate(role, now); err != nil {
			return nil, err
		}
		return entry, nil
	}
	size := len(in.Cert) + len(in.Key) + len(in.PKCS12) + len(in.Password)
	if len(c.entries) >= MaxEntries || size > MaxEncodedBytes-c.encodedBytes {
		return nil, ErrLimit
	}
	entry, err := decode(in)
	if err != nil {
		return nil, ErrInvalid
	}
	if err := entry.Validate(role, now); err != nil {
		return nil, err
	}
	c.entries[id] = entry
	c.encodedBytes += size
	return entry, nil
}
func onePEM(raw []byte) (*pem.Block, error) {
	raw = bytes.TrimSpace(raw)
	if !bytes.HasPrefix(raw, []byte("-----BEGIN ")) || bytes.Count(raw, []byte("-----BEGIN ")) != 1 {
		return nil, ErrInvalid
	}
	block, rest := pem.Decode(raw)
	if block == nil || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrInvalid
	}
	return block, nil
}
func decode(in Input) (*Material, error) {
	m := &Material{}
	var err error
	if len(in.PKCS12) > 0 {
		var chain []*x509.Certificate
		m.key, m.cert, chain, err = pkcs12.DecodeChain(in.PKCS12, in.Password)
		if err != nil {
			return nil, ErrInvalid
		}
		// DecodeChain rejects multiple private keys. Additional certificates must
		// be CA chain material, not additional candidate leaf identities.
		seen := map[string]bool{string(m.cert.Raw): true}
		for _, cert := range chain {
			if !cert.IsCA || seen[string(cert.Raw)] {
				return nil, ErrInvalid
			}
			seen[string(cert.Raw)] = true
		}
	} else {
		block, e := onePEM(in.Cert)
		if e != nil || block.Type != "CERTIFICATE" {
			return nil, ErrInvalid
		}
		m.cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, ErrInvalid
		}
		if len(in.Key) > 0 {
			block, e = onePEM(in.Key)
			if e != nil {
				return nil, ErrInvalid
			}
			switch block.Type {
			case "PRIVATE KEY":
				m.key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			case "RSA PRIVATE KEY":
				m.key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			case "EC PRIVATE KEY":
				m.key, err = x509.ParseECPrivateKey(block.Bytes)
			default:
				return nil, ErrInvalid
			}
			if err != nil {
				return nil, ErrInvalid
			}
		}
	}
	if m.key != nil {
		var pub crypto.PublicKey
		switch key := m.key.(type) {
		case *rsa.PrivateKey:
			if key.Validate() != nil {
				return nil, ErrInvalid
			}
			key.Precompute()
			pub = &key.PublicKey
		case *ecdsa.PrivateKey:
			pub = &key.PublicKey
		default:
			return nil, ErrInvalid
		}
		encoded, e := x509.MarshalPKIXPublicKey(pub)
		if e != nil {
			return nil, ErrInvalid
		}
		expected, e := x509.MarshalPKIXPublicKey(m.cert.PublicKey)
		if e != nil || !bytes.Equal(encoded, expected) {
			return nil, ErrInvalid
		}
	}
	return m, nil
}

// Public and Certificate return detached copies. Callers cannot mutate cached
// big integers, certificate slices or private key precomputation through them.
func (m *Material) Public() crypto.PublicKey {
	cert := m.Certificate()
	if cert == nil {
		return nil
	}
	return cert.PublicKey
}
func (m *Material) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if err := m.Validate(Signing, time.Now()); err != nil {
		return nil, err
	}
	if opts == nil {
		return nil, ErrInvalid
	}
	var signature []byte
	var err error
	switch key := m.key.(type) {
	case *rsa.PrivateKey:
		signature, err = key.Sign(random, digest, opts)
	case *ecdsa.PrivateKey:
		signature, err = key.Sign(random, digest, opts)
	default:
		return nil, ErrRole
	}
	if err != nil {
		return nil, ErrInvalid
	}
	return signature, nil
}
func (m *Material) Decrypt(random io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	if err := m.Validate(Decryption, time.Now()); err != nil {
		return nil, err
	}
	key, ok := m.key.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrRole
	}
	plaintext, err := key.Decrypt(random, ciphertext, opts)
	if err != nil {
		return nil, ErrInvalid
	}
	return plaintext, nil
}
