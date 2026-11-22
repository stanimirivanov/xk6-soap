package wssec

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/knroy/go-xml/v2/xdm"
	"github.com/stanimirivanov/xk6-soap/internal/keys"
)

var (
	ErrPolicy      = errors.New("SOAP_POLICY_INVALID")
	ErrPolicyKey   = errors.New("SOAP_POLICY_KEY")
	ErrUnavailable = errors.New("SOAP_FEATURE_UNAVAILABLE")
)

type UsernameTokenPolicy struct {
	User         string
	Password     string
	PasswordType string
}
type TimestampOptions struct {
	TTLSeconds         *int
	ClockOffsetSeconds *int
}
type TimestampPolicy struct {
	TTLSeconds         int
	ClockOffsetSeconds int
}
type SigningPolicy struct {
	Algorithm        string
	Digest           string
	Canonicalization string
	KeyID            string
	Headers          []string
}
type EncryptionPolicy struct {
	Algorithm    string
	KeyTransport string
	Target       string
	Headers      []string
}
type ExpandedName struct {
	Namespace string
	LocalName string
}
type ReceiveOptions struct {
	Signature           *bool
	Timestamp           *bool
	RequireEncryption   *bool
	Order               string
	SignatureAlgorithms []string
	DigestAlgorithms    []string
	SignedHeaders       []ExpandedName
	EncryptedHeaders    []ExpandedName
	ClockSkewSeconds    *int
	MaxAgeSeconds       *int
}

// ReceivePolicy holds the normalized requirements for inbound SOAP responses.
// Use the Receive field of the [Policy] returned by [CompilePolicy], including
// for plain exchanges. The zero value omits the default algorithm allow-lists.
type ReceivePolicy struct {
	Signature           bool
	Timestamp           bool
	RequireEncryption   bool
	Order               string
	SignatureAlgorithms []string
	DigestAlgorithms    []string
	SignedHeaders       []ExpandedName
	EncryptedHeaders    []ExpandedName
	ClockSkewSeconds    int
	MaxAgeSeconds       int
}
type SecurityOptions struct {
	UsernameToken *UsernameTokenPolicy
	Timestamp     *TimestampOptions
	Sign          *SigningPolicy
	Encrypt       *EncryptionPolicy
	Order         string
	Verify        *ReceiveOptions
}
type KeyMaterial struct {
	Signing    *keys.Material
	Decryption *keys.Material
	Recipient  *keys.Material
	Trust      []*keys.Material
}

// Policy is a client-owned normalized value. All slices/blocks are copied from
// options. It defines requirements, not evidence that protection was performed.
type Policy struct {
	UsernameToken *UsernameTokenPolicy
	Timestamp     *TimestampPolicy
	Sign          *SigningPolicy
	Encrypt       *EncryptionPolicy
	Order         string
	Receive       ReceivePolicy
}

var signatureKeyIDs = []string{directKeyID, "issuer-serial", "x509keyidentifier", "ski", "ThumbprintSHA1"}
var signatureAlgorithms = []string{"rsa-sha256", "rsa-sha384", "rsa-sha512", "ecdsa-sha256", "ecdsa-sha384", "ecdsa-sha512"}
var digestAlgorithms = []string{"sha256", "sha384", "sha512"}

// CompilePolicy normalizes options, validates their combinations and checks
// the required key roles at the supplied time. Call [Policy.RequireAvailable]
// on the result to check that the requested profile is supported.
//
// When omitted, receive signature verification defaults to whether outbound
// signing is configured. Timestamp freshness defaults to the resulting receive
// signature setting, with 60 seconds of clock skew and a maximum age of
// 300 seconds. Body encryption is optional by default. Receive signature
// and digest allow-lists default to RSA-SHA256 and SHA-256 independently
// of the outbound algorithms.
//
// Explicit settings override the defaults subject to validation. Freshness,
// required Body encryption and required signed or encrypted headers all
// require signature verification. Required signature verification needs
// configured trust pins with at least one compatible signature algorithm.
// Required Body or header encryption needs a decryption identity. Any
// decryption identity requires an explicit receive protection order.
func CompilePolicy(in SecurityOptions, material KeyMaterial, now time.Time) (Policy, error) {
	p := Policy{Order: in.Order}
	if in.UsernameToken != nil {
		token := *in.UsernameToken
		if token.PasswordType == "" {
			token.PasswordType = "PasswordDigest"
		}
		if token.User == "" || len(token.User) > 4<<20 || len(token.Password) > 4<<20 || !xmlText(token.User) || !utf8.ValidString(token.Password) || !slices.Contains([]string{"PasswordDigest", "PasswordText"}, token.PasswordType) || token.PasswordType == "PasswordText" && !xmlText(token.Password) {
			return Policy{}, ErrPolicy
		}
		p.UsernameToken = &token
	}
	if in.Timestamp != nil || in.UsernameToken != nil || in.Sign != nil {
		opts := TimestampOptions{}
		if in.Timestamp != nil {
			opts = *in.Timestamp
		}
		ttl, ok := integer(opts.TTLSeconds, 300, 1, 3600)
		if !ok {
			return Policy{}, ErrPolicy
		}
		offset, ok := integer(opts.ClockOffsetSeconds, 0, -300, 300)
		if !ok {
			return Policy{}, ErrPolicy
		}
		p.Timestamp = &TimestampPolicy{TTLSeconds: ttl, ClockOffsetSeconds: offset}
	}
	if in.Sign != nil {
		sign := *in.Sign
		sign.Headers = slices.Clone(sign.Headers)
		sign.Algorithm = defaultString(sign.Algorithm, "rsa-sha256")
		sign.Digest = defaultString(sign.Digest, "sha256")
		sign.Canonicalization = defaultString(sign.Canonicalization, "exclusive-c14n")
		sign.KeyID = defaultString(sign.KeyID, directKeyID)
		if sign.KeyID == "direct" {
			sign.KeyID = directKeyID
		}
		if !slices.Contains(signatureAlgorithms, sign.Algorithm) || !slices.Contains(digestAlgorithms, sign.Digest) || sign.Canonicalization != "exclusive-c14n" || !slices.Contains(signatureKeyIDs, sign.KeyID) || !selectors(sign.Headers) {
			return Policy{}, ErrPolicy
		}
		p.Sign = &sign
	}
	if in.Encrypt != nil {
		enc := *in.Encrypt
		enc.Headers = slices.Clone(enc.Headers)
		enc.Algorithm = defaultString(enc.Algorithm, "aes-256-gcm")
		enc.KeyTransport = defaultString(enc.KeyTransport, "rsa-oaep-sha256")
		enc.Target = defaultString(enc.Target, "content")
		if !slices.Contains([]string{"aes-128-gcm", "aes-256-gcm"}, enc.Algorithm) || enc.KeyTransport != "rsa-oaep-sha256" || !slices.Contains([]string{"body", "content", "headers"}, enc.Target) || !selectors(enc.Headers) {
			return Policy{}, ErrPolicy
		}
		if enc.Target == "headers" && len(enc.Headers) == 0 || enc.Target != "headers" && enc.Headers != nil {
			return Policy{}, ErrPolicy
		}
		p.Encrypt = &enc
	}
	if p.Sign != nil && p.Encrypt != nil {
		p.Order = defaultString(p.Order, string(SignThenEncrypt))
		if !validOrder(p.Order) {
			return Policy{}, ErrPolicy
		}
	} else if p.Order != "" {
		return Policy{}, ErrPolicy
	}
	opts := ReceiveOptions{}
	if in.Verify != nil {
		opts = *in.Verify
	}
	receive := ReceivePolicy{Signature: defaultBool(opts.Signature, p.Sign != nil), RequireEncryption: defaultBool(opts.RequireEncryption, false), Order: opts.Order}
	receive.Timestamp = defaultBool(opts.Timestamp, receive.Signature)
	receive.SignatureAlgorithms = slices.Clone(opts.SignatureAlgorithms)
	if opts.SignatureAlgorithms == nil {
		receive.SignatureAlgorithms = []string{"rsa-sha256"}
	}
	receive.DigestAlgorithms = slices.Clone(opts.DigestAlgorithms)
	if opts.DigestAlgorithms == nil {
		receive.DigestAlgorithms = []string{"sha256"}
	}
	if !algorithmList(receive.SignatureAlgorithms, signatureAlgorithms) || !algorithmList(receive.DigestAlgorithms, digestAlgorithms) {
		return Policy{}, ErrPolicy
	}
	receive.SignedHeaders = slices.Clone(opts.SignedHeaders)
	receive.EncryptedHeaders = slices.Clone(opts.EncryptedHeaders)
	if !expandedNames(receive.SignedHeaders) || !expandedNames(receive.EncryptedHeaders) {
		return Policy{}, ErrPolicy
	}
	var ok bool
	receive.ClockSkewSeconds, ok = integer(opts.ClockSkewSeconds, 60, 0, 300)
	if !ok {
		return Policy{}, ErrPolicy
	}
	receive.MaxAgeSeconds, ok = integer(opts.MaxAgeSeconds, 300, 1, 3600)
	if !ok {
		return Policy{}, ErrPolicy
	}
	if (receive.Timestamp || receive.RequireEncryption || len(receive.SignedHeaders) > 0 || len(receive.EncryptedHeaders) > 0) && !receive.Signature {
		return Policy{}, ErrPolicy
	}
	if (receive.RequireEncryption || len(receive.EncryptedHeaders) > 0) && material.Decryption == nil {
		return Policy{}, ErrPolicyKey
	}
	if receive.Order != "" && (!validOrder(receive.Order) || material.Decryption == nil) {
		return Policy{}, ErrPolicy
	}
	if material.Decryption != nil && receive.Order == "" {
		return Policy{}, ErrPolicy
	}
	p.Receive = receive
	if p.Sign != nil {
		if !validKey(material.Signing, keys.Signing, now) || !compatible(material.Signing, p.Sign.Algorithm) {
			return Policy{}, ErrPolicyKey
		}
		if p.Sign.KeyID == "ski" && len(material.Signing.Certificate().SubjectKeyId) == 0 {
			return Policy{}, ErrPolicyKey
		}
	}
	if p.Encrypt != nil && !validKey(material.Recipient, keys.Recipient, now) {
		return Policy{}, ErrPolicyKey
	}
	if material.Decryption != nil && !validKey(material.Decryption, keys.Decryption, now) {
		return Policy{}, ErrPolicyKey
	}
	if receive.Signature {
		if len(material.Trust) == 0 || len(material.Trust) > 8 {
			return Policy{}, ErrPolicyKey
		}
		matched := false
		for _, pin := range material.Trust {
			if !validKey(pin, keys.Trust, now) {
				return Policy{}, ErrPolicyKey
			}
			for _, algorithm := range receive.SignatureAlgorithms {
				matched = matched || compatible(pin, algorithm)
			}
		}
		if !matched {
			return Policy{}, ErrPolicyKey
		}
	}
	return p, nil
}

// RequireAvailable checks whether the configured signature and encryption
// profiles are supported.
func (p Policy) RequireAvailable() error {
	if s := p.Sign; s != nil && (signatureURIs[s.Algorithm] == "" || digestURIs[s.Digest] == "" || s.Canonicalization != "exclusive-c14n" || !slices.Contains(signatureKeyIDs, s.KeyID)) {
		return ErrUnavailable
	}

	if r := p.Receive; r.Signature && (!algorithmList(r.SignatureAlgorithms, signatureAlgorithms) || !algorithmList(r.DigestAlgorithms, digestAlgorithms)) {
		return ErrUnavailable
	}

	if e := p.Encrypt; e != nil && (p.Sign == nil || !validOrder(p.Order) || (e.Target != "content" && e.Target != "body" && e.Target != "headers") || (e.Target == "headers") != (len(e.Headers) != 0) || e.KeyTransport != "rsa-oaep-sha256" || (e.Algorithm != "aes-128-gcm" && e.Algorithm != "aes-256-gcm")) {
		return ErrUnavailable
	}
	if r := p.Receive; (r.RequireEncryption || len(r.EncryptedHeaders) != 0 || r.Order != "") && (!r.Signature || !validOrder(r.Order)) {
		return ErrUnavailable
	}
	return nil
}

// DiagnosticAlgorithm is an allow-list projection, never a policy/credential dump.
func (p Policy) DiagnosticAlgorithm() string {
	if p.Sign != nil {
		if slices.Contains(signatureAlgorithms, p.Sign.Algorithm) {
			return p.Sign.Algorithm
		}
		return "unavailable"
	}
	if p.Encrypt != nil {
		if slices.Contains([]string{"aes-128-gcm", "aes-256-gcm"}, p.Encrypt.Algorithm) {
			return p.Encrypt.Algorithm
		}
		return "unavailable"
	}
	if p.UsernameToken != nil {
		return "username-token"
	}
	if p.Timestamp != nil {
		return "timestamp"
	}
	return "plain"
}
func validKey(m *keys.Material, role keys.Role, now time.Time) bool {
	return m != nil && m.Validate(role, now) == nil
}
func compatible(m *keys.Material, algorithm string) bool {
	if m == nil {
		return false
	}
	return compatiblePublicKey(m.Public(), algorithm)
}

func compatiblePublicKey(key any, algorithm string) bool {
	switch pub := key.(type) {
	case *rsa.PublicKey:
		return pub.N.BitLen() >= 2048 && (algorithm == "rsa-sha256" || algorithm == "rsa-sha384" || algorithm == "rsa-sha512")
	case *ecdsa.PublicKey:
		return algorithm == "ecdsa-sha256" && pub.Curve == elliptic.P256() || algorithm == "ecdsa-sha384" && pub.Curve == elliptic.P384() || algorithm == "ecdsa-sha512" && pub.Curve == elliptic.P521()
	}
	return false
}
func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
func defaultBool(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}
func integer(value *int, fallback, min, max int) (int, bool) {
	if value == nil {
		return fallback, true
	}
	return *value, *value >= min && *value <= max
}
func validOrder(order string) bool {
	return order == string(SignThenEncrypt) || order == string(EncryptThenSign)
}
func selectors(names []string) bool {
	if len(names) > 16 {
		return false
	}
	seen := map[string]bool{}
	for _, name := range names {
		if len(name) > 4096 || !utf8.ValidString(name) || !xdm.IsNCName(name) || seen[name] {
			return false
		}
		seen[name] = true
	}
	return true
}
func expandedNames(names []ExpandedName) bool {
	if len(names) > 16 {
		return false
	}
	seen := map[ExpandedName]bool{}
	for _, name := range names {
		if name.Namespace == "" || len(name.Namespace) > 4096 || !xmlText(name.Namespace) || len(name.LocalName) > 4096 || !utf8.ValidString(name.LocalName) || !xdm.IsNCName(name.LocalName) || seen[name] {
			return false
		}
		seen[name] = true
	}
	return true
}
func algorithmList(values, allowed []string) bool {
	if len(values) == 0 || len(values) > len(allowed) {
		return false
	}
	seen := map[string]bool{}
	for _, value := range values {
		if !slices.Contains(allowed, value) || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}
func xmlText(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if !(r == 9 || r == 10 || r == 13 || r >= 32 && r <= 0xd7ff || r >= 0xe000 && r <= 0xfffd || r >= 0x10000 && r <= 0x10ffff) {
			return false
		}
	}
	return true
}
