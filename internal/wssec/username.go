package wssec

import (
	"bytes"
	"crypto/sha1" // OASIS UsernameToken PasswordDigest, never XML signatures.
	"encoding/base64"
	"errors"
	"io"
	"slices"
	"time"

	"github.com/knroy/go-xml/v2/c14n"
	"github.com/knroy/go-xml/v2/xdm"
	"github.com/knroy/go-xmlsec/v2"
	"github.com/knroy/go-xmlsec/v2/wss"
	"github.com/stanimirivanov/xk6-soap/internal/keys"
	"github.com/stanimirivanov/xk6-soap/internal/message"
)

var (
	ErrRandom          = errors.New("SOAP_RANDOM_FAILED")
	ErrCredentialBuild = errors.New("SOAP_CREDENTIAL_BUILD_FAILED")
	ErrOutputLimit     = errors.New("LIMIT_EXCEEDED")
)

type Credentials struct {
	User     string
	Password string
}

const tokenProfile = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#"
const base64Encoding = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"

// BuildCredentials owns a fresh tree per call. Time/randomness are internal Go
// seams; the public Client always supplies time.Now and crypto/rand.Reader.
func BuildCredentials(raw []byte, p Policy, now time.Time, random io.Reader, override *Credentials, limits message.Limits) ([]byte, error) {
	return BuildSecurity(raw, p, KeyMaterial{}, now, random, override, limits)
}

// BuildSecurity constructs credentials and signatures in one request-local tree.
// Only the completed tree is serialized to wire bytes.
func BuildSecurity(raw []byte, p Policy, material KeyMaterial, now time.Time, random io.Reader, override *Credentials, limits message.Limits, selectors ...message.HeaderSelector) (wire []byte, err error) {
	defer func() {
		if recover() != nil {
			wire = nil
			err = ErrCredentialBuild
		}
	}()
	if err = p.RequireAvailable(); err != nil {
		return nil, err
	}
	signing := material.Signing
	if p.Encrypt != nil && !validKey(material.Recipient, keys.Recipient, now) {
		return nil, ErrPolicyKey
	}
	if p.Sign != nil {
		if signing == nil || signing.Validate(keys.Signing, now) != nil || !compatible(signing, p.Sign.Algorithm) {
			return nil, ErrPolicyKey
		}
		if p.Timestamp == nil {
			return nil, ErrPolicy
		}
	}
	if p.Timestamp == nil {
		if override != nil || p.UsernameToken != nil {
			return nil, ErrPolicy
		}
		return bytes.Clone(raw), nil
	}
	effective := p.UsernameToken
	if override != nil {
		if effective == nil {
			return nil, ErrPolicy
		}
		token := *effective
		token.User = override.User
		token.Password = override.Password
		effective = &token
	}
	if effective != nil {
		normalized, e := CompilePolicy(SecurityOptions{UsernameToken: effective}, KeyMaterial{}, now)
		if e != nil {
			return nil, e
		}
		effective = normalized.UsernameToken
	}
	limits, e := limits.Normalized()
	if e != nil {
		return nil, ErrOutputLimit
	}
	doc, ns, e := parsed(raw)
	if e != nil {
		return nil, ErrCredentialBuild
	}
	header, e := wss.NewHeader(doc, ns, "", true)
	if e != nil {
		return nil, ErrCredentialBuild
	}
	created, e := appendTimestamp(header, *p.Timestamp, now)
	if e != nil {
		return nil, e
	}
	if effective != nil {
		nonce, e := freshTokenNonce(random)
		if e != nil {
			return nil, e
		}
		value := effective.Password
		if effective.PasswordType == "PasswordDigest" {
			digest := sha1.New()
			digest.Write(nonce)
			digest.Write([]byte(created))
			digest.Write([]byte(effective.Password))
			value = base64.StdEncoding.EncodeToString(digest.Sum(nil))
		}
		token := xdm.NewNode(xdm.KindElement, xdm.QName{URI: xmlsec.NSWSSE, Prefix: "wsse", Local: "UsernameToken"}, "")
		token.AddNamespace("wsse", xmlsec.NSWSSE)
		token.AddNamespace("wsu", xmlsec.NSWSU)
		token.AppendAttr(xdm.QName{URI: xmlsec.NSWSU, Prefix: "wsu", Local: "Id"}, "ut-1")
		token.AppendElement(xdm.QName{URI: xmlsec.NSWSSE, Prefix: "wsse", Local: "Username"}).AppendText(effective.User)
		password := token.AppendElement(xdm.QName{URI: xmlsec.NSWSSE, Prefix: "wsse", Local: "Password"})
		password.AppendAttr(xdm.QName{Local: "Type"}, tokenProfile+effective.PasswordType)
		password.AppendText(value)
		n := token.AppendElement(xdm.QName{URI: xmlsec.NSWSSE, Prefix: "wsse", Local: "Nonce"})
		n.AppendAttr(xdm.QName{Local: "EncodingType"}, base64Encoding)
		n.AppendText(base64.StdEncoding.EncodeToString(nonce))
		token.AppendElement(xdm.QName{URI: xmlsec.NSWSU, Prefix: "wsu", Local: "Created"}).AppendText(created)
		if header.Prepend(token) != nil {
			return nil, ErrCredentialBuild
		}
	}
	encryptFirst := p.Encrypt != nil && p.Order == string(EncryptThenSign)
	var encryptedSlots []int
	signingPolicy := p.Sign
	signingSelectors := selectors
	if p.Encrypt != nil && p.Encrypt.Target == "headers" {
		encryptedSlots, e = selectEncryptedHeaders(doc, ns, p.Encrypt.Headers, selectors)
		if e != nil {
			return nil, e
		}
		sig := *p.Sign
		sig.Headers = slices.Clone(sig.Headers)
		if encryptFirst {
			sig.Headers = slices.DeleteFunc(sig.Headers, func(name string) bool { return slices.Contains(p.Encrypt.Headers, name) })
			signingSelectors = slices.DeleteFunc(slices.Clone(selectors), func(sel message.HeaderSelector) bool { return slices.Contains(p.Encrypt.Headers, sel.Name) })
		} else {
			for _, name := range p.Encrypt.Headers {
				if !slices.Contains(sig.Headers, name) {
					sig.Headers = append(sig.Headers, name)
				}
			}
		}
		signingPolicy = &sig
	}

	var keyInfo *xdm.Node
	if p.Sign != nil {
		keyInfo, e = signingTokenReference(p.Sign.KeyID, signing.Certificate())
		if e != nil {
			return nil, ErrSignatureBuild
		}
		if keyInfo == nil {
			if _, e = header.AddBinarySecurityTokenWithID(signing.Certificate(), nil, xmlsec.BSTValueTypeX509v3, "bst-1"); e != nil {
				return nil, ErrSignatureBuild
			}
		}
	}
	if encryptFirst {
		encrypted, err := encryptRequest(doc, ns, header, p.Encrypt, material.Recipient.Certificate(), random, limits, encryptedSlots)
		if err != nil {
			return nil, err
		}
		if len(encrypted) > limits.Bytes {
			return nil, ErrOutputLimit
		}
		doc, ns, e = parsed(encrypted)
		if e != nil {
			return nil, ErrEncryptionBuild
		}
	}
	if p.Sign != nil {
		if e = appendSignature(doc, ns, signing, p.UsernameToken != nil, signingPolicy, keyInfo, encryptFirst, signingSelectors); e != nil {
			return nil, e
		}
	}
	if wss.CheckUniqueIDs(doc.Root(), xdm.QName{Local: "Id"}) != nil {
		return nil, ErrCredentialBuild
	}
	if p.Encrypt != nil && !encryptFirst {
		wire, e = encryptRequest(doc, ns, header, p.Encrypt, material.Recipient.Certificate(), random, limits, encryptedSlots)
		if e != nil {
			return nil, e
		}
	} else {
		root := doc.Root()
		if encryptFirst {
			// WSS4J processes these siblings in wire order. Keep the signature
			// before the key without moving any signed node to a new context.
			root = signatureBeforeKey(root, ns)
		}
		output := limitedXML{max: limits.Bytes}
		if e = c14n.Write(&output, root, c14n.Options{Algorithm: c14n.Inclusive10WithComments}); e != nil {
			if output.exceeded {
				return nil, ErrOutputLimit
			}
			return nil, ErrCredentialBuild
		}
		wire = output.Bytes()
	}
	version := "1.1"
	if ns == xmlsec.NSSOAP12 {
		version = "1.2"
	}
	if message.ValidateEnvelope(string(wire), version, limits) != nil {
		return nil, ErrOutputLimit
	}
	return wire, nil
}

// appendTimestamp is the provider adapter. It returns the exact serialized
// Created used for the digest, rather than independently formatting that value.
func appendTimestamp(header *wss.Header, p TimestampPolicy, now time.Time) (string, error) {
	if p.TTLSeconds < 1 || p.TTLSeconds > 3600 || p.ClockOffsetSeconds < -300 || p.ClockOffsetSeconds > 300 {
		return "", ErrPolicy
	}
	adjusted := now.UTC().Add(time.Duration(p.ClockOffsetSeconds) * time.Second)
	if adjusted.Year() < 1 || adjusted.Year() > 9999 || adjusted.Add(time.Duration(p.TTLSeconds)*time.Second).Year() > 9999 {
		return "", ErrPolicy
	}
	if _, err := header.AddTimestampWithID(adjusted, time.Duration(p.TTLSeconds)*time.Second, "ts-1"); err != nil {
		return "", ErrCredentialBuild
	}
	ts := header.Element().FirstElement(xmlsec.NSWSU, "Timestamp")
	return ts.FirstElement(xmlsec.NSWSU, "Created").StringValue(), nil
}

type limitedXML struct {
	bytes.Buffer
	max      int
	exceeded bool
}

func (w *limitedXML) Write(p []byte) (int, error) {
	if len(p) > w.max-w.Len() {
		w.exceeded = true
		return 0, ErrOutputLimit
	}
	return w.Buffer.Write(p)
}

func freshTokenNonce(random io.Reader) ([]byte, error) {
	nonce := make([]byte, 16)
	if err := readRandom(random, nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

// Unlike io.ReadFull, retain an error reported with a complete final read.
// Zero progress fails closed instead of looping.
func readRandom(random io.Reader, buf []byte) error {
	if random == nil {
		return ErrRandom
	}
	for len(buf) > 0 {
		n, err := random.Read(buf)
		if err != nil || n <= 0 || n > len(buf) {
			return ErrRandom
		}
		buf = buf[n:]
	}
	return nil
}
