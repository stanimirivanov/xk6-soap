package wssec

import (
	"bytes"
	"crypto/sha1" // OASIS UsernameToken PasswordDigest, never XML signatures.
	"encoding/base64"
	"errors"
	"io"
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
	return BuildSecurity(raw, p, nil, now, random, override, limits)
}

// BuildSecurity constructs credentials and signatures in one request-local tree.
// Only the completed tree is serialized to wire bytes.
func BuildSecurity(raw []byte, p Policy, signing *keys.Material, now time.Time, random io.Reader, override *Credentials, limits message.Limits, selectors ...message.HeaderSelector) (wire []byte, err error) {
	defer func() {
		if recover() != nil {
			wire = nil
			err = ErrCredentialBuild
		}
	}()
	if err = p.RequireAvailable(); err != nil {
		return nil, err
	}
	if p.Sign != nil {
		if signing == nil || signing.Validate(keys.Signing, now) != nil || !certificateOK(signing.Certificate(), now) {
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
	if p.Sign != nil {
		if e = appendSignature(doc, ns, header, signing, p.UsernameToken != nil, p.Sign.Headers, selectors); e != nil {
			return nil, e
		}
	}
	if wss.CheckUniqueIDs(doc.Root(), xdm.QName{Local: "Id"}) != nil {
		return nil, ErrCredentialBuild
	}
	output := limitedXML{max: limits.Bytes}
	if e = c14n.Write(&output, doc.Root(), c14n.Options{Algorithm: c14n.Inclusive10WithComments}); e != nil {
		if output.exceeded {
			return nil, ErrOutputLimit
		}
		return nil, ErrCredentialBuild
	}
	wire = output.Bytes()
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

// Unlike io.ReadFull, retain an error reported with a complete final read.
// At most 16 progressing reads are possible; zero progress fails closed.
func freshTokenNonce(random io.Reader) ([]byte, error) {
	if random == nil {
		return nil, ErrRandom
	}
	nonce := make([]byte, 16)
	for offset := 0; offset < len(nonce); {
		n, err := random.Read(nonce[offset:])
		if err != nil || n <= 0 || n > len(nonce)-offset {
			return nil, ErrRandom
		}
		offset += n
	}
	return nonce, nil
}
