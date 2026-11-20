// Package wssec contains the candidate XML-security adapter. No public JS
// security behavior is enabled until independent kernel gates pass.
package wssec

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"strings"
	"time"

	"github.com/knroy/go-xml/v2/c14n"
	"github.com/knroy/go-xml/v2/xdm"
	"github.com/knroy/go-xmlsec/v2"
	"github.com/knroy/go-xmlsec/v2/dsig"
	"github.com/knroy/go-xmlsec/v2/wss"
	"github.com/stanimirivanov/xk6-soap/internal/message"
)

var (
	ErrInvalidMessage = errors.New("SOAP_SIGNATURE_INVALID: message rejected")
	ErrKey            = errors.New("SOAP_SIGNATURE_KEY: invalid identity")
	ErrCoverage       = errors.New("SOAP_SIGNATURE_COVERAGE: required node not covered")
)

type Identity struct {
	Certificate *x509.Certificate
	Key         *rsa.PrivateKey
}

// Verified contains only serialization of the actual covered Body, not a
// separately reparsed or reselected application element. No provider node escapes.
type Verified struct {
	Body    []byte
	Created time.Time
	Expires time.Time
}

func certificateOK(cert *x509.Certificate, now time.Time) bool {
	return rsaCertificateOK(cert, now, x509.KeyUsageDigitalSignature)
}
func rsaCertificateOK(cert *x509.Certificate, now time.Time, usage x509.KeyUsage) bool {
	if cert == nil || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return false
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	return ok && pub.N.BitLen() >= 2048 && (cert.KeyUsage == 0 || cert.KeyUsage&usage != 0)
}
func parsed(raw []byte) (*xmlsec.Document, string, error) {
	tree, err := xmlsec.ParseWithLimits(raw, xmlsec.ParseLimits{MaxBytes: 4 << 20, MaxDepth: 64, MaxNodes: 50000})
	if err != nil {
		return nil, "", ErrInvalidMessage
	}
	env := element(tree.Root)
	if env == nil {
		return nil, "", ErrInvalidMessage
	}
	ns := env.Name().URI
	version := "1.1"
	if ns == xmlsec.NSSOAP12 {
		version = "1.2"
	}
	if message.ValidateEnvelope(string(raw), version, message.Limits{}) != nil {
		return nil, "", ErrInvalidMessage
	}
	if err := wss.CheckUniqueIDs(tree.Root, xdm.QName{Local: "Id"}); err != nil {
		return nil, "", ErrInvalidMessage
	}
	return xmlsec.NewDocument(tree.Root), ns, nil
}
func element(root *xdm.Node) *xdm.Node {
	for n := range root.Children() {
		if n.Kind() == xdm.KindElement {
			return n
		}
	}
	return nil
}
func prepare(raw []byte, identity Identity, now time.Time) (*xmlsec.Document, string, error) {
	doc, ns, _, err := prepareSecurity(raw, identity, now)
	return doc, ns, err
}
func prepareSecurity(raw []byte, identity Identity, now time.Time) (*xmlsec.Document, string, *wss.Header, error) {
	if !certificateOK(identity.Certificate, now) || identity.Key == nil || !identity.Key.PublicKey.Equal(identity.Certificate.PublicKey) {
		return nil, "", nil, ErrKey
	}
	doc, ns, err := parsed(raw)
	if err != nil {
		return nil, "", nil, err
	}
	env := element(doc.Root())
	body := env.FirstElement(ns, "Body")
	if _, err := wss.AssignIDWith(doc, body, "body-1"); err != nil {
		return nil, "", nil, ErrInvalidMessage
	}
	header, err := wss.NewHeader(doc, ns, "", true)
	if err != nil {
		return nil, "", nil, ErrInvalidMessage
	}
	if _, err := header.AddTimestampWithID(now, 5*time.Minute, "ts-1"); err != nil {
		return nil, "", nil, ErrInvalidMessage
	}
	if _, err := header.AddBinarySecurityTokenWithID(identity.Certificate, nil, xmlsec.BSTValueTypeX509v3, "bst-1"); err != nil {
		return nil, "", nil, ErrInvalidMessage
	}
	return doc, ns, header, nil
}

// Sign uses fixed IDs scoped to a single message, and the caller's clock.
// Every request is freshly timestamped; wire bytes must be sent unchanged.
func Sign(raw []byte, identity Identity, now time.Time, inclusivePrefixes ...string) (wire []byte, err error) {
	defer func() {
		if recover() != nil {
			wire = nil
			err = ErrInvalidMessage
		}
	}()
	doc, ns, err := prepare(raw, identity, now)
	if err != nil {
		return nil, err
	}
	security, err := wss.FindHeader(doc.Root(), ns, "")
	if err != nil {
		return nil, ErrInvalidMessage
	}
	if len(inclusivePrefixes) > 16 {
		return nil, ErrInvalidMessage
	}
	env := element(doc.Root())
	for _, prefix := range inclusivePrefixes {
		if prefix != "" && !xdm.IsNCName(prefix) {
			return nil, ErrInvalidMessage
		}
		if _, ok := env.LookupPrefix(prefix); !ok && prefix != "" {
			return nil, ErrInvalidMessage
		}
	}
	transform := []dsig.TransformSpec{{Algorithm: string(c14n.Exclusive10), InclusiveNamespacePrefixes: inclusivePrefixes}}
	_, err = dsig.Sign(doc, xmlsec.KeyProvider{Signer: identity.Key, Certificate: identity.Certificate}, dsig.SignOptions{
		SignatureAlgorithm: xmlsec.SigRSASHA256, CanonicalizationAlgorithm: string(c14n.Exclusive10), CanonicalizationPrefixes: inclusivePrefixes,
		References: []dsig.Reference{
			{URI: "#body-1", DigestAlgorithm: xmlsec.DigestSHA256, Transforms: transform},
			{URI: "#ts-1", DigestAlgorithm: xmlsec.DigestSHA256, Transforms: transform},
		}, KeyInfo: dsig.KeyInfoSecurityTokenReference, SecurityTokenID: "bst-1", SignatureID: "sig-1", Parent: security,
	})
	if err != nil {
		return nil, ErrInvalidMessage
	}
	wire, err = c14n.Bytes(doc.Root(), c14n.Options{Algorithm: c14n.Inclusive10WithComments})
	if err != nil || len(wire) > 4<<20 {
		return nil, ErrInvalidMessage
	}
	return wire, nil
}

func Verify(raw []byte, trust *x509.Certificate, now time.Time) (result *Verified, err error) {
	defer func() {
		if recover() != nil {
			result = nil
			err = ErrInvalidMessage
		}
	}()
	if !certificateOK(trust, now) {
		return nil, ErrKey
	}
	doc, ns, err := parsed(raw)
	if err != nil {
		return nil, err
	}
	return verifyDocument(doc, ns, trust, now, nil)
}

// verifyDocument checks coverage on this exact immutable snapshot. Encryption
// callers may permit one previously validated EncryptedKey and Body ciphertext.
func verifyDocument(doc *xmlsec.Document, ns string, trust *x509.Certificate, now time.Time, encryptedKey *xdm.Node) (*Verified, error) {
	return verifyDocumentCore(doc, ns, trust, now, encryptedKey, encryptedKey != nil)
}
func verifyRecovered(doc *xmlsec.Document, ns string, trust *x509.Certificate, now time.Time) (*Verified, error) {
	return verifyDocumentCore(doc, ns, trust, now, nil, true)
}
func verifyDocumentCore(doc *xmlsec.Document, ns string, trust *x509.Certificate, now time.Time, encryptedKey *xdm.Node, permitEncryption bool) (*Verified, error) {
	env := element(doc.Root())
	body := env.FirstElement(ns, "Body")
	security, err := wss.FindHeader(doc.Root(), ns, "")
	if err != nil || security == nil {
		return nil, ErrInvalidMessage
	}
	stamp, err := wss.FindTimestamp(security)
	if err != nil || stamp == nil {
		return nil, ErrCoverage
	}
	signature := security.FirstElement(xmlsec.NSDSig, "Signature")
	if signature == nil {
		return nil, ErrCoverage
	}
	count := 0
	var walk func(*xdm.Node) bool
	walk = func(n *xdm.Node) bool {
		if n.IsElement(xmlsec.NSDSig, "Signature") {
			count++
		}
		if !permitEncryption && (n.IsElement(xmlsec.NSXEnc, "EncryptedData") || n.IsElement(xmlsec.NSXEnc, "EncryptedKey")) {
			return false
		}
		for c := range n.Children() {
			if !walk(c) {
				return false
			}
		}
		return true
	}
	references := 2
	if encryptedKey != nil {
		references = 3
	}
	if !walk(doc.Root()) || count != 1 || !signaturePolicy(signature, references) {
		return nil, ErrInvalidMessage
	}
	coverage, err := dsig.Verify(doc.Root(), signature, dsig.VerifyOptions{
		Certificate: trust, AllowedSignatureAlgorithms: []string{xmlsec.SigRSASHA256}, AllowedDigestAlgorithms: []string{xmlsec.DigestSHA256},
		AllowedCanonicalizationAlgorithms: []string{string(c14n.Exclusive10)}, MaxReferences: references,
		StrictBSP: true, RequireExplicitCanonicalization: true, IDAttributes: []xdm.QName{dsig.IDAttrDSig},
	})
	if err != nil {
		return nil, ErrInvalidMessage
	}
	if !coverage.CoversNodes(body, stamp) || encryptedKey != nil && !coverage.CoversNodes(encryptedKey) {
		return nil, ErrCoverage
	}
	timestamp, err := wss.ParseTimestamp(stamp)
	if err != nil || timestamp.Expires.IsZero() || !timestamp.Expires.After(timestamp.Created) || timestamp.Expires.Sub(timestamp.Created) > 5*time.Minute || timestamp.Check(now, time.Minute, 5*time.Minute) != nil {
		return nil, ErrInvalidMessage
	}
	// Strict STR compares the referenced certificate to the supplied trust. Enforce
	// exact DER identity as well, not just equivalent public keys.
	bst := security.FirstElement(xmlsec.NSWSSE, "BinarySecurityToken")
	if bst == nil {
		return nil, ErrInvalidMessage
	}
	cert, err := wss.ParseBinarySecurityToken(bst)
	if err != nil || !bytes.Equal(cert.Raw, trust.Raw) {
		return nil, ErrKey
	}
	// Return exactly the Body reference's canonical octets, including its
	// verified InclusiveNamespaces parameters. Dropping these at consumption
	// would erase namespace bindings used only in signed QName-valued data.
	var prefixes []string
	for _, reference := range coverage.References {
		target, resolveErr := wss.FindByID(doc.Root(), strings.TrimPrefix(reference.URI, "#"), dsig.IDAttrDSig)
		if resolveErr != nil {
			return nil, ErrInvalidMessage
		}
		if target != nil && target.Is(body) {
			prefixes = reference.Transforms[0].InclusiveNamespacePrefixes
			break
		}
	}
	consumed, err := c14n.Bytes(body, c14n.Options{Algorithm: c14n.Exclusive10, InclusiveNamespacePrefixes: prefixes})
	if err != nil || len(consumed) > 4<<20 {
		return nil, ErrInvalidMessage
	}
	return &Verified{Body: consumed, Created: timestamp.Created, Expires: timestamp.Expires}, nil
}
func signaturePolicy(signature *xdm.Node, required int) bool {
	info := signature.FirstElement(xmlsec.NSDSig, "SignedInfo")
	if info == nil {
		return false
	}
	method := info.FirstElement(xmlsec.NSDSig, "CanonicalizationMethod")
	if method == nil || !prefixPolicy(method) {
		return false
	}
	references := 0
	for ref := range info.Children() {
		if !ref.IsElement(xmlsec.NSDSig, "Reference") {
			continue
		}
		references++
		uri := ref.AttrValue("URI")
		if !strings.HasPrefix(uri, "#") || !xdm.IsNCName(strings.TrimPrefix(uri, "#")) {
			return false
		}
		transforms := ref.FirstElement(xmlsec.NSDSig, "Transforms")
		if transforms == nil {
			return false
		}
		count := 0
		for transform := range transforms.Children() {
			if transform.Kind() != xdm.KindElement {
				continue
			}
			count++
			if !transform.IsElement(xmlsec.NSDSig, "Transform") || transform.AttrValue("Algorithm") != string(c14n.Exclusive10) {
				return false
			}
			if !prefixPolicy(transform) {
				return false
			}
		}
		if count != 1 {
			return false
		}
	}
	return references == required
}

func prefixPolicy(parent *xdm.Node) bool {
	count := 0
	for parameter := range parent.Children() {
		if parameter.Kind() != xdm.KindElement {
			continue
		}
		count++
		if !parameter.IsElement(string(c14n.Exclusive10), "InclusiveNamespaces") {
			return false
		}
		value := parameter.AttrValue("PrefixList")
		if len(value) > 1024 || len(strings.Fields(value)) > 16 {
			return false
		}
		seen := map[string]bool{}
		for _, prefix := range strings.Fields(value) {
			if prefix == "#default" {
				prefix = ""
			}
			if seen[prefix] || prefix != "" && !xdm.IsNCName(prefix) {
				return false
			}
			seen[prefix] = true
			if _, ok := parameter.LookupPrefix(prefix); !ok && prefix != "" {
				return false
			}
		}
	}
	return count <= 1
}
