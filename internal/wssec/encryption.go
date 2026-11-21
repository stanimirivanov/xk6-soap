package wssec

import (
	"crypto/x509"
	"errors"
	"strings"
	"time"

	"github.com/knroy/go-xml/v2/c14n"
	"github.com/knroy/go-xml/v2/xdm"
	"github.com/knroy/go-xmlsec/v2"
	"github.com/knroy/go-xmlsec/v2/dsig"
	"github.com/knroy/go-xmlsec/v2/wss"
	"github.com/knroy/go-xmlsec/v2/xenc"
)

type ProtectionOrder string

const (
	SignThenEncrypt ProtectionOrder = "sign-then-encrypt"
	EncryptThenSign ProtectionOrder = "encrypt-then-sign"
)

var ErrEncryption = errors.New("SOAP_ENCRYPTION_INVALID: message rejected")

func encryptionAlgorithm(bits int) string {
	switch bits {
	case 128:
		return xmlsec.EncAES128GCM
	case 256:
		return xmlsec.EncAES256GCM
	}
	return ""
}

// Protect is a kernel probe, not public JS configuration. It supports only one
// whole Body-content region, one recipient, one signature and a clear Timestamp.
func Protect(raw []byte, signer Identity, recipient *x509.Certificate, now time.Time, order ProtectionOrder, bits int) (wire []byte, err error) {
	defer func() {
		if recover() != nil {
			wire = nil
			err = ErrEncryption
		}
	}()
	alg := encryptionAlgorithm(bits)
	if alg == "" || order != SignThenEncrypt && order != EncryptThenSign || !rsaCertificateOK(recipient, now, x509.KeyUsageKeyEncipherment) {
		return nil, ErrEncryption
	}
	doc, ns, header, err := prepareSecurity(raw, signer, now)
	if err != nil {
		return nil, err
	}
	if order == SignThenEncrypt {
		if err := signProbe(doc, ns, signer, []string{"body-1", "ts-1"}); err != nil {
			return nil, err
		}
	}
	opts := xenc.EncryptOptions{DataAlgorithm: alg, KeyTransportAlgorithm: xmlsec.KeyTransportRSAOAEP, MGFAlgorithm: xmlsec.MGF1SHA256, DigestAlgorithm: xmlsec.DigestSHA256, Recipient: recipient, DataID: "ed-1"}
	ek, err := xenc.GenerateEncryptedKey(opts)
	if err != nil {
		return nil, ErrEncryption
	}
	defer clear(ek.SessionKey)
	ref, err := wss.NewIssuerSerialReference(recipient)
	if err != nil || ek.SetKeyInfo(ref) != nil || ek.AddDataReference("ed-1") != nil {
		return nil, ErrEncryption
	}
	if header.Prepend(ek.Element) != nil {
		return nil, ErrEncryption
	}
	if _, err = wss.AssignIDWith(doc, doc.Node(ek.Element), "ek-1"); err != nil {
		return nil, ErrEncryption
	}
	opts.DataKeyInfo = wss.NewEncryptedKeyReference("ek-1")
	body := element(doc.Root()).FirstElement(ns, "Body")
	wire, err = xenc.EncryptContent(doc.Root(), body, ek.SessionKey, opts)
	if err != nil {
		return nil, ErrEncryption
	}
	if order == EncryptThenSign {
		doc, ns, err = parsed(wire)
		if err != nil {
			return nil, ErrEncryption
		}
		if err = signProbe(doc, ns, signer, []string{"body-1", "ts-1", "ek-1"}); err != nil {
			return nil, err
		}
		wire, err = c14n.Bytes(signatureBeforeKey(doc.Root(), ns), c14n.Options{Algorithm: c14n.Inclusive10WithComments})
	}
	if err != nil || len(wire) > 4<<20 {
		return nil, ErrEncryption
	}
	return wire, nil
}

// Open keeps plaintext private until the configured order, exact coverage and
// whole-Body encryption policy pass. There is no order/algorithm fallback.
func Open(raw []byte, trust *x509.Certificate, recipient Identity, now time.Time, order ProtectionOrder, bits int) (result *Verified, err error) {
	defer func() {
		if recover() != nil {
			result = nil
			err = ErrEncryption
		}
	}()
	alg := encryptionAlgorithm(bits)
	if alg == "" || order != SignThenEncrypt && order != EncryptThenSign || !certificateOK(trust, now) || !rsaCertificateOK(recipient.Certificate, now, x509.KeyUsageKeyEncipherment) || recipient.Key == nil || !recipient.Key.PublicKey.Equal(recipient.Certificate.PublicKey) {
		return nil, ErrEncryption
	}
	doc, ns, err := parsed(raw)
	if err != nil {
		return nil, ErrEncryption
	}
	ed, ek, err := encryptionGraph(doc, ns, alg, false)
	if err != nil {
		return nil, err
	}
	var verified *Verified
	if order == EncryptThenSign {
		verified, err = verifyDocument(doc, ns, trust, now, ek)
		if err != nil {
			return nil, ErrEncryption
		}
	}
	opts := xenc.DecryptOptions{StrictBSP: true, AllowedDataAlgorithms: []string{alg}, AllowedKeyTransportAlgorithms: []string{xmlsec.KeyTransportRSAOAEP}, AllowedDigestAlgorithms: []string{xmlsec.DigestSHA256}, AllowedMGFAlgorithms: []string{xmlsec.MGF1SHA256}}
	key, err := xenc.DecryptEncryptedKey(ek, recipient.Key, opts)
	if err != nil {
		return nil, ErrEncryption
	}
	defer clear(key)
	plain, err := xenc.DecryptAndReplace(doc.Root(), ed, key, opts)
	if err != nil {
		return nil, ErrEncryption
	}
	defer clear(plain)
	recovered, recoveredNS, err := parsed(plain)
	if err != nil || recoveredNS != ns {
		return nil, ErrEncryption
	}
	// Provenance is intentionally limited to exactly one Content replacement in
	// the direct Body. The provider owns replacement/context restoration. No IDs
	// from a second parse are used to transfer signature coverage across trees.
	if countElements(recovered.Root(), xmlsec.NSXEnc, "EncryptedData") != 0 || countElements(recovered.Root(), xmlsec.NSXEnc, "EncryptedKey") != 1 || countElements(recovered.Root(), xmlsec.NSDSig, "Signature") != 1 {
		return nil, ErrEncryption
	}
	if order == SignThenEncrypt {
		// Remove no security nodes and verify this recovered snapshot itself. The
		// retained key is not signed in this order; do not claim it was covered.
		verified, err = verifyRecovered(recovered, ns, trust, now)
		if err != nil {
			return nil, ErrEncryption
		}
		return verified, nil
	}
	body := element(recovered.Root()).FirstElement(ns, "Body")
	consumed, err := c14n.Bytes(body, c14n.Options{Algorithm: c14n.Inclusive10WithComments})
	if err != nil {
		return nil, ErrEncryption
	}
	return &Verified{Body: consumed, Created: verified.Created, Expires: verified.Expires}, nil
}

func countElements(n *xdm.Node, ns, local string) int {
	count := 0
	if n.IsElement(ns, local) {
		count++
	}
	for c := range n.Children() {
		count += countElements(c, ns, local)
	}
	return count
}

func encryptionGraph(doc *xmlsec.Document, ns, alg string, allowElement bool) (*xdm.Node, *xdm.Node, error) {
	body := element(doc.Root()).FirstElement(ns, "Body")
	sec, err := wss.FindHeader(doc.Root(), ns, "")
	if err != nil || sec == nil || body == nil {
		return nil, nil, ErrEncryption
	}
	ed := body.FirstElement(xmlsec.NSXEnc, "EncryptedData")
	ek := sec.FirstElement(xmlsec.NSXEnc, "EncryptedKey")
	if ed == nil || ek == nil || countElements(doc.Root(), xmlsec.NSXEnc, "EncryptedData") != 1 || countElements(doc.Root(), xmlsec.NSXEnc, "EncryptedKey") != 1 || (ed.AttrValue("Type") != xenc.TypeContent && (!allowElement || ed.AttrValue("Type") != xenc.TypeElement)) {
		return nil, nil, ErrEncryption
	}
	for c := range body.Children() {
		if c.Kind() == xdm.KindElement && !c.Is(ed) || c.Kind() == xdm.KindText && strings.TrimSpace(c.StringValue()) != "" {
			return nil, nil, ErrEncryption
		}
	}
	method := ed.FirstElement(xmlsec.NSXEnc, "EncryptionMethod")
	km := ek.FirstElement(xmlsec.NSXEnc, "EncryptionMethod")
	if method == nil || method.AttrValue("Algorithm") != alg || km == nil || km.AttrValue("Algorithm") != xmlsec.KeyTransportRSAOAEP {
		return nil, nil, ErrEncryption
	}
	digest := km.FirstElement(xmlsec.NSDSig, "DigestMethod")
	mgf := km.FirstElement(xmlsec.NSXEnc11, "MGF")
	if digest == nil || digest.AttrValue("Algorithm") != xmlsec.DigestSHA256 || mgf == nil || mgf.AttrValue("Algorithm") != xmlsec.MGF1SHA256 || km.FirstElement(xmlsec.NSXEnc, "OAEPparams") != nil {
		return nil, nil, ErrEncryption
	}
	list := ek.FirstElement(xmlsec.NSXEnc, "ReferenceList")
	if list == nil {
		return nil, nil, ErrEncryption
	}
	for child := range list.Children() {
		if child.Kind() == xdm.KindElement && !child.IsElement(xmlsec.NSXEnc, "DataReference") {
			return nil, nil, ErrEncryption
		}
	}
	targets, e := xenc.ReferencedData(list)
	if e != nil || len(targets) != 1 || !targets[0].Is(ed) {
		return nil, nil, ErrEncryption
	}
	resolved, e := xenc.FindEncryptedKey(ed)
	if e != nil || !resolved.Is(ek) {
		return nil, nil, ErrEncryption
	}
	return ed, ek, nil
}

func signProbe(doc *xmlsec.Document, ns string, signer Identity, ids []string) error {
	sec, err := wss.FindHeader(doc.Root(), ns, "")
	if err != nil {
		return ErrEncryption
	}
	var refs []dsig.Reference
	for _, id := range ids {
		refs = append(refs, dsig.Reference{URI: "#" + id, DigestAlgorithm: xmlsec.DigestSHA256, Transforms: []dsig.TransformSpec{{Algorithm: string(c14n.Exclusive10)}}})
	}
	_, err = dsig.Sign(doc, xmlsec.KeyProvider{Signer: signer.Key, Certificate: signer.Certificate}, dsig.SignOptions{SignatureAlgorithm: xmlsec.SigRSASHA256, CanonicalizationAlgorithm: string(c14n.Exclusive10), References: refs, KeyInfo: dsig.KeyInfoSecurityTokenReference, SecurityTokenID: "bst-1", SignatureID: "sig-1", Parent: sec, IDAttributes: []xdm.QName{dsig.IDAttrDSig}})
	if err != nil {
		return ErrEncryption
	}
	return nil
}

// signatureBeforeKey changes sibling order using the provider's XDM builder.
// No namespaces or ancestors change; this probe uses exclusive C14N without
// InclusiveNamespaces. Inbound verification always uses the final wire tree.
func signatureBeforeKey(root *xdm.Node, ns string) *xdm.Node {
	sec, _ := wss.FindHeader(root, ns, "")
	sig := sec.FirstElement(xmlsec.NSDSig, "Signature")
	var copyPath func(*xdm.Node, *xdm.Node)
	copyPath = func(dst, src *xdm.Node) {
		for prefix, uri := range src.DeclaredNamespaces() {
			dst.AddNamespace(prefix, uri)
		}
		for a := range src.Attrs() {
			dst.AppendCopy(a)
		}
		if src.Is(sec) {
			key := sec.FirstElement(xmlsec.NSXEnc, "EncryptedKey")
			for child := range src.Children() {
				if !child.Is(sig) && !child.Is(key) {
					dst.AppendCopy(child)
				}
			}
			dst.AppendCopy(sig)
			dst.AppendCopy(key)
			return
		}
		for child := range src.Children() {
			if child.IsElement(ns, "Envelope") || child.IsElement(ns, "Header") || child.Is(sec) {
				copyPath(dst.AppendShallowCopy(child), child)
			} else {
				dst.AppendCopy(child)
			}
		}
	}
	out := xdm.ShallowCopy(root)
	copyPath(out, root)
	return out
}
