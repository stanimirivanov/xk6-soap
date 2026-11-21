package wssec

import (
	"time"

	"github.com/knroy/go-xml/v2/xdm"
	"github.com/knroy/go-xmlsec/v2"
	"github.com/knroy/go-xmlsec/v2/wss"
	"github.com/knroy/go-xmlsec/v2/xenc"
	"github.com/stanimirivanov/xk6-soap/internal/keys"
)

func isEncryptionNode(n *xdm.Node) bool {
	return n.Kind() == xdm.KindElement && (n.Name().URI == xmlsec.NSXEnc || n.Name().URI == xmlsec.NSXEnc11 || n.IsElement(xmlsec.NSWSSE11, "EncryptedHeader"))
}

// hasEncryptionOutside ignores only subtrees that the encryption adapter has
// identified explicitly. In the recovered tree only the consumed EncryptedKey
// may remain. The application Body must contain no encryption structures.
func hasEncryptionOutside(n *xdm.Node, first, second *xdm.Node) bool {
	if first != nil && n.Is(first) || second != nil && n.Is(second) {
		return false
	}
	if isEncryptionNode(n) {
		return true
	}
	for c := range n.Children() {
		if hasEncryptionOutside(c, first, second) {
			return true
		}
	}
	return false
}

func decryptResponse(doc *xmlsec.Document, ns string, recipient *keys.Material, now time.Time) ([]byte, string) {
	if !validKey(recipient, keys.Decryption, now) {
		return nil, "DECRYPTION_FAILED"
	}
	env := element(doc.Root())
	body := env.FirstElement(ns, "Body")
	ed := body.FirstElement(xmlsec.NSXEnc, "EncryptedData")
	if ed == nil {
		return nil, "POLICY_VIOLATION"
	}
	method := ed.FirstElement(xmlsec.NSXEnc, "EncryptionMethod")
	if method == nil || elementCount(method) != 0 {
		return nil, "POLICY_VIOLATION"
	}
	algorithm := method.AttrValue("Algorithm")
	if algorithm != xmlsec.EncAES128GCM && algorithm != xmlsec.EncAES256GCM {
		return nil, "POLICY_VIOLATION"
	}
	ed, ek, err := encryptionGraph(doc, ns, algorithm, true)
	if err != nil || hasEncryptionOutside(doc.Root(), ed, ek) || countElements(doc.Root(), xmlsec.NSDSig, "Signature") != 1 || !supportedEncryptionChildren(ed, ek) {
		return nil, "POLICY_VIOLATION"
	}
	info := ek.FirstElement(xmlsec.NSDSig, "KeyInfo")
	if info == nil || elementCount(info) != 1 {
		return nil, "POLICY_VIOLATION"
	}
	str := info.FirstElement(xmlsec.NSWSSE, "SecurityTokenReference")
	if !validIssuerSerialReference(str) {
		return nil, "POLICY_VIOLATION"
	}
	if !wss.MatchSecurityTokenReference(str, recipient.Certificate()) {
		return nil, "DECRYPTION_FAILED"
	}
	options := xenc.DecryptOptions{
		StrictBSP: true, AllowedDataAlgorithms: []string{algorithm},
		AllowedKeyTransportAlgorithms: []string{xmlsec.KeyTransportRSAOAEP},
		AllowedDigestAlgorithms:       []string{xmlsec.DigestSHA256}, AllowedMGFAlgorithms: []string{xmlsec.MGF1SHA256},
	}
	key, err := xenc.DecryptEncryptedKey(ek, recipient, options)
	if err != nil {
		return nil, "DECRYPTION_FAILED"
	}
	defer clear(key)
	plaintext, err := xenc.DecryptAndReplace(doc.Root(), ed, key, options)
	if err != nil {
		return nil, "DECRYPTION_FAILED"
	}
	return plaintext, ""
}

func supportedEncryptionChildren(ed, ek *xdm.Node) bool {
	// Required method and CipherData, plus an optional local STR on the data.
	count := 2
	if info := ed.FirstElement(xmlsec.NSDSig, "KeyInfo"); info != nil {
		if elementCount(info) != 1 || info.FirstElement(xmlsec.NSWSSE, "SecurityTokenReference") == nil {
			return false
		}
		count++
	}
	// The graph has already validated the two OAEP parameters and ReferenceList.
	km := ek.FirstElement(xmlsec.NSXEnc, "EncryptionMethod")
	if elementCount(km) != 2 || elementCount(km.FirstElement(xmlsec.NSDSig, "DigestMethod")) != 0 || elementCount(km.FirstElement(xmlsec.NSXEnc11, "MGF")) != 0 {
		return false
	}
	return elementCount(ed) == count && elementCount(ek) == 4 && inlineCipher(ed) && inlineCipher(ek)
}

func inlineCipher(node *xdm.Node) bool {
	data := node.FirstElement(xmlsec.NSXEnc, "CipherData")
	if data == nil || elementCount(data) != 1 {
		return false
	}
	value := data.FirstElement(xmlsec.NSXEnc, "CipherValue")
	return value != nil && elementCount(value) == 0
}
