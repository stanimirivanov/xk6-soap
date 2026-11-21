package wssec

import (
	"github.com/stanimirivanov/xk6-soap/internal/message"
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

type responseEncryption struct {
	data      *xdm.Node
	key       *xdm.Node
	algorithm string
}

func inspectResponseEncryption(doc *xmlsec.Document, ns string) (responseEncryption, bool) {
	env := element(doc.Root())
	body := env.FirstElement(ns, "Body")
	ed := body.FirstElement(xmlsec.NSXEnc, "EncryptedData")
	if ed == nil {
		return responseEncryption{}, false
	}
	method := ed.FirstElement(xmlsec.NSXEnc, "EncryptionMethod")
	if method == nil || elementCount(method) != 0 {
		return responseEncryption{}, false
	}
	algorithm := method.AttrValue("Algorithm")
	if algorithm != xmlsec.EncAES128GCM && algorithm != xmlsec.EncAES256GCM {
		return responseEncryption{}, false
	}
	ed, ek, err := encryptionGraph(doc, ns, algorithm, true)
	if err != nil || hasEncryptionOutside(doc.Root(), ed, ek) || countElements(doc.Root(), xmlsec.NSDSig, "Signature") != 1 || !supportedEncryptionChildren(ed, ek) {
		return responseEncryption{}, false
	}
	info := ek.FirstElement(xmlsec.NSDSig, "KeyInfo")
	if info == nil || elementCount(info) != 1 {
		return responseEncryption{}, false
	}
	str := info.FirstElement(xmlsec.NSWSSE, "SecurityTokenReference")
	if !validIssuerSerialReference(str) {
		return responseEncryption{}, false
	}
	return responseEncryption{data: ed, key: ek, algorithm: algorithm}, true
}

func (graph responseEncryption) decrypt(doc *xmlsec.Document, recipient *keys.Material, now time.Time) ([]byte, string) {
	if !validKey(recipient, keys.Decryption, now) {
		return nil, "DECRYPTION_FAILED"
	}
	info := graph.key.FirstElement(xmlsec.NSDSig, "KeyInfo")
	str := info.FirstElement(xmlsec.NSWSSE, "SecurityTokenReference")
	if !wss.MatchSecurityTokenReference(str, recipient.Certificate()) {
		return nil, "DECRYPTION_FAILED"
	}
	options := xenc.DecryptOptions{
		StrictBSP: true, AllowedDataAlgorithms: []string{graph.algorithm},
		AllowedKeyTransportAlgorithms: []string{xmlsec.KeyTransportRSAOAEP},
		AllowedDigestAlgorithms:       []string{xmlsec.DigestSHA256}, AllowedMGFAlgorithms: []string{xmlsec.MGF1SHA256},
	}
	key, err := xenc.DecryptEncryptedKey(graph.key, recipient, options)
	if err != nil {
		return nil, "DECRYPTION_FAILED"
	}
	defer clear(key)
	plaintext, err := xenc.DecryptAndReplace(doc.Root(), graph.data, key, options)
	if err != nil {
		return nil, "DECRYPTION_FAILED"
	}
	return plaintext, ""
}

type responseDecryptor func(responseEncryption, *xmlsec.Document, *keys.Material, time.Time) ([]byte, string)

// recoverEncryptedBody replaces the exact region established by graph. No
// references are resolved against this new tree to transfer ciphertext coverage.
func recoverEncryptedBody(decrypt responseDecryptor, graph responseEncryption, doc *xmlsec.Document, recipient *keys.Material, now time.Time, version string, limits message.Limits) (*xmlsec.Document, *xdm.Node, string) {
	recovered, code := decrypt(graph, doc, recipient, now)
	if code != "" {
		return nil, nil, code
	}
	defer clear(recovered)
	if e := message.ValidateEnvelope(string(recovered), version, limits); e != nil {
		if e.(*message.Error).Code == "LIMIT_EXCEEDED" {
			return nil, nil, "LIMIT_EXCEEDED"
		}
		return nil, nil, "DECRYPTION_FAILED"
	}
	restored, ns, err := parsed(recovered)
	if err != nil {
		return nil, nil, "DECRYPTION_FAILED"
	}
	security, err := wss.FindHeader(restored.Root(), ns, "")
	if err != nil || security == nil {
		return nil, nil, "DECRYPTION_FAILED"
	}
	key := security.FirstElement(xmlsec.NSXEnc, "EncryptedKey")
	if key == nil || hasEncryptionOutside(restored.Root(), key, nil) {
		return nil, nil, "POLICY_VIOLATION"
	}
	return restored, key, ""
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
