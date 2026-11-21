package wssec

import (
	"time"

	"encoding/xml"
	"github.com/knroy/go-xml/v2/xdm"
	"github.com/knroy/go-xmlsec/v2"
	"github.com/knroy/go-xmlsec/v2/wss"
	"github.com/knroy/go-xmlsec/v2/xenc"
	"github.com/stanimirivanov/xk6-soap/internal/keys"
	"github.com/stanimirivanov/xk6-soap/internal/message"
	"strings"
)

func isEncryptionNode(n *xdm.Node) bool {
	return n.Kind() == xdm.KindElement && (n.Name().URI == xmlsec.NSXEnc || n.Name().URI == xmlsec.NSXEnc11 || n.IsElement(xmlsec.NSWSSE11, "EncryptedHeader"))
}

// hasEncryptionOutside ignores only subtrees that the encryption adapter has
// identified explicitly. In the recovered tree only the consumed EncryptedKey
// may remain. The application Body must contain no encryption structures.
func hasEncryptionOutside(n *xdm.Node, allowed ...*xdm.Node) bool {
	for _, node := range allowed {
		if node != nil && n.Is(node) {
			return false
		}
	}
	if isEncryptionNode(n) {
		return true
	}
	for c := range n.Children() {
		if hasEncryptionOutside(c, allowed...) {
			return true
		}
	}
	return false
}

type responseEncryption struct {
	data        *xdm.Node
	key         *xdm.Node
	algorithm   string
	headerSlots []int
	limits      message.Limits
	version     string
}

func inspectResponseEncryption(doc *xmlsec.Document, ns string) (responseEncryption, bool) {
	var graph responseEncryption
	env := element(doc.Root())
	body := env.FirstElement(ns, "Body")
	security, err := wss.FindHeader(doc.Root(), ns, "")
	if err != nil || security == nil || countElements(doc.Root(), xmlsec.NSDSig, "Signature") != 1 {
		return graph, false
	}
	ek := security.FirstElement(xmlsec.NSXEnc, "EncryptedKey")
	if ek == nil || countElements(doc.Root(), xmlsec.NSXEnc, "EncryptedKey") != 1 || !validKeyTransport(ek) {
		return graph, false
	}
	graph.key = ek
	allowed := []*xdm.Node{ek}
	var parts []*xdm.Node
	if ed := body.FirstElement(xmlsec.NSXEnc, "EncryptedData"); ed != nil {
		for c := range body.Children() {
			if c.Kind() == xdm.KindElement && !c.Is(ed) || c.Kind() == xdm.KindText && strings.TrimSpace(c.StringValue()) != "" {
				return graph, false
			}
		}
		if typ := ed.AttrValue("Type"); typ != xenc.TypeContent && typ != xenc.TypeElement {
			return graph, false
		}
		graph.data = ed
		parts = append(parts, ed)
		allowed = append(allowed, ed)
	}
	for i, block := range headerBlocks(doc, ns) {
		if !block.IsElement(xmlsec.NSWSSE11, "EncryptedHeader") {
			continue
		}
		if !validEncryptedHeaderMetadata(block, security, ns) {
			return graph, false
		}
		var ed *xdm.Node
		for c := range block.Children() {
			if c.Kind() == xdm.KindText && strings.Trim(c.Value(), " \t\r\n") == "" {
				continue
			}
			if ed != nil || !c.IsElement(xmlsec.NSXEnc, "EncryptedData") {
				return graph, false
			}
			ed = c
		}
		if ed == nil || ed.AttrValue("Type") != xenc.TypeElement {
			return graph, false
		}
		graph.headerSlots = append(graph.headerSlots, i)
		parts = append(parts, ed)
		allowed = append(allowed, block)
	}
	if len(parts) == 0 || len(parts) > maxEncryptedParts || countElements(doc.Root(), xmlsec.NSXEnc, "EncryptedData") != len(parts) || hasEncryptionOutside(doc.Root(), allowed...) {
		return graph, false
	}
	list := ek.FirstElement(xmlsec.NSXEnc, "ReferenceList")
	if list == nil || elementCount(list) != len(parts) {
		return graph, false
	}
	for ref := range list.Children() {
		if ref.Kind() == xdm.KindElement && (!ref.IsElement(xmlsec.NSXEnc, "DataReference") || elementCount(ref) != 0) {
			return graph, false
		}
	}
	targets, err := xenc.ReferencedData(list)
	if err != nil || len(targets) != len(parts) {
		return graph, false
	}
	for _, part := range parts {
		method := part.FirstElement(xmlsec.NSXEnc, "EncryptionMethod")
		if method == nil || elementCount(method) != 0 || !supportedEncryptionChildren(part, ek) {
			return graph, false
		}
		algorithm := method.AttrValue("Algorithm")
		if algorithm != xmlsec.EncAES128GCM && algorithm != xmlsec.EncAES256GCM || graph.algorithm != "" && graph.algorithm != algorithm {
			return graph, false
		}
		graph.algorithm = algorithm
		matches := 0
		for _, target := range targets {
			if target.Is(part) {
				matches++
			}
		}
		key, err := xenc.FindEncryptedKey(part)
		if matches != 1 || err != nil || !key.Is(ek) {
			return graph, false
		}
	}
	return graph, true
}

func validKeyTransport(ek *xdm.Node) bool {
	km := ek.FirstElement(xmlsec.NSXEnc, "EncryptionMethod")
	if km == nil || km.AttrValue("Algorithm") != xmlsec.KeyTransportRSAOAEP {
		return false
	}
	digest := km.FirstElement(xmlsec.NSDSig, "DigestMethod")
	mgf := km.FirstElement(xmlsec.NSXEnc11, "MGF")
	if digest == nil || digest.AttrValue("Algorithm") != xmlsec.DigestSHA256 || mgf == nil || mgf.AttrValue("Algorithm") != xmlsec.MGF1SHA256 {
		return false
	}
	info := ek.FirstElement(xmlsec.NSDSig, "KeyInfo")
	return info != nil && elementCount(info) == 1 && validIssuerSerialReference(info.FirstElement(xmlsec.NSWSSE, "SecurityTokenReference"))
}

func validEncryptedHeaderMetadata(wrapper, security *xdm.Node, ns string) bool {
	for a := range wrapper.Attrs() {
		if a.Name().URI == xmlsec.NSSOAP11 || a.Name().URI == xmlsec.NSSOAP12 {
			if a.Name().URI != ns {
				return false
			}
			switch a.Name().Local {
			case "mustUnderstand":
			case "actor":
				if ns != xmlsec.NSSOAP11 {
					return false
				}
			case "role", "relay":
				if ns != xmlsec.NSSOAP12 {
					return false
				}
			default:
				return false
			}
		}
	}
	for _, name := range []string{"mustUnderstand", "actor", "role", "relay"} {
		a := wrapper.Attr(ns, name)
		b := security.Attr(ns, name)
		if (a == nil) != (b == nil) {
			return false
		}
		if a != nil && a.Value() != b.Value() {
			if ns != xmlsec.NSSOAP12 || (name != "mustUnderstand" && name != "relay") || !sameSOAPBoolean(a.Value(), b.Value()) {
				return false
			}
		}
		if a != nil && name == "relay" && !sameSOAPBoolean(a.Value(), a.Value()) {
			return false
		}
	}
	return true
}

func sameSOAPBoolean(a, b string) bool {
	return (a == "1" || a == "true") && (b == "1" || b == "true") || (a == "0" || a == "false") && (b == "0" || b == "false")
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
	var plaintext []byte
	if graph.data != nil {
		plaintext, err = xenc.DecryptAndReplace(doc.Root(), graph.data, key, options)
		if err != nil {
			return nil, "DECRYPTION_FAILED"
		}
	}
	for _, slot := range graph.headerSlots {
		if plaintext != nil {
			var code string
			doc, code = parseRecoveredSnapshot(plaintext, graph.version, graph.limits)
			clear(plaintext)
			if code != "" {
				return nil, code
			}
		}
		blocks := headerBlocks(doc, element(doc.Root()).Name().URI)
		if slot >= len(blocks) {
			return nil, "DECRYPTION_FAILED"
		}
		plaintext, err = xenc.DecryptHeader(doc.Root(), blocks[slot], key, options)
		if err != nil {
			return nil, "DECRYPTION_FAILED"
		}
	}
	return plaintext, ""
}

type responseDecryptor func(responseEncryption, *xmlsec.Document, *keys.Material, time.Time) ([]byte, string)

// recoverEncryptedRegions replaces the exact regions established by graph. No
// references are resolved against this new tree to transfer ciphertext coverage.
func recoverEncryptedRegions(decrypt responseDecryptor, graph responseEncryption, doc *xmlsec.Document, recipient *keys.Material, now time.Time, version string, limits message.Limits, understood ...xml.Name) (*xmlsec.Document, *xdm.Node, string) {
	graph.version = version
	graph.limits = limits
	recovered, code := decrypt(graph, doc, recipient, now)
	if code != "" {
		return nil, nil, code
	}
	defer clear(recovered)
	restored, code := parseRecoveredSnapshot(recovered, version, limits)
	if code != "" {
		return nil, nil, code
	}
	if len(graph.headerSlots) != 0 {
		if failure := message.CheckSecurityEnvelope(string(recovered), version, limits, understood...); failure != nil {
			return nil, nil, failure.Code
		}
	}
	ns := element(restored.Root()).Name().URI
	security, err := wss.FindHeader(restored.Root(), ns, "")
	if err != nil || security == nil {
		return nil, nil, "DECRYPTION_FAILED"
	}
	key := security.FirstElement(xmlsec.NSXEnc, "EncryptedKey")
	if key == nil || hasEncryptionOutside(restored.Root(), key) {
		return nil, nil, "POLICY_VIOLATION"
	}
	return restored, key, ""
}

func parseRecoveredSnapshot(raw []byte, version string, limits message.Limits) (*xmlsec.Document, string) {
	if e := message.ValidateEnvelope(string(raw), version, limits); e != nil {
		if e.(*message.Error).Code == "LIMIT_EXCEEDED" {
			return nil, "LIMIT_EXCEEDED"
		}
		return nil, "DECRYPTION_FAILED"
	}
	restored, _, err := parsed(raw)
	if err != nil {
		return nil, "DECRYPTION_FAILED"
	}
	return restored, ""
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
