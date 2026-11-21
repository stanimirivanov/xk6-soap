package wssec

import (
	"encoding/xml"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/knroy/go-xml/v2/c14n"
	"github.com/knroy/go-xml/v2/xdm"
	"github.com/knroy/go-xmlsec/v2"
	"github.com/knroy/go-xmlsec/v2/dsig"
	"github.com/knroy/go-xmlsec/v2/wss"
	"github.com/stanimirivanov/xk6-soap/internal/keys"
	"github.com/stanimirivanov/xk6-soap/internal/message"
)

var errReceiveSignature = errors.New("SIGNATURE_INVALID")

// Receive never returns application content before all required security checks
// succeed. Provider nodes are request-local and never escape this adapter.
func Receive(status int, raw, version string, limits message.Limits, policy ReceivePolicy, trust []*keys.Material, now time.Time) *message.Parsed {
	return ReceiveWithKeys(status, raw, version, limits, policy, KeyMaterial{Trust: trust}, now)
}

func ReceiveWithKeys(status int, raw, version string, limits message.Limits, policy ReceivePolicy, material KeyMaterial, now time.Time) *message.Parsed {
	return receiveWithDecryptor(status, raw, version, limits, policy, material, now, responseEncryption.decrypt)
}

func receiveWithDecryptor(status int, raw, version string, limits message.Limits, policy ReceivePolicy, material KeyMaterial, now time.Time, decrypt responseDecryptor) (result *message.Parsed) {
	result = &message.Parsed{Status: status}
	fail := func(code string) *message.Parsed {
		result.Error = &message.Error{Code: code, Stage: "security"}
		return result
	}
	defer func() {
		if recover() != nil {
			result = &message.Parsed{Status: status, Error: &message.Error{Code: "SIGNATURE_INVALID", Stage: "security"}, SigVerified: result.SigVerified, TimestampValid: result.TimestampValid}
		}
	}()
	if status == 0 || raw == "" {
		return message.Parse(status, raw, version, limits)
	}
	if e := message.ValidateEnvelope(raw, version, limits); e != nil {
		result.Error = e.(*message.Error)
		return result
	}
	doc, ns, e := parsed([]byte(raw))
	if e != nil {
		return fail("POLICY_VIOLATION")
	}
	if !policy.Signature && !policy.RequireEncryption {
		env := element(doc.Root())
		head := env.FirstElement(ns, "Header")
		if head == nil || head.FirstElement(xmlsec.NSWSSE, "Security") == nil {
			return message.Parse(status, raw, version, limits)
		}
	}
	var understood []xml.Name
	for _, name := range append(slices.Clone(policy.SignedHeaders), policy.EncryptedHeaders...) {
		understood = append(understood, xml.Name{Space: name.Namespace, Local: name.LocalName})
	}
	wireUnderstood := append(slices.Clone(understood), xml.Name{Space: xmlsec.NSWSSE11, Local: "EncryptedHeader"})
	if e := message.CheckSecurityEnvelope(raw, version, limits, wireUnderstood...); e != nil {
		result.Error = e
		return result
	}
	if policy.Signature {
		no := false
		result.SigVerified = &no
	}
	var retainedKey *xdm.Node
	var graph responseEncryption
	var verifyCiphertext bool
	if hasEncryptionOutside(doc.Root(), nil, nil) {
		if !policy.Signature || !validOrder(policy.Order) {
			return fail("POLICY_VIOLATION")
		}
		var ok bool
		graph, ok = inspectResponseEncryption(doc, ns)
		if !ok || policy.RequireEncryption && graph.data == nil {
			return fail("POLICY_VIOLATION")
		}
		verifyCiphertext = policy.Order == string(EncryptThenSign)
		if verifyCiphertext {
			retainedKey = graph.key
		} else {
			var code string
			slotsBefore := len(headerBlocks(doc, ns))
			doc, retainedKey, code = recoverEncryptedRegions(decrypt, graph, doc, material.Decryption, now, version, limits, understood...)
			if code != "" {
				return fail(code)
			}
			if len(headerBlocks(doc, ns)) != slotsBefore {
				return fail("POLICY_VIOLATION")
			}
		}
	} else if policy.RequireEncryption || len(policy.EncryptedHeaders) != 0 {
		return fail("POLICY_VIOLATION")
	}
	env := element(doc.Root())
	header := env.FirstElement(ns, "Header")
	var security *xdm.Node
	if header != nil {
		security = header.FirstElement(xmlsec.NSWSSE, "Security")
	}
	if security == nil {
		return fail("SIGNATURE_INVALID")
	}
	counts := map[string]int{}
	var walk func(*xdm.Node)
	walk = func(n *xdm.Node) {
		if n.Kind() == xdm.KindElement {
			if n.Name().URI == xmlsec.NSWSSE && (n.Name().Local == "Security" || n.Name().Local == "BinarySecurityToken") {
				counts[n.Name().Local]++
			}
			if n.IsElement(xmlsec.NSWSU, "Timestamp") {
				counts["Timestamp"]++
			}
			if n.IsElement(xmlsec.NSDSig, "Signature") {
				counts["Signature"]++
			}
		}
		for c := range n.Children() {
			walk(c)
		}
	}
	walk(doc.Root())
	if counts["Security"] != 1 || counts["Signature"] != 1 || counts["BinarySecurityToken"] > 1 || counts["Timestamp"] > 1 {
		return fail("POLICY_VIOLATION")
	}
	attrName := "actor"
	if ns == xmlsec.NSSOAP12 {
		attrName = "role"
	}
	role := ""
	if a := security.Attr(ns, attrName); a != nil {
		role = a.StringValue()
	}
	if !(role == "" || ns == xmlsec.NSSOAP11 && role == "http://schemas.xmlsoap.org/soap/actor/next" || ns == xmlsec.NSSOAP12 && (role == xmlsec.NSSOAP12+"/role/ultimateReceiver" || role == xmlsec.NSSOAP12+"/role/next")) {
		return fail("POLICY_VIOLATION")
	}
	for c := range security.Children() {
		if c.Kind() == xdm.KindElement && !(retainedKey != nil && c.Is(retainedKey)) && !c.IsElement(xmlsec.NSWSU, "Timestamp") && !c.IsElement(xmlsec.NSDSig, "Signature") && !c.IsElement(xmlsec.NSWSSE, "BinarySecurityToken") {
			return fail("POLICY_VIOLATION")
		}
	}
	blocks := headerBlocks(doc, ns)
	if !verifyCiphertext && !validRecoveredHeaders(blocks, graph, policy) {
		return fail("POLICY_VIOLATION")
	}
	var requiredHeaders []*xdm.Node
	for _, slot := range graph.headerSlots {
		requiredHeaders = append(requiredHeaders, blocks[slot])
	}
	var coveredSlots []bool

	var allowedHeaders []*xdm.Node
	seenAddressing := map[string]bool{}
	if header != nil {
		for c := range header.Children() {
			if c.Kind() != xdm.KindElement || c.IsElement(xmlsec.NSWSSE, "Security") {
				continue
			}
			allowedHeaders = append(allowedHeaders, c)
			if message.IsAddressingHeader(c.Name().URI, c.Name().Local) {
				if seenAddressing[c.Name().Local] {
					return fail("POLICY_VIOLATION")
				}
				seenAddressing[c.Name().Local] = true
				requiredHeaders = append(requiredHeaders, c)
			}
		}
	}
	if !verifyCiphertext || len(graph.headerSlots) == 0 {
		for _, name := range policy.SignedHeaders {
			idx := uniqueHeader(blocks, name.Namespace, name.LocalName)
			if idx < 0 {
				return fail("SIGNATURE_INVALID")
			}
			requiredHeaders = append(requiredHeaders, blocks[idx])
		}
	}
	body := env.FirstElement(ns, "Body")
	stamp := security.FirstElement(xmlsec.NSWSU, "Timestamp")
	signature := security.FirstElement(xmlsec.NSDSig, "Signature")
	refs := 0
	if signature != nil {
		if si := signature.FirstElement(xmlsec.NSDSig, "SignedInfo"); si != nil {
			for c := range si.Children() {
				if c.IsElement(xmlsec.NSDSig, "Reference") {
					refs++
				}
			}
		}
	}
	if refs < 1 || refs > 16 {
		return fail("POLICY_VIOLATION")
	}
	if signature == nil || !coreSignatureShape(signature, refs) || !signaturePolicy(signature, refs) {
		return fail("POLICY_VIOLATION")
	}
	// Enforce algorithm policy even when authentication is explicitly skipped.
	info := signature.FirstElement(xmlsec.NSDSig, "SignedInfo")
	if info.FirstElement(xmlsec.NSDSig, "CanonicalizationMethod").AttrValue("Algorithm") != string(c14n.Exclusive10) {
		return fail("POLICY_VIOLATION")
	}
	method := info.FirstElement(xmlsec.NSDSig, "SignatureMethod")
	if method == nil || elementCount(method) != 0 {
		return fail("POLICY_VIOLATION")
	}
	signatureURI := method.AttrValue("Algorithm")
	algorithm := allowedSignatureAlgorithm(signatureURI, policy.SignatureAlgorithms)
	if algorithm == "" {
		return fail("POLICY_VIOLATION")
	}
	var allowedDigests []string
	for _, name := range policy.DigestAlgorithms {
		if uri := digestURIs[name]; uri != "" {
			allowedDigests = append(allowedDigests, uri)
		}
	}
	for r := range info.Children() {
		if r.IsElement(xmlsec.NSDSig, "Reference") {
			m := r.FirstElement(xmlsec.NSDSig, "DigestMethod")
			if m == nil || !slices.Contains(allowedDigests, m.AttrValue("Algorithm")) {
				return fail("POLICY_VIOLATION")
			}
		}
	}
	bst := security.FirstElement(xmlsec.NSWSSE, "BinarySecurityToken")
	identifier, ok := readSignatureKey(doc.Root(), signature, bst, counts["BinarySecurityToken"])
	if !ok || identifier.embedded != nil && !compatiblePublicKey(identifier.embedded.PublicKey, algorithm) {
		return fail("POLICY_VIOLATION")
	}
	if verifyCiphertext {
		allowedHeaders = append(allowedHeaders, graph.key)
		requiredHeaders = append(requiredHeaders, graph.key)
	}
	normalized, _ := limits.Normalized()
	accepted, e := receiveBodyOctets(doc, info, body, stamp, normalized.Bytes, allowedHeaders...)
	if e != nil {
		return fail(e.Error())
	}
	if policy.Signature {
		pin := identifier.pinnedCertificate(material.Trust, now)
		if pin == nil || !compatiblePublicKey(pin.PublicKey, algorithm) {
			return fail("SIGNATURE_INVALID")
		}
		// The provider's BSP checker excludes inline X509v3 KeyIdentifier. This
		// form has already passed the exact local shape, DER and pin checks above.
		coverage, e := dsig.Verify(doc.Root(), signature, dsig.VerifyOptions{Certificate: pin, AllowedSignatureAlgorithms: []string{signatureURI}, AllowedDigestAlgorithms: allowedDigests, AllowedCanonicalizationAlgorithms: []string{string(c14n.Exclusive10)}, MaxReferences: 16, StrictBSP: !identifier.inlineX509, RequireExplicitCanonicalization: true, IDAttributes: []xdm.QName{dsig.IDAttrDSig}})
		if e != nil || !coverage.CoversNodes(body) || stamp != nil && !coverage.CoversNodes(stamp) {
			return fail("SIGNATURE_INVALID")
		}
		for _, node := range requiredHeaders {
			if !coverage.CoversNodes(node) {
				return fail("SIGNATURE_INVALID")
			}
		}
		if verifyCiphertext && len(graph.headerSlots) != 0 {
			coveredSlots = make([]bool, len(blocks))
			for i, block := range blocks {
				coveredSlots[i] = coverage.CoversNodes(block)
			}
		}
		yes := true
		result.SigVerified = &yes
		if policy.Timestamp {
			no := false
			result.TimestampValid = &no
			if stamp == nil {
				return fail("TIMESTAMP_INVALID")
			}
			if !timestampFresh(stamp, now, policy) {
				return fail("TIMESTAMP_INVALID")
			}

			yes := true
			result.TimestampValid = &yes
		}
	}

	if verifyCiphertext {
		// The signature covered the original Body and the exact key used here.
		// The validated graph has one replacement, inside that same Body.
		restored, _, code := recoverEncryptedRegions(decrypt, graph, doc, material.Decryption, now, version, limits, understood...)
		if code != "" {
			return fail(code)
		}
		recoveredBlocks := headerBlocks(restored, ns)
		if len(recoveredBlocks) != len(blocks) || !validRecoveredHeaders(recoveredBlocks, graph, policy) {
			return fail("POLICY_VIOLATION")
		}
		if len(graph.headerSlots) != 0 {
			for _, name := range policy.SignedHeaders {
				idx := uniqueHeader(recoveredBlocks, name.Namespace, name.LocalName)
				if idx < 0 || !coveredSlots[idx] {
					return fail("SIGNATURE_INVALID")
				}
			}
		}
		recoveredBody := element(restored.Root()).FirstElement(ns, "Body")
		output := limitedXML{max: normalized.Bytes}
		if err := c14n.Write(&output, recoveredBody, c14n.Options{Algorithm: c14n.Inclusive10}); err != nil {
			if output.exceeded {
				return fail("LIMIT_EXCEEDED")
			}
			return fail("DECRYPTION_FAILED")
		}
		accepted = output.Bytes()
		defer clear(accepted)
	}

	projection := message.ParseAcceptedBody(status, string(accepted), version, limits)
	projection.SigVerified = result.SigVerified
	projection.TimestampValid = result.TimestampValid
	return projection
}

func elementCount(node *xdm.Node) int {
	n := 0
	for c := range node.Children() {
		if c.Kind() == xdm.KindElement {
			n++
		}
	}
	return n
}

// Bound every canonicalization before the provider's cryptographic verifier.
// Inclusive namespace rendering can expand beyond the source envelope size.
func receiveBodyOctets(doc *xmlsec.Document, info, body, stamp *xdm.Node, max int, headers ...*xdm.Node) ([]byte, error) {
	render := func(node, params *xdm.Node) ([]byte, error) {
		var prefixes []string
		if inc := params.FirstElement(string(c14n.Exclusive10), "InclusiveNamespaces"); inc != nil {
			for _, p := range strings.Fields(inc.AttrValue("PrefixList")) {
				if p == "#default" {
					p = ""
				}
				prefixes = append(prefixes, p)
			}
		}
		out := limitedXML{max: max}
		if e := c14n.Write(&out, node, c14n.Options{Algorithm: c14n.Exclusive10, InclusiveNamespacePrefixes: prefixes}); e != nil {
			if out.exceeded {
				return nil, ErrOutputLimit
			}
			return nil, errReceiveSignature
		}
		return out.Bytes(), nil
	}
	if _, e := render(info, info.FirstElement(xmlsec.NSDSig, "CanonicalizationMethod")); e != nil {
		return nil, e
	}
	var accepted []byte
	for r := range info.Children() {
		if r.IsElement(xmlsec.NSDSig, "Reference") {
			target, e := wss.FindByID(doc.Root(), strings.TrimPrefix(r.AttrValue("URI"), "#"), dsig.IDAttrDSig)
			allowed := target != nil && (target.Is(body) || stamp != nil && target.Is(stamp))
			for _, h := range headers {
				if target != nil && target.Is(h) {
					allowed = true
				}
			}
			if e != nil || !allowed {
				return nil, errReceiveSignature
			}
			transform := r.FirstElement(xmlsec.NSDSig, "Transforms").FirstElement(xmlsec.NSDSig, "Transform")
			wire, e := render(target, transform)
			if e != nil {
				return nil, e
			}
			if target.Is(body) {
				accepted = wire
			}
		}
	}
	if accepted == nil {
		return nil, errReceiveSignature
	}
	return accepted, nil
}

func coreSignatureShape(signature *xdm.Node, refs int) bool {
	if elementCount(signature) != 3 {
		return false
	}
	counts := map[string]int{}
	for c := range signature.Children() {
		if c.Kind() == xdm.KindElement {
			if c.Name().URI != xmlsec.NSDSig {
				return false
			}
			counts[c.Name().Local]++
		}
	}
	if counts["SignedInfo"] != 1 || counts["SignatureValue"] != 1 || counts["KeyInfo"] != 1 {
		return false
	}
	info := signature.FirstElement(xmlsec.NSDSig, "SignedInfo")
	if elementCount(info) != refs+2 {
		return false
	}
	counts = map[string]int{}
	for c := range info.Children() {
		if c.Kind() == xdm.KindElement {
			if c.Name().URI != xmlsec.NSDSig {
				return false
			}
			counts[c.Name().Local]++
		}
	}
	return counts["CanonicalizationMethod"] == 1 && counts["SignatureMethod"] == 1 && counts["Reference"] == refs
}
