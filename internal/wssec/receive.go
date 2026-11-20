package wssec

import (
	"bytes"
	"crypto/rsa"
	"encoding/xml"
	"errors"
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
func Receive(status int, raw, version string, limits message.Limits, policy ReceivePolicy, trust []*keys.Material, now time.Time) (result *message.Parsed) {
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
	env := element(doc.Root())
	header := env.FirstElement(ns, "Header")
	var security *xdm.Node
	if header != nil {
		security = header.FirstElement(xmlsec.NSWSSE, "Security")
	}
	if security == nil && !policy.Signature {
		return message.Parse(status, raw, version, limits)
	}
	var understood []xml.Name
	for _, name := range policy.SignedHeaders {
		understood = append(understood, xml.Name{Space: name.Namespace, Local: name.LocalName})
	}
	if e := message.CheckSecurityEnvelope(raw, version, limits, understood...); e != nil {
		result.Error = e
		return result
	}
	if policy.Signature {
		no := false
		result.SigVerified = &no
	}
	if security == nil {
		return fail("SIGNATURE_INVALID")
	}
	counts := map[string]int{}
	bad := false
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
			if n.Name().URI == xmlsec.NSXEnc || n.Name().URI == "http://www.w3.org/2009/xmlenc11#" {
				bad = true
			}
		}
		for c := range n.Children() {
			walk(c)
		}
	}
	walk(doc.Root())
	if bad || counts["Security"] != 1 || counts["Signature"] != 1 || counts["BinarySecurityToken"] != 1 || counts["Timestamp"] > 1 {
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
		if c.Kind() == xdm.KindElement && !c.IsElement(xmlsec.NSWSU, "Timestamp") && !c.IsElement(xmlsec.NSDSig, "Signature") && !c.IsElement(xmlsec.NSWSSE, "BinarySecurityToken") {
			return fail("POLICY_VIOLATION")
		}
	}
	var requiredHeaders []*xdm.Node
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
	for _, name := range policy.SignedHeaders {
		var found *xdm.Node
		for _, c := range allowedHeaders {
			if c.IsElement(name.Namespace, name.LocalName) {
				if found != nil {
					return fail("SIGNATURE_INVALID")
				}
				found = c
			}
		}
		if found == nil {
			return fail("SIGNATURE_INVALID")
		}
		requiredHeaders = append(requiredHeaders, found)
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
	if info.FirstElement(xmlsec.NSDSig, "SignatureMethod") == nil || info.FirstElement(xmlsec.NSDSig, "SignatureMethod").AttrValue("Algorithm") != xmlsec.SigRSASHA256 {
		return fail("POLICY_VIOLATION")
	}
	for r := range info.Children() {
		if r.IsElement(xmlsec.NSDSig, "Reference") {
			m := r.FirstElement(xmlsec.NSDSig, "DigestMethod")
			if m == nil || m.AttrValue("Algorithm") != xmlsec.DigestSHA256 {
				return fail("POLICY_VIOLATION")
			}
		}
	}
	bst := security.FirstElement(xmlsec.NSWSSE, "BinarySecurityToken")
	embedded, e := wss.ParseBinarySecurityToken(bst)
	if e != nil {
		return fail("POLICY_VIOLATION")
	}
	pub, ok := embedded.PublicKey.(*rsa.PublicKey)
	if !ok || pub.N.BitLen() < 2048 || !coreKeyInfo(signature, bst) {
		return fail("POLICY_VIOLATION")
	}
	normalized, _ := limits.Normalized()
	accepted, e := receiveBodyOctets(doc, info, body, stamp, normalized.Bytes, allowedHeaders...)
	if e != nil {
		return fail(e.Error())
	}
	if policy.Signature {
		var pin *keys.Material
		for _, candidate := range trust {
			if candidate != nil && candidate.Validate(keys.Trust, now) == nil && bytes.Equal(candidate.Certificate().Raw, embedded.Raw) {
				pin = candidate
				break
			}
		}
		if pin == nil || !certificateOK(pin.Certificate(), now) {
			return fail("SIGNATURE_INVALID")
		}
		coverage, e := dsig.Verify(doc.Root(), signature, dsig.VerifyOptions{Certificate: pin.Certificate(), AllowedSignatureAlgorithms: []string{xmlsec.SigRSASHA256}, AllowedDigestAlgorithms: []string{xmlsec.DigestSHA256}, AllowedCanonicalizationAlgorithms: []string{string(c14n.Exclusive10)}, MaxReferences: 16, StrictBSP: true, RequireExplicitCanonicalization: true, IDAttributes: []xdm.QName{dsig.IDAttrDSig}})
		if e != nil || !coverage.CoversNodes(body) || stamp != nil && !coverage.CoversNodes(stamp) {
			return fail("SIGNATURE_INVALID")
		}
		for _, node := range requiredHeaders {
			if !coverage.CoversNodes(node) {
				return fail("SIGNATURE_INVALID")
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

	projection := message.ParseAcceptedBody(status, string(accepted), version, limits)
	projection.SigVerified = result.SigVerified
	projection.TimestampValid = result.TimestampValid
	return projection
}

// The core receive profile supports only a local direct BST reference, including
// when verification is skipped. No resolver or alternate key representation runs.
func coreKeyInfo(signature, bst *xdm.Node) bool {
	info := signature.FirstElement(xmlsec.NSDSig, "KeyInfo")
	if info == nil || elementCount(info) != 1 {
		return false
	}
	str := info.FirstElement(xmlsec.NSWSSE, "SecurityTokenReference")
	if str == nil || elementCount(str) != 1 {
		return false
	}
	ref := str.FirstElement(xmlsec.NSWSSE, "Reference")
	id := bst.Attr(xmlsec.NSWSU, "Id")
	return ref != nil && id != nil && xdm.IsNCName(id.StringValue()) && ref.AttrValue("URI") == "#"+id.StringValue() && ref.AttrValue("ValueType") == xmlsec.BSTValueTypeX509v3 && elementCount(ref) == 0
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
