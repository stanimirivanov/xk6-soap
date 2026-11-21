package wssec

import (
	"errors"
	"strconv"

	"github.com/knroy/go-xml/v2/c14n"
	"github.com/knroy/go-xml/v2/xdm"
	"github.com/knroy/go-xmlsec/v2"
	"github.com/knroy/go-xmlsec/v2/dsig"
	"github.com/knroy/go-xmlsec/v2/wss"
	"github.com/stanimirivanov/xk6-soap/internal/keys"
	"github.com/stanimirivanov/xk6-soap/internal/message"
)

var ErrSignatureBuild = errors.New("SOAP_SIGNATURE_BUILD_FAILED")

func appendSignature(doc *xmlsec.Document, ns string, header *wss.Header, signing *keys.Material, token bool, policy *SigningPolicy, selectors []message.HeaderSelector) error {
	body := element(doc.Root()).FirstElement(ns, "Body")
	// AssignIDWith preserves an existing ID. Never let a payload decoy take
	// the fixed reference while the actual Body retains a different ID.
	if id, err := wss.AssignIDWith(doc, body, "body-1"); err != nil || id != "body-1" {
		return ErrSignatureBuild
	}
	headerIDs, e := assignHeaderIDs(doc, ns, policy.Headers, selectors)
	if e != nil {
		return e
	}
	keyInfo, err := signingTokenReference(policy.KeyID, signing.Certificate())
	if err != nil {
		return ErrSignatureBuild
	}
	if keyInfo == nil {
		if _, err := header.AddBinarySecurityTokenWithID(signing.Certificate(), nil, xmlsec.BSTValueTypeX509v3, "bst-1"); err != nil {
			return ErrSignatureBuild
		}
	}
	// Provider edits publish immutable snapshots: select the final nodes after edits.
	security, err := wss.FindHeader(doc.Root(), ns, "")
	if err != nil || security == nil || security.FirstElement(xmlsec.NSWSU, "Timestamp") == nil {
		return ErrSignatureBuild
	}
	ids := []string{"body-1", "ts-1"}
	if token {
		if security.FirstElement(xmlsec.NSWSSE, "UsernameToken") == nil {
			return ErrSignatureBuild
		}
		ids = append(ids, "ut-1")
	}
	ids = append(ids, headerIDs...)
	if len(ids) > 16 {
		return ErrSignatureBuild
	}
	refs := make([]dsig.Reference, 0, len(ids))
	for _, id := range ids {
		refs = append(refs, dsig.Reference{URI: "#" + id, DigestAlgorithm: digestURIs[policy.Digest], Transforms: []dsig.TransformSpec{{Algorithm: string(c14n.Exclusive10)}}})
	}
	_, err = dsig.Sign(doc, xmlsec.KeyProvider{Signer: signing, Certificate: signing.Certificate()}, dsig.SignOptions{
		SignatureAlgorithm: signatureURIs[policy.Algorithm], CanonicalizationAlgorithm: string(c14n.Exclusive10), References: refs,
		KeyInfo: dsig.KeyInfoSecurityTokenReference, SecurityTokenID: "bst-1", KeyInfoElement: keyInfo, SignatureID: "sig-1", Parent: security,
	})
	if err != nil {
		return ErrSignatureBuild
	}
	return nil
}

// Assign IDs before signing; each provider edit publishes a new snapshot.
func assignHeaderIDs(doc *xmlsec.Document, ns string, selected []string, selectors []message.HeaderSelector) ([]string, error) {
	wanted := map[string]bool{}
	for _, name := range selected {
		if wanted[name] {
			return nil, ErrSignatureBuild
		}
		wanted[name] = true
	}
	seen := map[string]bool{}
	var targets []message.HeaderSelector
	for _, selector := range selectors {
		if seen[selector.Name] {
			return nil, ErrSignatureBuild
		}
		seen[selector.Name] = true
		if wanted[selector.Name] {
			targets = append(targets, selector)
			delete(wanted, selector.Name)
		}
	}
	if len(wanted) != 0 {
		return nil, ErrSignatureBuild
	}
	header := element(doc.Root()).FirstElement(ns, "Header")
	if header != nil {
		for c := range header.Children() {
			if message.IsAddressingHeader(c.Name().URI, c.Name().Local) {
				found := false
				for _, t := range targets {
					if t.Namespace == c.Name().URI && t.LocalName == c.Name().Local {
						found = true
					}
				}
				if !found {
					targets = append(targets, message.HeaderSelector{Namespace: c.Name().URI, LocalName: c.Name().Local})
				}
			}
		}
	}
	var ids []string
	used := map[string]bool{}
	for _, target := range targets {
		key := target.Namespace + "\x00" + target.LocalName
		if used[key] {
			return nil, ErrSignatureBuild
		}
		used[key] = true
		var node *xdm.Node
		header = element(doc.Root()).FirstElement(ns, "Header")
		if header == nil {
			return nil, ErrSignatureBuild
		}
		for c := range header.Children() {
			if c.IsElement(target.Namespace, target.LocalName) {
				if node != nil {
					return nil, ErrSignatureBuild
				}
				node = c
			}
		}
		if node == nil || node.IsElement(xmlsec.NSWSSE, "Security") {
			return nil, ErrSignatureBuild
		}
		id := "header-" + strconv.Itoa(len(ids)+1)
		if actual, e := wss.AssignIDWith(doc, node, id); e != nil || actual != id {
			return nil, ErrSignatureBuild
		}
		ids = append(ids, id)
	}
	return ids, nil
}
