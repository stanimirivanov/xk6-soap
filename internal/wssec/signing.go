package wssec

import (
	"errors"

	"github.com/knroy/go-xml/v2/c14n"
	"github.com/knroy/go-xmlsec/v2"
	"github.com/knroy/go-xmlsec/v2/dsig"
	"github.com/knroy/go-xmlsec/v2/wss"
	"github.com/stanimirivanov/xk6-soap/internal/keys"
)

var ErrSignatureBuild = errors.New("SOAP_SIGNATURE_BUILD_FAILED")

func appendSignature(doc *xmlsec.Document, ns string, header *wss.Header, signing *keys.Material, token bool) error {
	body := element(doc.Root()).FirstElement(ns, "Body")
	// AssignIDWith preserves an existing ID. Never let a payload decoy take
	// the fixed reference while the actual Body retains a different ID.
	if id, err := wss.AssignIDWith(doc, body, "body-1"); err != nil || id != "body-1" {
		return ErrSignatureBuild
	}
	if _, err := header.AddBinarySecurityTokenWithID(signing.Certificate(), nil, xmlsec.BSTValueTypeX509v3, "bst-1"); err != nil {
		return ErrSignatureBuild
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
	refs := make([]dsig.Reference, 0, len(ids))
	for _, id := range ids {
		refs = append(refs, dsig.Reference{URI: "#" + id, DigestAlgorithm: xmlsec.DigestSHA256, Transforms: []dsig.TransformSpec{{Algorithm: string(c14n.Exclusive10)}}})
	}
	_, err = dsig.Sign(doc, xmlsec.KeyProvider{Signer: signing, Certificate: signing.Certificate()}, dsig.SignOptions{
		SignatureAlgorithm: xmlsec.SigRSASHA256, CanonicalizationAlgorithm: string(c14n.Exclusive10), References: refs,
		KeyInfo: dsig.KeyInfoSecurityTokenReference, SecurityTokenID: "bst-1", SignatureID: "sig-1", Parent: security,
	})
	if err != nil {
		return ErrSignatureBuild
	}
	return nil
}
