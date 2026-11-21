package wssec

import (
	"crypto/x509"
	"errors"
	"io"

	"github.com/knroy/go-xml/v2/xdm"
	"github.com/knroy/go-xmlsec/v2"
	"github.com/knroy/go-xmlsec/v2/dsig"
	"github.com/knroy/go-xmlsec/v2/wss"
	"github.com/knroy/go-xmlsec/v2/xenc"
	"github.com/stanimirivanov/xk6-soap/internal/message"
)

var ErrEncryptionBuild = errors.New("SOAP_ENCRYPTION_BUILD_FAILED")

// encryptRequest replaces the configured region on the current request tree.
// The provider owns the GCM IV and OAEP randomness and emits the final wire.
func encryptRequest(doc *xmlsec.Document, ns string, header *wss.Header, policy *EncryptionPolicy, recipient *x509.Certificate, random io.Reader, limits message.Limits, headerSlots []int) ([]byte, error) {
	var size int
	var algorithm string
	switch policy.Algorithm {
	case "aes-128-gcm":
		size = 16
		algorithm = xmlsec.EncAES128GCM
	case "aes-256-gcm":
		size = 32
		algorithm = xmlsec.EncAES256GCM
	default:
		return nil, ErrPolicy
	}
	for node := range doc.Root().Descendants() {
		if node.Kind() == xdm.KindElement && (node.Name().URI == xmlsec.NSXEnc || node.Name().URI == xmlsec.NSXEnc11 || node.IsElement(xmlsec.NSWSSE11, "EncryptedHeader")) {
			return nil, ErrEncryptionBuild
		}
	}
	count := 1
	if policy.Target == "headers" {
		count = len(headerSlots)
	}
	ids := []string{"ek-1"}
	for idx := 0; idx < count; idx++ {
		ids = append(ids, encryptionDataID(idx))
	}
	for _, id := range ids {
		if _, err := wss.FindByID(doc.Root(), id, dsig.IDAttrDSig); !errors.Is(err, xmlsec.ErrIDNotFound) {
			return nil, ErrEncryptionBuild
		}
	}

	key := make([]byte, size)
	defer clear(key)
	if err := readRandom(random, key); err != nil {
		return nil, err
	}
	opts := xenc.EncryptOptions{
		DataAlgorithm: algorithm, KeyTransportAlgorithm: xmlsec.KeyTransportRSAOAEP,
		MGFAlgorithm: xmlsec.MGF1SHA256, DigestAlgorithm: xmlsec.DigestSHA256,
		Recipient: recipient, SessionKey: key, DataID: "ed-1",
	}
	ek, err := xenc.GenerateEncryptedKey(opts)
	if err != nil {
		return nil, ErrEncryptionBuild
	}
	ref, err := wss.NewIssuerSerialReference(recipient)
	if err != nil || ek.SetKeyInfo(ref) != nil {
		return nil, ErrEncryptionBuild
	}
	for _, id := range ids[1:] {
		if ek.AddDataReference(id) != nil {
			return nil, ErrEncryptionBuild
		}
	}
	encryptedKey, _, err := wss.WithID(ek.Element, "ek-1")
	if err != nil || header.Prepend(encryptedKey) != nil {
		return nil, ErrEncryptionBuild
	}
	opts.DataKeyInfo = wss.NewEncryptedKeyReference("ek-1")

	body := element(doc.Root()).FirstElement(ns, "Body")
	var wire []byte
	switch policy.Target {
	case "content":
		wire, err = xenc.EncryptContent(doc.Root(), body, key, opts)
	case "body":
		children := body.ChildElements()
		if len(children) != 1 {
			return nil, ErrEncryptionBuild
		}
		wire, err = xenc.EncryptElement(doc.Root(), children[0], key, opts)
	case "headers":
		version := "1.1"
		if ns == xmlsec.NSSOAP12 {
			version = "1.2"
		}
		for i, slot := range headerSlots {
			security, e := wss.FindHeader(doc.Root(), ns, "")
			blocks := headerBlocks(doc, ns)
			if e != nil || security == nil || slot >= len(blocks) {
				return nil, ErrEncryptionBuild
			}
			opts.DataID = encryptionDataID(i)
			wire, e = xenc.EncryptHeader(doc.Root(), blocks[slot], security, key, opts)
			if e != nil {
				return nil, ErrEncryptionBuild
			}
			if e = message.ValidateEnvelope(string(wire), version, limits); e != nil {
				return nil, e
			}
			if i+1 < len(headerSlots) {
				doc, _, e = parsed(wire)
				if e != nil {
					return nil, ErrEncryptionBuild
				}
			}
		}
	default:
		return nil, ErrUnavailable
	}
	if err != nil {
		return nil, ErrEncryptionBuild
	}
	return wire, nil
}
