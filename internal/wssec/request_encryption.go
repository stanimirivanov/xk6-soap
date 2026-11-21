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
)

var ErrEncryptionBuild = errors.New("SOAP_ENCRYPTION_BUILD_FAILED")

// encryptRequest replaces the configured region on the already signed tree.
// The provider owns the GCM IV and OAEP randomness and emits the final wire.
func encryptRequest(doc *xmlsec.Document, ns string, header *wss.Header, policy *EncryptionPolicy, recipient *x509.Certificate, random io.Reader) ([]byte, error) {
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
	for _, id := range []string{"ek-1", "ed-1"} {
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
	if err != nil || ek.SetKeyInfo(ref) != nil || ek.AddDataReference("ed-1") != nil {
		return nil, ErrEncryptionBuild
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
	default:
		return nil, ErrUnavailable
	}
	if err != nil {
		return nil, ErrEncryptionBuild
	}
	return wire, nil
}
