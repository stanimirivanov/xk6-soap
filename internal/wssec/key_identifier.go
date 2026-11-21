package wssec

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"time"

	"github.com/knroy/go-xml/v2/xdm"
	"github.com/knroy/go-xmlsec/v2"
	"github.com/knroy/go-xmlsec/v2/wss"
	"github.com/stanimirivanov/xk6-soap/internal/keys"
)

const directKeyID = "binary-security-token"
const skiType = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier"
const thumbprintType = "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1"

func signingTokenReference(kind string, cert *x509.Certificate) (*xdm.Node, error) {
	switch kind {
	case directKeyID:
		return nil, nil // The provider builds the reference to the BST in the document.
	case "issuer-serial":
		return wss.NewIssuerSerialReference(cert)
	case "ski":
		if len(cert.SubjectKeyId) == 0 {
			return nil, ErrPolicyKey
		}
		return wss.NewKeyIdentifierReference(cert)
	case "ThumbprintSHA1":
		// The provider selects the thumbprint when no SKI is presented.
		thumbprintCert := *cert
		thumbprintCert.SubjectKeyId = nil
		return wss.NewKeyIdentifierReference(&thumbprintCert)
	case "x509keyidentifier":
		str := xdm.NewNode(xdm.KindElement, xdm.QName{URI: xmlsec.NSWSSE, Prefix: "wsse", Local: "SecurityTokenReference"}, "")
		str.AddNamespace("wsse", xmlsec.NSWSSE)
		ki := str.AppendElement(xdm.QName{URI: xmlsec.NSWSSE, Prefix: "wsse", Local: "KeyIdentifier"})
		ki.AppendAttr(xdm.QName{Local: "ValueType"}, xmlsec.BSTValueTypeX509v3)
		ki.AppendAttr(xdm.QName{Local: "EncodingType"}, xmlsec.BSTEncodingBase64)
		ki.AppendText(base64.StdEncoding.EncodeToString(cert.Raw))
		return str, nil
	}
	return nil, ErrPolicy
}

type signatureKeyIdentifier struct {
	reference  *xdm.Node
	embedded   *x509.Certificate
	inlineX509 bool
}

func readSignatureKey(doc, signature, bst *xdm.Node, bstCount int) (signatureKeyIdentifier, bool) {
	var out signatureKeyIdentifier
	info := signature.FirstElement(xmlsec.NSDSig, "KeyInfo")
	if info == nil || elementCount(info) != 1 {
		return out, false
	}
	str := info.FirstElement(xmlsec.NSWSSE, "SecurityTokenReference")
	if str == nil || elementCount(str) != 1 {
		return out, false
	}
	ref := str.ChildElements()[0]
	out.reference = str
	if ref.IsElement(xmlsec.NSWSSE, "Reference") {
		if bstCount != 1 || bst == nil || elementCount(ref) != 0 {
			return out, false
		}
		id := bst.Attr(xmlsec.NSWSU, "Id")
		if id == nil || !xdm.IsNCName(id.StringValue()) || ref.AttrValue("URI") != "#"+id.StringValue() || ref.AttrValue("ValueType") != xmlsec.BSTValueTypeX509v3 {
			return out, false
		}
		var err error
		out.embedded, err = wss.ResolveSecurityTokenReferenceStrict(doc, str)
		return out, err == nil
	}
	if bstCount != 0 {
		return out, false
	}
	if ref.IsElement(xmlsec.NSWSSE, "KeyIdentifier") {
		if elementCount(ref) != 0 || ref.AttrValue("EncodingType") != xmlsec.BSTEncodingBase64 {
			return out, false
		}
		tt := str.Attr(xmlsec.NSWSSE11, "TokenType")
		if tt != nil && tt.StringValue() != xmlsec.BSTValueTypeX509v3 {
			return out, false
		}
		raw := strings.Map(func(r rune) rune {
			if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
				return -1
			}
			return r
		}, ref.StringValue())
		der, err := base64.StdEncoding.Strict().DecodeString(raw)
		if err != nil || len(der) == 0 {
			return out, false
		}
		switch ref.AttrValue("ValueType") {
		case xmlsec.BSTValueTypeX509v3:
			out.inlineX509 = true
			out.embedded, err = x509.ParseCertificate(der)
			return out, err == nil
		case skiType:
			return out, wss.CheckSecurityTokenReference(str) == nil
		case thumbprintType:
			return out, len(der) == 20 && wss.CheckSecurityTokenReference(str) == nil
		}
		return out, false
	}
	if !ref.IsElement(xmlsec.NSDSig, "X509Data") || elementCount(ref) != 1 || wss.CheckSecurityTokenReference(str) != nil {
		return out, false
	}
	issuerSerial := ref.FirstElement(xmlsec.NSDSig, "X509IssuerSerial")
	if issuerSerial == nil || elementCount(issuerSerial) != 2 {
		return out, false
	}
	issuer := issuerSerial.FirstElement(xmlsec.NSDSig, "X509IssuerName")
	serial := issuerSerial.FirstElement(xmlsec.NSDSig, "X509SerialNumber")
	if issuer == nil || serial == nil || elementCount(issuer) != 0 || elementCount(serial) != 0 {
		return out, false
	}
	return out, len(issuer.StringValue()) > 0 && len(issuer.StringValue()) <= 4096 && len(serial.StringValue()) > 0 && len(serial.StringValue()) <= 64
}

func (id signatureKeyIdentifier) pinnedCertificate(trust []*keys.Material, now time.Time) *x509.Certificate {
	var found *x509.Certificate
	for _, pin := range trust {
		if pin == nil || pin.Validate(keys.Trust, now) != nil {
			continue
		}
		cert := pin.Certificate()
		if id.embedded != nil {
			if !bytes.Equal(cert.Raw, id.embedded.Raw) {
				continue
			}
		} else if !wss.MatchSecurityTokenReference(id.reference, cert) {
			continue
		}
		if found != nil && !found.Equal(cert) {
			return nil
		}
		found = cert
	}
	return found
}
