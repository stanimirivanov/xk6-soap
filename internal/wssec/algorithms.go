package wssec

import "github.com/knroy/go-xmlsec/v2"

var signatureURIs = map[string]string{
	"rsa-sha256":   xmlsec.SigRSASHA256,
	"rsa-sha384":   xmlsec.SigRSASHA384,
	"rsa-sha512":   xmlsec.SigRSASHA512,
	"ecdsa-sha256": xmlsec.SigECDSASHA256,
	"ecdsa-sha384": xmlsec.SigECDSASHA384,
	"ecdsa-sha512": xmlsec.SigECDSASHA512,
}

var digestURIs = map[string]string{
	"sha256": xmlsec.DigestSHA256,
	"sha384": xmlsec.DigestSHA384,
	"sha512": xmlsec.DigestSHA512,
}

func allowedSignatureAlgorithm(uri string, names []string) string {
	if uri != "" {
		for _, name := range names {
			if signatureURIs[name] == uri {
				return name
			}
		}
	}
	return ""
}
