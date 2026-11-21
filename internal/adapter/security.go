package adapter

import (
	"math"
	"strconv"

	"github.com/grafana/sobek"
	"github.com/stanimirivanov/xk6-soap/internal/wssec"
)

func (i *instance) invalidPolicy() { i.throw(wssec.ErrPolicy.Error(), "security") }

// Policy fields are own properties: prototype pollution cannot supply defaults,
// credentials or enabled blocks. Accessors are caught at the decoder boundary.
func policyField(obj *sobek.Object, name string) sobek.Value {
	for _, field := range obj.GetOwnPropertyNames() {
		if field == name {
			return obj.Get(name)
		}
	}
	return nil
}
func (i *instance) policyText(value sobek.Value, empty bool) string {
	text, ok := value.(sobek.String)
	if !ok || !empty && text.Length() == 0 {
		i.invalidPolicy()
	}
	return text.String()
}
func (i *instance) policyString(obj *sobek.Object, name string) string {
	value := policyField(obj, name)
	if value == nil {
		return ""
	}
	return i.policyText(value, false)
}
func (i *instance) policyInt(obj *sobek.Object, name string) *int {
	value := policyField(obj, name)
	if value == nil {
		return nil
	}
	if _, object := value.(*sobek.Object); object {
		i.invalidPolicy()
	}
	var number float64
	switch n := value.Export().(type) {
	case int64:
		number = float64(n)
	case float64:
		number = n
	default:
		i.invalidPolicy()
	}
	if math.IsNaN(number) || math.IsInf(number, 0) || number != math.Trunc(number) || number < math.MinInt32 || number > math.MaxInt32 {
		i.invalidPolicy()
	}
	n := int(number)
	return &n
}
func (i *instance) policyBool(obj *sobek.Object, name string) *bool {
	value := policyField(obj, name)
	if value == nil {
		return nil
	}
	if _, object := value.(*sobek.Object); object {
		i.invalidPolicy()
	}
	flag, ok := value.Export().(bool)
	if !ok {
		i.invalidPolicy()
	}
	return &flag
}
func (i *instance) policyArray(value sobek.Value, max int) (*sobek.Object, int) {
	array, ok := value.(*sobek.Object)
	if !ok || array.ClassName() != "Array" || len(array.Symbols()) != 0 {
		i.invalidPolicy()
	}
	length := array.Get("length").ToInteger()
	if length < 0 || length > int64(max) {
		i.invalidPolicy()
	}
	for _, name := range array.GetOwnPropertyNames() {
		if name == "length" {
			continue
		}
		index, err := strconv.Atoi(name)
		if err != nil || index < 0 || int64(index) >= length || strconv.Itoa(index) != name {
			i.invalidPolicy()
		}
	}
	return array, int(length)
}
func (i *instance) policyStrings(obj *sobek.Object, name string, max int) []string {
	value := policyField(obj, name)
	if value == nil {
		return nil
	}
	array, length := i.policyArray(value, max)
	out := []string{}
	for index := 0; index < length; index++ {
		out = append(out, i.policyText(policyField(array, strconv.Itoa(index)), false))
	}
	return out
}
func (i *instance) policyNames(obj *sobek.Object, name string) []wssec.ExpandedName {
	value := policyField(obj, name)
	if value == nil {
		return nil
	}
	array, length := i.policyArray(value, 16)
	out := []wssec.ExpandedName{}
	for index := 0; index < length; index++ {
		item := i.object(policyField(array, strconv.Itoa(index)), "namespace", "localName")
		out = append(out, wssec.ExpandedName{Namespace: i.policyText(policyField(item, "namespace"), false), LocalName: i.policyText(policyField(item, "localName"), false)})
	}
	return out
}
func (i *instance) decodeSecurity(options *sobek.Object) (out wssec.SecurityOptions) {
	// A hostile accessor can throw its own secret-bearing JS exception. Convert
	// decoder failures to our fixed diagnostic rather than reflecting that value.
	defer func() {
		if recover() != nil {
			i.invalidPolicy()
		}
	}()
	value := policyField(options, "security")
	if value == nil {
		return out
	}
	obj := i.object(value, "usernameToken", "timestamp", "sign", "encrypt", "order", "verify")
	if value := policyField(obj, "usernameToken"); value != nil {
		block := i.object(value, "user", "password", "passwordType")
		out.UsernameToken = &wssec.UsernameTokenPolicy{User: i.policyText(policyField(block, "user"), false), Password: i.policyText(policyField(block, "password"), true), PasswordType: i.policyString(block, "passwordType")}
	}
	if value := policyField(obj, "timestamp"); value != nil {
		block := i.object(value, "ttlSeconds", "clockOffsetSeconds")
		out.Timestamp = &wssec.TimestampOptions{TTLSeconds: i.policyInt(block, "ttlSeconds"), ClockOffsetSeconds: i.policyInt(block, "clockOffsetSeconds")}
	}
	if value := policyField(obj, "sign"); value != nil {
		block := i.object(value, "algorithm", "digest", "canonicalization", "keyId", "headers")
		out.Sign = &wssec.SigningPolicy{Algorithm: i.policyString(block, "algorithm"), Digest: i.policyString(block, "digest"), Canonicalization: i.policyString(block, "canonicalization"), KeyID: i.policyString(block, "keyId"), Headers: i.policyStrings(block, "headers", 16)}
	}
	if value := policyField(obj, "encrypt"); value != nil {
		block := i.object(value, "algorithm", "keyTransport", "target", "headers")
		out.Encrypt = &wssec.EncryptionPolicy{Algorithm: i.policyString(block, "algorithm"), KeyTransport: i.policyString(block, "keyTransport"), Target: i.policyString(block, "target"), Headers: i.policyStrings(block, "headers", 16)}
	}
	out.Order = i.policyString(obj, "order")
	if value := policyField(obj, "verify"); value != nil {
		block := i.object(value, "signature", "timestamp", "requireEncryption", "order", "signatureAlgorithms", "digestAlgorithms", "signedHeaders", "encryptedHeaders", "clockSkewSeconds", "maxAgeSeconds")
		out.Verify = &wssec.ReceiveOptions{Signature: i.policyBool(block, "signature"), Timestamp: i.policyBool(block, "timestamp"), RequireEncryption: i.policyBool(block, "requireEncryption"), Order: i.policyString(block, "order"), SignatureAlgorithms: i.policyStrings(block, "signatureAlgorithms", 6), DigestAlgorithms: i.policyStrings(block, "digestAlgorithms", 3), SignedHeaders: i.policyNames(block, "signedHeaders"), EncryptedHeaders: i.policyNames(block, "encryptedHeaders"), ClockSkewSeconds: i.policyInt(block, "clockSkewSeconds"), MaxAgeSeconds: i.policyInt(block, "maxAgeSeconds")}
	}
	return out
}
func (k *clientKeys) policyMaterial() wssec.KeyMaterial {
	if k == nil {
		return wssec.KeyMaterial{}
	}
	return wssec.KeyMaterial{Signing: k.signing, Decryption: k.decryption, Recipient: k.recipient, Trust: k.trust}
}
