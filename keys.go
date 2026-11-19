package soap

import (
	"bytes"
	"strconv"
	"time"

	"github.com/grafana/sobek"
	"github.com/stanimirivanov/xk6-soap/internal/keys"
)

type clientKeys struct {
	signing, decryption, recipient *keys.Material
	trust                          []*keys.Material
}

func (k *clientKeys) validate(now time.Time) error {
	if k == nil {
		return nil
	}
	for _, item := range []struct {
		material *keys.Material
		role     keys.Role
	}{{k.signing, keys.Signing}, {k.decryption, keys.Decryption}, {k.recipient, keys.Recipient}} {
		if item.material != nil {
			if err := item.material.Validate(item.role, now); err != nil {
				return err
			}
		}
	}
	for _, pin := range k.trust {
		if err := pin.Validate(keys.Trust, now); err != nil {
			return err
		}
	}
	return nil
}
func (i *instance) keyBytes(value sobek.Value) []byte {
	if absent(value) {
		i.throw("SOAP_KEY_INVALID", "keys")
	}
	buffer, ok := value.Export().(sobek.ArrayBuffer)
	if !ok {
		i.throw("SOAP_KEY_INVALID", "keys")
	}
	raw := buffer.Bytes()
	if len(raw) == 0 {
		i.throw("SOAP_KEY_INVALID", "keys")
	}
	if len(raw) > keys.MaxInput {
		i.throw("SOAP_KEY_LIMIT", "keys")
	}
	return bytes.Clone(raw)
}
func (i *instance) loadKey(value sobek.Value, role keys.Role) *keys.Material {
	var input keys.Input
	if role == keys.Trust {
		input.Cert = i.keyBytes(value)
	} else {
		obj := i.object(value, "cert", "key", "pkcs12", "password")
		cert, key, pfx, password := obj.Get("cert"), obj.Get("key"), obj.Get("pkcs12"), obj.Get("password")
		if role == keys.Recipient {
			if !absent(key) || !absent(pfx) || !absent(password) {
				i.throw("SOAP_KEY_INVALID", "keys")
			}
			input.Cert = i.keyBytes(cert)
		} else if !absent(pfx) {
			if !absent(cert) || !absent(key) || absent(password) {
				i.throw("SOAP_KEY_INVALID", "keys")
			}
			input.PKCS12 = i.keyBytes(pfx)
			input.Password = i.text(password)
		} else {
			if !absent(password) {
				i.throw("SOAP_KEY_INVALID", "keys")
			}
			input.Cert = i.keyBytes(cert)
			input.Key = i.keyBytes(key)
		}
	}
	defer clear(input.Key)
	defer clear(input.PKCS12)
	material, err := i.keyCache.Load(input, role, time.Now())
	if err != nil {
		i.throw(err.Error(), "keys")
	}
	return material
}
func (i *instance) decodeKeys(value sobek.Value) *clientKeys {
	obj := i.object(value, "signing", "decryption", "recipient", "trust")
	out := &clientKeys{}
	for _, field := range []struct {
		name   string
		role   keys.Role
		target **keys.Material
	}{{"signing", keys.Signing, &out.signing}, {"decryption", keys.Decryption, &out.decryption}, {"recipient", keys.Recipient, &out.recipient}} {
		if v := obj.Get(field.name); !absent(v) {
			*field.target = i.loadKey(v, field.role)
		}
	}
	if value := obj.Get("trust"); !absent(value) {
		array, ok := value.(*sobek.Object)
		if !ok || array.ClassName() != "Array" {
			i.throw("SOAP_KEY_INVALID", "keys")
		}
		n := i.number(array.Get("length"))
		if n > 8 {
			i.throw("SOAP_KEY_LIMIT", "keys")
		}
		for index := 0; index < n; index++ {
			out.trust = append(out.trust, i.loadKey(array.Get(strconv.Itoa(index)), keys.Trust))
		}
	}
	return out
}
func (i *instance) validateKeys(cfg clientConfig) {
	if err := cfg.keys.validate(time.Now()); err != nil {
		i.throw(err.Error(), "keys")
	}
}
