package adapter

import (
	"github.com/grafana/sobek"
	"github.com/stanimirivanov/xk6-soap/internal/wssec"
)

func (i *instance) decodeCredentials(options *sobek.Object, p wssec.Policy) (out *wssec.Credentials) {
	defer func() {
		if recover() != nil {
			i.throw("INVALID_ARGUMENT", "credentials")
		}
	}()
	value := policyField(options, "credentials")
	if value == nil {
		return nil
	}
	if p.UsernameToken == nil {
		i.throw("INVALID_ARGUMENT", "credentials")
	}
	obj := i.object(value, "user", "password")
	return &wssec.Credentials{User: i.policyText(policyField(obj, "user"), false), Password: i.policyText(policyField(obj, "password"), true)}
}
