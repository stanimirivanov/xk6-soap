package soap

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/grafana/sobek"
	"github.com/stanimirivanov/xk6-soap/internal/keys"
	"go.k6.io/k6/v2/js/modulestest"
	"go.k6.io/k6/v2/lib"
)

func keyRuntime(t *testing.T, root *RootModule) *modulestest.Runtime {
	t.Helper()
	rt := modulestest.NewRuntime(t)
	for name, path := range map[string]string{"cert": "internal/wssec/testdata/signing-cert.pem", "key": "internal/wssec/testdata/signing-key.pem", "pfx": "internal/keys/testdata/openssl3.p12"} {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := rt.VU.Runtime().Set(name, rt.VU.Runtime().NewArrayBuffer(b)); err != nil {
			t.Fatal(err)
		}
	}
	if err := rt.VU.Runtime().Set("Client", root.NewModuleInstance(rt.VU).Exports().Named["Client"]); err != nil {
		t.Fatal(err)
	}
	return rt
}
func TestKeyConstruction(t *testing.T) {
	root := New()
	rt := keyRuntime(t, root)
	js(t, rt.VU.Runtime(), `var client=new Client({url:'https://example.test',keys:{signing:{cert,key},recipient:{cert},trust:[cert]}});new Client({url:'https://example.test',keys:{signing:{pkcs12:pfx,password:'synthetic-only'}}});`)
	js(t, rt.VU.Runtime(), `for(const keys of [
 {signing:{cert,key:'path.pem'}},{signing:{cert,key,password:'SECRET'}},{signing:{pkcs12:pfx,password:'SECRET'}},
 {signing:{pkcs12:pfx}},{signing:{cert,key,pkcs12:pfx,password:'synthetic-only'}},{signing:{cert}},
 {recipient:{cert,key}},{trust:[cert,cert,cert,cert,cert,cert,cert,cert,cert]}, {trust:'path.pem'},
 {recipient:{cert:new Uint8Array(cert)}},{unknown:{}},{signing:null}
 ]) {let caught=false;try{new Client({url:'https://example.test',keys});}catch(e){caught=true;if(!e.code||String(e).includes('SECRET'))throw new Error('unsafe key failure');}if(!caught)throw new Error('invalid keys accepted');}`)
	// Mutating one VU's ArrayBuffers must not poison shared decoded state.
	js(t, rt.VU.Runtime(), `new Uint8Array(cert).fill(0);new Uint8Array(key).fill(0);`)
	fresh := keyRuntime(t, root)
	js(t, fresh.VU.Runtime(), `new Client({url:'https://example.test',keys:{signing:{cert,key}}});`)
}
func TestCrossVUKeyCache(t *testing.T) {
	root := New()
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			rt := keyRuntime(t, root)
			_, err := rt.VU.Runtime().RunString(`new Client({url:'https://example.test',keys:{signing:{pkcs12:pfx,password:'synthetic-only'}}});`)
			if err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
}

func TestRevalidateKeysAtBuildAndParse(t *testing.T) {
	rt := keyRuntime(t, New())
	keyPEM, err := os.ReadFile("internal/wssec/testdata/signing-key.pem")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(keyPEM)
	private, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key := private.(*rsa.PrivateKey)
	template := &x509.Certificate{SerialNumber: big.NewInt(500), NotBefore: time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	material, err := keys.NewCache().Load(keys.Input{Cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), Key: keyPEM}, keys.Signing, time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	cfg := clientConfig{version: "1.1", keys: &clientKeys{signing: material}}
	instance := &instance{vu: rt.VU}
	rt.MoveToVUContext(&lib.State{})
	for name, fn := range map[string]func(clientConfig, sobek.FunctionCall) sobek.Value{"build": instance.build, "parse": instance.parse} {
		if err := rt.VU.Runtime().Set(name, func(call sobek.FunctionCall) sobek.Value { return fn(cfg, call) }); err != nil {
			t.Fatal(err)
		}
		js(t, rt.VU.Runtime(), `try{`+name+`({status:200,body:'<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body/></s:Envelope>'});throw new Error('expired key accepted');}catch(e){if(e.code!=='SOAP_KEY_VALIDITY'||e.stage!=='keys')throw e;}`)
	}
}
