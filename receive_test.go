package soap

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/stanimirivanov/xk6-soap/internal/wssec"
	"go.k6.io/k6/v2/lib"
)

func signedResponse(t *testing.T, payload string) string {
	t.Helper()
	b, e := os.ReadFile("internal/wssec/testdata/signing-key.pem")
	if e != nil {
		t.Fatal(e)
	}
	block, _ := pem.Decode(b)
	key, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	wire, e := wssec.Sign([]byte(`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>`+payload+`</s:Body></s:Envelope>`), wssec.Identity{Certificate: signingCertificate(t), Key: key.(*rsa.PrivateKey)}, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	return string(wire)
}
func TestVerifiedResponsePublic(t *testing.T) {
	rt := keyRuntime(t, New())
	js(t, rt.VU.Runtime(), `var receiver=new Client({url:'https://example.test',keys:{trust:[cert]},security:{verify:{signature:true}}});`)
	rt.VU.Runtime().Set("wire", signedResponse(t, "<Echo>PRIVATE_RESPONSE</Echo>"))
	rt.MoveToVUContext(&lib.State{})
	js(t, rt.VU.Runtime(), `var p=receiver.parse({status:200,body:wire});if(!p.ok||p.sigVerified!==true||p.timestampValid!==true||!p.body.includes('PRIVATE_RESPONSE')||p.xpath('string(Echo)').value!=='PRIVATE_RESPONSE')throw new Error('verified response unavailable');
 var bad=receiver.parse({status:500,body:wire.replace('PRIVATE_RESPONSE','TAMPERED')});if(bad.ok||bad.body!==null||bad.fault!==null||bad.sigVerified!==false||bad.xpath('string(.)').error.code!=='CONTENT_UNAVAILABLE')throw new Error('unverified content escaped');`)
}
