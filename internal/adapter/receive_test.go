package adapter

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stanimirivanov/xk6-soap/internal/message"
	"github.com/stanimirivanov/xk6-soap/internal/wssec"
	"go.k6.io/k6/v2/js/modulestest"
	"go.k6.io/k6/v2/lib"
)

func signedResponse(t *testing.T, payload string) string {
	return signedResponseAt(t, payload, time.Now())
}
func signedResponseAt(t *testing.T, payload string, now time.Time) string {
	t.Helper()
	return signResponseEnvelope(t, `<s:Envelope xmlns:s="`+message.SOAP11+`"><s:Body>`+payload+`</s:Body></s:Envelope>`, now)
}

func signResponseEnvelope(t *testing.T, envelope string, now time.Time) string {
	t.Helper()
	b, e := os.ReadFile("../wssec/testdata/signing-key.pem")
	if e != nil {
		t.Fatal(e)
	}
	block, _ := pem.Decode(b)
	key, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	wire, e := wssec.Sign([]byte(envelope), wssec.Identity{Certificate: signingCertificate(t), Key: key.(*rsa.PrivateKey)}, now)
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

func TestVerifiedSOAP12WrapperAttributes(t *testing.T) {
	rt := keyRuntime(t, New())
	js(t, rt.VU.Runtime(), `var receiver=new Client({
		url:'https://example.test', soapVersion:'1.2', keys:{trust:[cert]},
		security:{verify:{signature:true}},
	});`)
	const envelope = `<s:Envelope xmlns:s="` + message.SOAP12 + `" xmlns:m="urn:fixture" m:metadata="envelope">` +
		`<s:Body m:metadata="body"><m:Echo s:encodingStyle="` + message.SOAP12 + `/encoding/none">signed-wrapper-marker</m:Echo></s:Body></s:Envelope>`
	valid := signResponseEnvelope(t, envelope, time.Now())
	invalid := strings.Replace(valid, "<s:Envelope ", `<s:Envelope ordinary="fixture" `, 1)
	rt.VU.Runtime().Set("validWire", valid)
	rt.VU.Runtime().Set("invalidWire", invalid)
	rt.MoveToVUContext(&lib.State{})
	js(t, rt.VU.Runtime(), `
		const namespaces = {m:'urn:fixture'};
		const valid = receiver.parse({status:200, body:validWire});
		if (!valid.ok || valid.sigVerified !== true ||
			valid.xpath('string(./m:Echo)', namespaces).value !== 'signed-wrapper-marker') {
			throw new Error('valid signed wrapper attributes rejected');
		}
		const invalid = receiver.parse({status:200, body:invalidWire});
		const query = invalid.xpath('string(./m:Echo)', namespaces);
		if (invalid.ok || invalid.error?.code !== 'XML_INVALID' || invalid.error.stage !== 'xml' ||
			invalid.sigVerified !== null || invalid.timestampValid !== null ||
			invalid.body !== null || invalid.fault !== null || query.value !== null ||
			query.error?.code !== 'CONTENT_UNAVAILABLE') {
			throw new Error('invalid signed wrapper reached security or exposed content');
		}
	`)
}

func TestTimestampClockInjectionAndPolicyIndependence(t *testing.T) {
	rt := modulestest.NewRuntime(t)
	inst := New().NewModuleInstance(rt.VU).(*instance)
	created := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	clockNow := created
	inst.now = func() time.Time { return clockNow }
	rt.VU.Runtime().Set("Client", inst.Exports().Named["Client"])
	cert, e := os.ReadFile("../wssec/testdata/signing-cert.pem")
	if e != nil {
		t.Fatal(e)
	}
	rt.VU.Runtime().Set("cert", rt.VU.Runtime().NewArrayBuffer(cert))
	rt.VU.Runtime().Set("wire", signedResponseAt(t, "<Echo>PRIVATE_TIMESTAMP</Echo>", created))
	js(t, rt.VU.Runtime(), `var receiver=new Client({url:'https://example.test',keys:{trust:[cert]},security:{timestamp:{clockOffsetSeconds:300,ttlSeconds:3600},verify:{signature:true,clockSkewSeconds:0,maxAgeSeconds:300}}});
 var skip=new Client({url:'https://example.test',keys:{trust:[cert]},security:{verify:{signature:true,timestamp:false,clockSkewSeconds:0,maxAgeSeconds:1}}});
 for(const option of ['now','clock','random']){try{new Client({url:'https://example.test',[option]:()=>0});throw new Error('public clock/random override accepted');}catch(e){if(e.code!=='INVALID_ARGUMENT')throw e;}}`)
	rt.MoveToVUContext(&lib.State{})
	clockNow = created.Add(300*time.Second - time.Nanosecond)
	js(t, rt.VU.Runtime(), `var good=receiver.parse({status:200,body:wire});if(!good.ok||good.sigVerified!==true||good.timestampValid!==true)throw new Error('valid timestamp rejected');`)
	clockNow = created.Add(300 * time.Second)
	js(t, rt.VU.Runtime(), `var bad=receiver.parse({status:500,body:wire});if(bad.ok||bad.body!==null||bad.fault!==null||bad.error.code!=='TIMESTAMP_INVALID'||bad.sigVerified!==true||bad.timestampValid!==false||bad.xpath('string(.)').error.code!=='CONTENT_UNAVAILABLE')throw new Error('outbound offset affected receive tolerance');
 var skipped=skip.parse({status:200,body:wire});if(!skipped.ok||skipped.sigVerified!==true||skipped.timestampValid!==null)throw new Error('freshness skip changed');`)
}
