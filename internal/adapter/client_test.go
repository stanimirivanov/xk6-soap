package adapter

import (
	"testing"

	"github.com/grafana/sobek"
	"go.k6.io/k6/v2/js/modulestest"
	"go.k6.io/k6/v2/lib"
)

func clientRuntime(t *testing.T) *modulestest.Runtime {
	t.Helper()
	rt := modulestest.NewRuntime(t)
	if err := rt.VU.Runtime().Set("Client", New().NewModuleInstance(rt.VU).Exports().Named["Client"]); err != nil {
		t.Fatal(err)
	}
	return rt
}
func js(t *testing.T, rt *sobek.Runtime, source string) {
	t.Helper()
	if _, err := rt.RunString(source); err != nil {
		t.Fatal(err)
	}
}
func TestPlainClientBindings(t *testing.T) {
	rt := clientRuntime(t)
	js(t, rt.VU.Runtime(), `var client = new Client({url:'https://example.test/service',soapVersion:'1.1'});
 try { client.build('Echo','<Echo/>'); throw new Error('accepted init build'); } catch(e) { if(e.code!=='SOAP_EXECUTION_ONLY') throw e; }`)
	rt.MoveToVUContext(&lib.State{})
	js(t, rt.VU.Runtime(), `var req=client.build('Echo','<m:Echo xmlns:m="urn:test">yes</m:Echo>',{soapAction:'urn:echo'});
 if(req.url!=='https://example.test/service'||req.headers.SOAPAction!=='"urn:echo"'||typeof req.buildDuration!=='number') throw new Error('request shape');
 var parsed=client.parse({status:200,body:req.body});
 if(!parsed.ok||parsed.error!==null||parsed.fault!==null||parsed.sigVerified!==null||parsed.timestampValid!==null) throw new Error('result shape');
 var nodes=parsed.xpath('//m:Echo',{m:'urn:test'});
 if(nodes.error!==null||nodes.value.length!==1||nodes.value[0]!=='yes') throw new Error('xpath result');
 if(parsed.xpath('count(//m:Echo)',{m:'urn:test'}).value!==1) throw new Error('scalar type');
 if(parsed.xpath('//missing:Echo').error.code!=='XPATH_INVALID') throw new Error('missing prefix');
 if(client.parse({status:0,body:123}).error.code!=='TRANSPORT_ERROR') throw new Error('transport precedence');
 for(var body of [null,undefined,'']) if(client.parse({status:204,body}).error.code!=='BODY_UNAVAILABLE') throw new Error('unavailable');
 var binary = new TextEncoder().encode(req.body).buffer;
 if(!client.parse({status:200,body:binary}).ok) throw new Error('binary body');
 if(client.parse({status:200,body:new Uint8Array([255]).buffer}).error.code!=='XML_INVALID') throw new Error('utf8');
 var bad=client.parse({status:200,body:'SECRET invalid XML'});
 if(bad.body!==null||bad.error.code!=='XML_INVALID'||bad.error.message.includes('SECRET')||bad.xpath('//*').error.code!=='CONTENT_UNAVAILABLE') throw new Error('remote error');
 for(var fn of [()=>client.build('Echo',{}),()=>client.build('Echo','<Echo/>',{unknown:true}),()=>client.parse({status:'200',body:req.body}),()=>client.parse(null),()=>client.parse({status:200,body:5})]) {
  try {fn();throw new Error('invalid accepted');} catch(e) {if(e.code!=='INVALID_ARGUMENT') throw e;}
 }
 `)
}
func TestClientOptionValidation(t *testing.T) {
	rt := clientRuntime(t)
	js(t, rt.VU.Runtime(), `for(var cfg of [null,{}, {url:'file:///SECRET'}, {url:'https://u:SECRET@example.test'}, {url:'https://example.test',typo:1}, {url:'https://example.test',soapVersion:'2'}, {url:'https://example.test',securityTypo:{}}, {url:'https://example.test',limits:{depth:65}}, {url:'https://example.test',limits:{depth:'3'}}, {url:'https://example.test',debug:'true'}]) {
 try {new Client(cfg);throw new Error('invalid accepted');} catch(e) {if(e.code!=='INVALID_ARGUMENT'||String(e).includes('SECRET')) throw e;}
 }
 var small=new Client({url:'http://example.test',soapVersion:'1.2',limits:{bytes:20}});`)
	rt.MoveToVUContext(&lib.State{})
	js(t, rt.VU.Runtime(), `try {small.build('Echo','<Echo/>');throw new Error('limit ignored');} catch(e) {if(e.code!=='LIMIT_EXCEEDED') throw e;}`)
}
