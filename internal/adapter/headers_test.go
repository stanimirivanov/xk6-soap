package adapter

import (
	"go.k6.io/k6/v2/lib"
	"testing"
)

func TestHeaderBindings(t *testing.T) {
	rt := clientRuntime(t)
	js(t, rt.VU.Runtime(), `var client=new Client({url:'https://example.test/service'});`)
	rt.MoveToVUContext(&lib.State{})
	js(t, rt.VU.Runtime(), `
 var opts={headers:[{name:'trace',xml:'<h:Trace xmlns:h="urn:trace">one</h:Trace>'}],addressing:{action:'urn:echo',to:'https://example.test/service',messageId:'urn:id:one',replyTo:'http://www.w3.org/2005/08/addressing/anonymous'}};
 var req=client.build('Echo','<Echo/>',opts);
 if(!req.body.includes('MessageID')||!req.body.includes('Trace')||req.headers.SOAPAction!=='"urn:echo"') throw new Error('header binding');
 for (var bad of [null,{},[null],new Array(1),[new Proxy({name:"trace",xml:"<h:T xmlns:h=\"urn:t\"/>"},{})],[{name:'trace',xml:4}],[{name:'trace',xml:'<h:T xmlns:h="urn:t"/>',extra:1}]]) {
  try {client.build('Echo','<Echo/>',{headers:bad});throw new Error('accepted');} catch(e){if(e.code!=='INVALID_ARGUMENT')throw e;}
 }
 for (var bad of [null,{}, {action:'urn:a',to:'https://example.test/service',messageId:'urn:id',replyTo:3}]) {
  try {client.build('Echo','<Echo/>',{addressing:bad});throw new Error('accepted');} catch(e){if(e.code!=='INVALID_ARGUMENT')throw e;}
 }
 var accessor={get headers(){throw new Error('SECRET');}};
 try {client.build('Echo','<Echo/>',accessor);throw new Error('accepted');}catch(e){if(e.code!=='INVALID_ARGUMENT'||String(e).includes('SECRET'))throw e;}
 `)
}

func TestPublicSignedHeaderInputs(t *testing.T) {
	rt := keyRuntime(t, New())
	js(t, rt.VU.Runtime(), `var client=new Client({url:'https://example.test',keys:{signing:{cert,key},trust:[cert]},security:{sign:{headers:['trace']},verify:{signedHeaders:[{namespace:'urn:trace',localName:'Trace'}]}}});`)
	rt.MoveToVUContext(&lib.State{})
	js(t, rt.VU.Runtime(), `
 var opts={headers:[{name:'trace',xml:'<h:Trace xmlns:h="urn:trace">original</h:Trace>'}],addressing:{action:'urn:echo',to:'https://example.test',messageId:'urn:id',replyTo:'urn:reply'}};
 var request=client.build('Echo','<Echo/>',opts);
 var parsed=client.parse({status:200,body:request.body});if(!parsed.ok||parsed.sigVerified!==true)throw new Error('public signed headers');
 var bad=client.parse({status:200,body:request.body.replace('original','changed')});if(bad.ok||bad.body!==null||bad.sigVerified!==false)throw new Error('tampered selected header accepted');
 try{client.build('Echo','<Echo/>');throw new Error('missing selector accepted')}catch(e){if(e.code!=='SOAP_SIGNATURE_BUILD_FAILED')throw e;}
 opts.soapAction='';try{client.build('Echo','<Echo/>',opts);throw new Error('action mismatch accepted')}catch(e){if(e.code!=='INVALID_ARGUMENT')throw e;}
 `)
}
