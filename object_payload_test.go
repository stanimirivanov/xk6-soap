package soap

import (
	"github.com/stanimirivanov/xk6-soap/internal/wssec"
	"strings"
	"testing"
	"time"

	"go.k6.io/k6/v2/lib"
)

func TestObjectPayloadOrderedEnvelope(t *testing.T) {
	rt := clientRuntime(t)
	js(t, rt.VU.Runtime(), `var client=new Client({url:'https://example.test',namespace:'urn:test'});`)
	rt.MoveToVUContext(&lib.State{})
	value, e := rt.VU.Runtime().RunString(`client.build('Echo',{'@id':'a&"',z:'last',a:['one','two'],item:{'@flag':true,'#text':'<&'},empty:{},none:[]}).body`)
	if e != nil {
		t.Fatal(e)
	}
	want := `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><Echo xmlns="urn:test" id="a&amp;&#34;">` + `<z>last</z><a>one</a><a>two</a><item flag="true">&lt;&amp;</item><empty></empty></Echo></s:Body></s:Envelope>`
	if value.String() != want {
		t.Fatalf("object envelope:\n%s\nwant:\n%s", value.String(), want)
	}
	js(t, rt.VU.Runtime(), `const raw='<m:Echo xmlns:m="urn:raw"><m:x><![CDATA[a<b]]></m:x></m:Echo>';if(client.build('Echo',raw).body!=='<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>'+raw+'</s:Body></s:Envelope>')throw new Error('raw XML changed');`)
}

func TestObjectPayloadTypesOrderAndRejections(t *testing.T) {
	rt := clientRuntime(t)
	js(t, rt.VU.Runtime(), `var client=new Client({url:'https://example.test',namespace:'urn:test'});var plain=new Client({url:'https://example.test'});`)
	rt.MoveToVUContext(&lib.State{})
	js(t, rt.VU.Runtime(), `
 function rejects(value){let caught=false;try{client.build('Echo',value)}catch(e){caught=true;if(e.code!=='INVALID_ARGUMENT'||String(e).includes('PRIVATE'))throw e;}if(!caught)throw new Error('invalid object accepted');}
 let cycle={};cycle.self=cycle;let arrayCycle=[];arrayCycle.push(arrayCycle);
 class CustomArray extends Array{};rejects({x:new CustomArray(1)});
 const hidden=Object.create(null);hidden.z=1;Object.defineProperty(hidden,'ignored',{value:'PRIVATE',enumerable:false});hidden.a=2;
 const shared={value:3};const reordered={z:'z',a:'a'};delete reordered.z;reordered.z='last';
 const result=client.build('Echo',{first:hidden,one:shared,two:shared,ordered:reordered,n:-0,b:false}).body;
 if(!result.includes('<first><z>1</z><a>2</a></first>')||!result.includes('<ordered><a>a</a><z>last</z></ordered>')||!result.includes('<n>0</n><b>false</b>')||result.includes('PRIVATE'))throw new Error('enumeration/scalar/shared reference mapping');
 for(const value of [null,undefined,1,true,1n,Symbol('PRIVATE'),()=>1,[],new Date(),new Map(),new Set(),new String('x'),new Uint8Array(1),Object.create({x:1}),new Proxy({x:1},{}),cycle,
 {x:null},{x:undefined},{x:NaN},{x:Infinity},{x:1n},{x:Symbol('PRIVATE')},{x:()=>1},{x:new Date()},{x:arrayCycle},{x:[[1]]},{x:[,1]},
 {'p:x':'a'},{xmlns:'urn:x'},{'@xmlns':'urn:x'},{'@p:x':'a'},{'@':'x'},{'1':'x'},{'a b':'x'},
 {'#text':'a',x:1},{'#text':'a',x:[]},{'#text':{}},{'@a':[]},{x:'\u0000'},{x:'\ud800'},{x:'\udc00'},{'\ud800':1},
 {[Symbol('PRIVATE')]:1},{get x(){throw new Error('PRIVATE_GETTER')}},
 ])rejects(value);
 const proto={late:'PRIVATE_INHERITED'};Object.prototype.late=proto.late;
 try{const object={get early(){delete object.late;return 'ok'},late:'own'};rejects(object)}finally{delete Object.prototype.late}
 try{plain.build('Echo',{});throw new Error('missing namespace accepted')}catch(e){if(e.code!=='INVALID_ARGUMENT')throw e;}
 `)
}

func TestNamespaceValidation(t *testing.T) {
	rt := clientRuntime(t)
	js(t, rt.VU.Runtime(), `for(const namespace of ['',null,undefined,1,{},Symbol('PRIVATE'),'urn:\u0000','\ud800','http://www.w3.org/2000/xmlns/','http://www.w3.org/XML/1998/namespace']){let caught=false;try{new Client({url:'https://example.test',namespace})}catch(e){caught=true;if(e.code!=='INVALID_ARGUMENT')throw e;}if(!caught)throw new Error('invalid namespace accepted');}
 try{new Client({url:'https://example.test',get namespace(){throw new Error('PRIVATE_ACCESSOR')}});throw new Error('namespace accessor accepted')}catch(e){if(e.code!=='INVALID_ARGUMENT'||String(e).includes('PRIVATE'))throw e;}
 try{new Client({url:'https://example.test',namespace:{get x(){throw new Error('PRIVATE_NAMESPACE')}}});throw new Error('bad namespace accepted')}catch(e){if(e.code!=='INVALID_ARGUMENT'||String(e).includes('PRIVATE'))throw e;}`)
}

func TestObjectPayloadLimitsAndAccessors(t *testing.T) {
	rt := clientRuntime(t)
	js(t, rt.VU.Runtime(), `var client=new Client({url:'https://example.test',namespace:'urn:test'});
 var small=new Client({url:'https://example.test',namespace:'urn:test',limits:{bytes:256,depth:5,nodes:20,attributes:2}});`)
	rt.MoveToVUContext(&lib.State{})
	js(t, rt.VU.Runtime(), `for(const value of [{x:'&'.repeat(200)},{a:{b:{c:{d:1}}}},{'@a':1,'@b':2,'@c':3},{x:Array(30).fill(1)}]){let caught=false;try{small.build('Echo',value)}catch(e){caught=true;if(e.code!=='LIMIT_EXCEEDED')throw e;}if(!caught)throw new Error('object limit ignored');}
 const object={get z(){object.added='not captured';return 1},a:2};const first=client.build('Echo',object).body;if(!first.includes('<z>1</z><a>2</a>')||first.includes('not captured'))throw new Error('keys were not snapshotted');
 if(!client.build('Echo',{x:'😀'}).body.includes('😀'))throw new Error('valid surrogate pair lost');`)
}

func TestObjectPayloadSignedBuild(t *testing.T) {
	rt := keyRuntime(t, New())
	js(t, rt.VU.Runtime(), `var client=new Client({url:'https://example.test',namespace:'urn:test',keys:{signing:{cert,key}},security:{sign:{},verify:{signature:false}}});`)
	rt.MoveToVUContext(&lib.State{})
	value, e := rt.VU.Runtime().RunString(`client.build('Echo',{z:'first',a:['one','two']}).body`)
	if e != nil {
		t.Fatal(e)
	}
	verified, e := wssec.Verify([]byte(value.String()), signingCertificate(t), time.Now())
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(verified.Body), `<z>first</z><a>one</a><a>two</a>`) {
		t.Fatal("signed object order changed", string(verified.Body))
	}
}

func TestObjectPayloadCancellationDuringGetter(t *testing.T) {
	rt := clientRuntime(t)
	rt.VU.Runtime().Set("cancelPayload", func() { rt.CancelContext() })
	js(t, rt.VU.Runtime(), `var client=new Client({url:'https://example.test',namespace:'urn:test'});`)
	rt.MoveToVUContext(&lib.State{})
	js(t, rt.VU.Runtime(), `let caught=false;try{client.build('Echo',{get '#text'(){cancelPayload();return 'PRIVATE'}})}catch(e){caught=true;if(e.code!=='CANCELLED')throw e;}if(!caught)throw new Error('canceled object build returned a request');`)
}
