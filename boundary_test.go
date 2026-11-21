package soap

import (
	"testing"

	"go.k6.io/k6/v2/lib"
)

func TestCancelledResponseGetterWithholdsResult(t *testing.T) {
	rt := clientRuntime(t)
	vm := rt.VU.Runtime()
	if err := vm.Set("cancelRead", func() { rt.CancelContext() }); err != nil {
		t.Fatal(err)
	}
	js(t, vm, `var client=new Client({url:'https://example.test'});`)
	rt.MoveToVUContext(&lib.State{})
	js(t, vm, `
  try {
    client.parse({status:200,get body(){cancelRead();return '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><Echo>private</Echo></s:Body></s:Envelope>';}});
    throw new Error('canceled parse returned content');
  } catch(e) { if(e.code !== 'CANCELLED') throw e; }
 `)
}

func TestResponseReadErrorsAreSanitized(t *testing.T) {
	rt := clientRuntime(t)
	vm := rt.VU.Runtime()
	js(t, vm, `var client=new Client({url:'https://example.test'});`)
	rt.MoveToVUContext(&lib.State{})
	js(t, vm, `
  var visited = false;
  for (const response of [
    {get status(){throw new Error('PRIVATE_GETTER');}},
    {status:200,get body(){throw new Error('PRIVATE_GETTER');}},
    {status:200,body:{get unexpected(){visited=true;throw new Error('PRIVATE_GETTER');}}},
  ]) {
    try { client.parse(response); throw new Error('accepted invalid response'); }
    catch(e) {if(e.code !== 'INVALID_ARGUMENT' || String(e).includes('PRIVATE_GETTER')) throw e;}
  }
  if(visited) throw new Error('response decoder traversed an invalid body object');
 `)
}

func FuzzSecurityOptions(f *testing.F) {
	for _, seed := range []string{
		`{}`, `{"verify":{"signature":false}}`, `{"timestamp":{"ttlSeconds":300}}`,
		`{"verify":{"requireEncryption":true}}`, `{"sign":{"headers":["trace","trace"]}}`,
		`{"encrypt":{"target":"headers","headers":["trace"]}}`, `{"verify":{"maxAgeSeconds":1e100}}`,
		`{"__proto__":{"verify":{}}}`, `{"PRIVATE_POLICY":true}`, `null`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 4096 {
			return
		}
		rt := clientRuntime(t)
		vm := rt.VU.Runtime()
		if err := vm.Set("policyJSON", input); err != nil {
			t.Fatal(err)
		}
		js(t, vm, `
   (() => {
     let security;
     try { security = JSON.parse(policyJSON); } catch (_) { return; }
     try { new Client({url:'https://example.test', security}); }
     catch (e) {
       const allowed = ['INVALID_ARGUMENT','SOAP_POLICY_INVALID','SOAP_POLICY_KEY','SOAP_FEATURE_UNAVAILABLE'];
       if (!allowed.includes(e.code) || String(e).includes('PRIVATE_POLICY')) {
         throw new Error('unsanitized or unexpected policy failure');
       }
     }
   })();
  `)
	})
}

func TestPolicyRejectsScalarObjectsWithoutTraversal(t *testing.T) {
	rt := clientRuntime(t)
	js(t, rt.VU.Runtime(), `
  let visited=false;
  const nonScalar={get private(){visited=true;throw new Error('PRIVATE_POLICY');}};
  for (const security of [
    {sign:{algorithm:nonScalar}},
    {timestamp:{ttlSeconds:nonScalar}},
    {verify:{signature:nonScalar}},
  ]) {
    try {new Client({url:'https://example.test',security});throw new Error('invalid policy accepted');}
    catch(e) {if(e.code!=='SOAP_POLICY_INVALID'||String(e).includes('PRIVATE_POLICY'))throw e;}
    if(visited)throw new Error('policy decoder traversed an invalid scalar object');
  }
 `)
}

func TestCancelledPlainBuildWithholdsResult(t *testing.T) {
	rt := clientRuntime(t)
	vm := rt.VU.Runtime()
	if err := vm.Set("cancelBuild", func() { rt.CancelContext() }); err != nil {
		t.Fatal(err)
	}
	js(t, vm, `var client=new Client({url:'https://example.test'});`)
	rt.MoveToVUContext(&lib.State{})
	js(t, vm, `
  try {
    client.build('Echo','<Echo/>',{get headers(){cancelBuild();return [];}});
    throw new Error('canceled build returned a request');
  } catch(e) { if(e.code !== 'CANCELLED') throw e; }
 `)
}

func TestXPathOptionsDoNotExposeAccessors(t *testing.T) {
	rt := clientRuntime(t)
	vm := rt.VU.Runtime()
	js(t, vm, `var client=new Client({url:'https://example.test'});`)
	rt.MoveToVUContext(&lib.State{})
	js(t, vm, `
  const parsed=client.parse({status:200,body:client.build('Echo','<Echo/>').body});
  let visited=false;
  const nonScalar={get private(){visited=true;throw new Error('PRIVATE_XPATH');}};
  for (const args of [
    [nonScalar],
    ['//*',{p:nonScalar}],
    ['//*',{get p(){throw new Error('PRIVATE_XPATH');}}],
  ]) {
    const result=parsed.xpath(...args);
    if(result.value!==null || result.error.code!=='XPATH_INVALID' ||
       result.error.message.includes('PRIVATE_XPATH') || visited)
      throw new Error('unsafe XPath option handling');
  }
 `)
}
