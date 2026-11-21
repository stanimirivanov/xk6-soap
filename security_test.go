package soap

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stanimirivanov/xk6-soap/internal/wssec"
	"go.k6.io/k6/v2/lib"
)

func TestSecurityOptionMatrix(t *testing.T) {
	rt := keyRuntime(t, New())
	js(t, rt.VU.Runtime(), `
 function rejected(security,code,keys={signing:{cert,key},recipient:{cert},trust:[cert]}) {
  let caught=false;try{new Client({url:'https://SECRET.invalid',security,keys});}catch(e){caught=true;if(e.code!==code||e.stage!=='security'||String(e).includes('SECRET'))throw new Error('unexpected sanitized policy error: '+e.code+':'+e.stage);}
  if(!caught)throw new Error('security configuration silently ignored');
 }
 for (const security of [
  {encrypt:{}},
  {sign:{},encrypt:{}},
 ])rejected(security,'SOAP_FEATURE_UNAVAILABLE');
 for (const security of [null,false,[],{type:'SECRET'},{sign:{signBody:false}},{sign:{algorithm:'rsa-sha1'}},
  {usernameToken:{user:'SECRET'}},{usernameToken:{user:'SECRET',password:'SECRET',extra:true}},
  {usernameToken:{user:'u',password:'SECRET',passwordType:'SECRET'}},
  {timestamp:{ttlSeconds:0}},{timestamp:{clockOffsetSeconds:-301}},{timestamp:{ttlSeconds:1.5}},
  {timestamp:{ttlSeconds:NaN}},{timestamp:{ttlSeconds:Infinity}},{timestamp:{ttlSeconds:'300'}},
  {sign:{digest:'sha1'}},{sign:{canonicalization:'inclusive-c14n'}},{sign:{keyId:'SECRET'}},
  {sign:{algorithm:''}},{sign:{headers:['a','a']}},{sign:{headers:['bad:name']}},
  {sign:{headers:Array(17).fill('h')}},{encrypt:{target:'headers'}},{encrypt:{target:'body',headers:[]}},
  {encrypt:{algorithm:'aes-256-cbc'}},{encrypt:{keyTransport:'rsa-1_5'}},{encrypt:{headers:['h']}},
  {order:'sign-then-encrypt'},{sign:{},encrypt:{},order:'SECRET'},
  {verify:{timestamp:true,signature:false}},{verify:{signature:'true'}},{verify:{clockSkewSeconds:301}},
  {verify:{signatureAlgorithms:[]}},{verify:{digestAlgorithms:['sha1']}},
  {verify:{signedHeaders:[{namespace:'urn:test',localName:'h',extra:true}]}},
  {verify:{signedHeaders:[{namespace:'urn:test',localName:'h'}]}},
  {verify:{encryptedHeaders:[{namespace:'urn:test',localName:'h'}]}},
  {verify:{order:'encrypt-then-sign'}},{verify:{unexpected:'SECRET'}},
 ])rejected(security,'SOAP_POLICY_INVALID');
 rejected({sign:{}},'SOAP_POLICY_KEY',{});
 rejected({encrypt:{}},'SOAP_POLICY_KEY',{});
 rejected({verify:{signature:true}},'SOAP_POLICY_KEY',{});
 rejected(undefined,'SOAP_POLICY_INVALID',{decryption:{cert,key}});
 rejected({verify:{signature:true,requireEncryption:true,order:'encrypt-then-sign'}},'SOAP_FEATURE_UNAVAILABLE',{decryption:{cert,key},trust:[cert]});

 for(const block of ['usernameToken','timestamp','sign','encrypt','verify']) {
  rejected({[block]:{SECRET_UNKNOWN:true}},'SOAP_POLICY_INVALID');
  rejected({[block]:undefined},'SOAP_POLICY_INVALID');
 }
 rejected({sign:{algorithm:undefined}},'SOAP_POLICY_INVALID');
 rejected({verify:{signature:undefined}},'SOAP_POLICY_INVALID');
 rejected({timestamp:{ttlSeconds:undefined}},'SOAP_POLICY_INVALID');
 rejected(Object.create({sign:{}}),'SOAP_POLICY_INVALID');
 const accessor={};Object.defineProperty(accessor,'user',{get(){throw new Error('SECRET_ACCESSOR')}});rejected({usernameToken:accessor},'SOAP_POLICY_INVALID');
 const unknown={};Object.defineProperty(unknown,'SECRET',{value:true});rejected({timestamp:unknown},'SOAP_POLICY_INVALID');
 rejected({sign:{[Symbol('SECRET')]:true}},'SOAP_POLICY_INVALID');
 var plain=new Client({url:'https://example.test',security:{}});
 new Client({url:'https://example.test',security:{verify:{signature:false,timestamp:false,requireEncryption:false}}});
 `)
	rt.MoveToVUContext(&lib.State{})
	js(t, rt.VU.Runtime(), `for(const opts of [{security:{sign:{}}},{keys:{signing:{cert,key}}},{order:'sign-then-encrypt'}]) {try {plain.build('Echo','<Echo/>',opts);throw new Error('per-request security accepted');}catch(e){if(e.code!=='INVALID_ARGUMENT')throw e;}}`)
}
func TestMetadataDiagnosticsNeverReflectInputs(t *testing.T) {
	rt := keyRuntime(t, New())
	var output bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&output)
	logger.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})
	rt.VU.InitEnvField.Logger = logger
	js(t, rt.VU.Runtime(), `new Client({url:'https://SECRET.invalid'});`)
	if output.Len() != 0 {
		t.Fatal("diagnostics enabled by default")
	}
	js(t, rt.VU.Runtime(), `try{new Client({url:'https://SECRET.invalid',debug:true,keys:{signing:{cert,key},recipient:{cert},trust:[cert]},security:{sign:{algorithm:'rsa-sha384'},encrypt:{}}});throw new Error('unavailable accepted');}catch(e){if(e.code!=='SOAP_FEATURE_UNAVAILABLE')throw e;}
 var signedClient=new Client({url:'https://SECRET.invalid',debug:true,keys:{signing:{cert,key}},security:{sign:{},verify:{signature:false},usernameToken:{user:'SECRET_USER',password:'SECRET_PASSWORD',passwordType:'PasswordText'}}});var tokenClient=new Client({url:'https://SECRET.invalid',debug:true,security:{usernameToken:{user:'SECRET_USER',password:'SECRET_PASSWORD',passwordType:'PasswordText'}}});var client=new Client({url:'https://SECRET.invalid',debug:true});`)
	rt.MoveToVUContext(&lib.State{Logger: logger})
	js(t, rt.VU.Runtime(), `signedClient.build('Echo','<Echo>SECRET_SIGNED_PAYLOAD</Echo>');tokenClient.build('Echo','<Echo/>');var request=client.build('Echo','<Echo>SECRET_PAYLOAD</Echo>');client.parse({status:200,body:request.body});client.parse({status:500,body:'SECRET_FAULT'});`)
	logs := output.String()
	for _, required := range []string{"stage=constructor", "stage=build", "stage=parse", "duration_ms=", "algorithm=", "code=SOAP_FEATURE_UNAVAILABLE"} {
		if !strings.Contains(logs, required) {
			t.Fatalf("missing metadata %s", required)
		}
	}
	if strings.Contains(logs, "SECRET") || strings.Contains(logs, "PRIVATE KEY") || strings.Contains(logs, "<Echo>") {
		t.Fatal("diagnostics reflected private input")
	}
}

func TestRootAndKeyRecordsRejectHiddenUnknownOptions(t *testing.T) {
	rt := keyRuntime(t, New())
	js(t, rt.VU.Runtime(), `for(const cfg of [
 Object.defineProperty({url:'https://example.test'},'SECRET_UNKNOWN',{value:true}),
 {url:'https://example.test',[Symbol('SECRET_UNKNOWN')]:true},
 {url:'https://example.test',keys:{signing:Object.defineProperty({cert,key},'SECRET_UNKNOWN',{value:true})}},
 Object.assign(Object.create({security:{sign:{}}}),{url:'https://example.test'}),
 ]){let caught=false;try{new Client(cfg);}catch(e){caught=true;if(e.code!=='INVALID_ARGUMENT'||String(e).includes('SECRET'))throw e;}if(!caught)throw new Error('hidden or inherited unknown option accepted');}`)
}

func TestDiagnosticBoundaryRejectsUncheckedMetadata(t *testing.T) {
	rt := keyRuntime(t, New())
	var output bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&output)
	rt.VU.InitEnvField.Logger = logger
	instance := &instance{vu: rt.VU}
	instance.diagnostic(true, "SECRET_STAGE", time.Now(), wssec.Policy{Sign: &wssec.SigningPolicy{Algorithm: "SECRET_ALGORITHM"}}, "SECRET_CODE")
	if strings.Contains(output.String(), "SECRET") {
		t.Fatal("diagnostic boundary accepted unchecked metadata")
	}
}

func TestSecurityDecodingNonDefaultValues(t *testing.T) {
	root := New()
	rt := keyRuntime(t, root)
	instance := &instance{vu: rt.VU, keyCache: root.keyCache}
	value, err := rt.VU.Runtime().RunString(`({keys:{signing:{cert,key},recipient:{cert},decryption:{cert,key},trust:[cert]},security:{
 usernameToken:{user:'synthetic',password:'synthetic',passwordType:'PasswordText'},
 timestamp:{ttlSeconds:600,clockOffsetSeconds:-42},
 sign:{algorithm:'rsa-sha512',digest:'sha384',canonicalization:'exclusive-c14n',keyId:'issuer-serial',headers:['custom']},
 encrypt:{algorithm:'aes-128-gcm',keyTransport:'rsa-oaep-sha256',target:'headers',headers:['custom']},order:'encrypt-then-sign',
 verify:{signature:true,timestamp:false,requireEncryption:true,order:'sign-then-encrypt',signatureAlgorithms:['rsa-sha384'],digestAlgorithms:['sha512'],signedHeaders:[{namespace:'urn:custom',localName:'Header'}],encryptedHeaders:[{namespace:'urn:custom',localName:'Header'}],clockSkewSeconds:0,maxAgeSeconds:900}
 }})`)
	if err != nil {
		t.Fatal(err)
	}
	options := value.ToObject(rt.VU.Runtime())
	material := instance.decodeKeys(options.Get("keys"))
	p, err := wssec.CompilePolicy(instance.decodeSecurity(options), material.policyMaterial(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if p.UsernameToken.PasswordType != "PasswordText" || p.Timestamp.TTLSeconds != 600 || p.Timestamp.ClockOffsetSeconds != -42 || p.Sign.Algorithm != "rsa-sha512" || p.Sign.Digest != "sha384" || p.Sign.KeyID != "issuer-serial" || p.Sign.Headers[0] != "custom" || p.Encrypt.Algorithm != "aes-128-gcm" || p.Encrypt.Target != "headers" || p.Encrypt.Headers[0] != "custom" || p.Order != "encrypt-then-sign" {
		t.Fatal("outbound options were not decoded faithfully")
	}
	if !p.Receive.Signature || p.Receive.Timestamp || !p.Receive.RequireEncryption || p.Receive.Order != "sign-then-encrypt" || p.Receive.SignatureAlgorithms[0] != "rsa-sha384" || p.Receive.DigestAlgorithms[0] != "sha512" || p.Receive.ClockSkewSeconds != 0 || p.Receive.MaxAgeSeconds != 900 || p.Receive.SignedHeaders[0].Namespace != "urn:custom" || p.Receive.EncryptedHeaders[0].LocalName != "Header" {
		t.Fatal("receive options were not decoded faithfully")
	}
	if p.RequireAvailable() != wssec.ErrUnavailable {
		t.Fatal("internal definition unexpectedly activated public security")
	}
}
