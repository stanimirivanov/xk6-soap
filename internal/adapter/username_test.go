package adapter

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"go.k6.io/k6/v2/js/modulestest"
	"go.k6.io/k6/v2/lib"
)

func TestUsernameTokenPublicBuildAndOverrides(t *testing.T) {
	rt := clientRuntime(t)
	js(t, rt.VU.Runtime(), `var tokenClient=new Client({url:'https://example.test',security:{usernameToken:{user:'default-user',password:'PRIVATE_DEFAULT',passwordType:'PasswordText'},timestamp:{ttlSeconds:1,clockOffsetSeconds:-1}}});`)
	rt.MoveToVUContext(&lib.State{})
	js(t, rt.VU.Runtime(), `var a=tokenClient.build('Echo','<Echo/>',{credentials:{user:'override-user',password:'PRIVATE_OVERRIDE'}});var b=tokenClient.build('Echo','<Echo/>');var c=tokenClient.build('Echo','<Echo/>');
 if(!a.body.includes('PRIVATE_OVERRIDE')||a.body.includes('PRIVATE_DEFAULT')||!b.body.includes('PRIVATE_DEFAULT')||b.body.includes('PRIVATE_OVERRIDE')||b.body===c.body)throw new Error('override/default/freshness failure');
 for(const credentials of [{user:'x'},{password:'PRIVATE'},{user:'x',password:'PRIVATE',passwordType:'PasswordDigest'},null,undefined]){try{tokenClient.build('Echo','<Echo/>',{credentials});throw new Error('bad override accepted');}catch(e){if(e.code!=='INVALID_ARGUMENT'||String(e).includes('PRIVATE'))throw e;}}
 var result=tokenClient.parse({status:200,body:'<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><Echo/></s:Body></s:Envelope>'});if(!result.ok||result.sigVerified!==null||result.timestampValid!==null)throw new Error('unsigned response authenticity claim');`)
}
func TestRandomFailureThrowsWithoutCredentials(t *testing.T) {
	rt := modulestest.NewRuntime(t)
	instance := New().NewModuleInstance(rt.VU).(*instance)
	instance.random = brokenRandom{}
	rt.VU.Runtime().Set("Client", instance.Exports().Named["Client"])
	js(t, rt.VU.Runtime(), `var client=new Client({url:'https://example.test',security:{usernameToken:{user:'PRIVATE',password:'PRIVATE'}}});`)
	rt.MoveToVUContext(&lib.State{})
	js(t, rt.VU.Runtime(), `try{client.build('Echo','<Echo/>');throw new Error('RNG failure ignored');}catch(e){if(e.code!=='SOAP_RANDOM_FAILED'||e.stage!=='build'||String(e).includes('PRIVATE'))throw e;}`)
}

type brokenRandom struct{}

func (brokenRandom) Read([]byte) (int, error) { return 0, errors.New("PRIVATE_RNG") }
func TestTimestampOnlyPublicBuild(t *testing.T) {
	rt := modulestest.NewRuntime(t)
	instance := New().NewModuleInstance(rt.VU).(*instance)
	instance.now = func() time.Time { return time.Date(2030, 1, 2, 3, 4, 5, 999999999, time.FixedZone("synthetic", 3600)) }
	instance.random = brokenRandom{}
	rt.VU.Runtime().Set("Client", instance.Exports().Named["Client"])
	js(t, rt.VU.Runtime(), `var client=new Client({url:'https://example.test',soapVersion:'1.2',security:{timestamp:{ttlSeconds:3600,clockOffsetSeconds:300}}});`)
	rt.MoveToVUContext(&lib.State{})
	value, err := rt.VU.Runtime().RunString(`client.build('Echo','<Echo/>').body`)
	if err != nil {
		t.Fatal(err)
	}
	raw := value.String()
	if !strings.Contains(raw, "2030-01-02T02:09:05.999Z") || !strings.Contains(raw, "2030-01-02T03:09:05.999Z") || strings.Contains(raw, "UsernameToken") {
		t.Fatal("timestamp facade did not honor UTC/offset/TTL")
	}
	decoder := xml.NewDecoder(bytes.NewBufferString(raw))
	for {
		_, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}
