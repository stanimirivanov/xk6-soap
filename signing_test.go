package soap

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stanimirivanov/xk6-soap/internal/wssec"
	"go.k6.io/k6/v2/lib"
)

func TestSignedPublicBuild(t *testing.T) {
	rt := keyRuntime(t, New())
	js(t, rt.VU.Runtime(), `var signer=new Client({url:'https://example.test',keys:{signing:{cert,key}},security:{sign:{},verify:{signature:false}}});`)
	rt.MoveToVUContext(&lib.State{})
	v, err := rt.VU.Runtime().RunString(`signer.build('Echo','<Echo>SIGN_PRIVATE_PAYLOAD</Echo>').body`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = wssec.Verify([]byte(v.String()), signingCertificate(t), time.Now()); err != nil {
		t.Fatal("public wire signature", err)
	}
	if strings.Count(v.String(), "<ds:Signature ") != 1 {
		t.Fatal("missing single signature")
	}
}

func signingCertificate(t *testing.T) *x509.Certificate {
	t.Helper()
	b, e := os.ReadFile("internal/wssec/testdata/signing-cert.pem")
	if e != nil {
		t.Fatal(e)
	}
	block, _ := pem.Decode(b)
	c, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	return c
}

func TestPublicSigningRejectsUnsupportedProfiles(t *testing.T) {
	rt := keyRuntime(t, New())
	js(t, rt.VU.Runtime(), `for(const sign of [{keyId:'issuer-serial'},{keyId:'ski'}]){let caught=false;try{new Client({url:'https://example.test',keys:{signing:{cert,key}},security:{sign,verify:{signature:false}}});}catch(e){caught=true;if(e.code!=='SOAP_FEATURE_UNAVAILABLE')throw e;}if(!caught)throw new Error('unsupported signing profile activated');}`)
}
