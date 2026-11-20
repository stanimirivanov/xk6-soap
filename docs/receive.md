# Core verified responses

PR-12 enables RSA-SHA256/SHA256, exclusive C14N (including validated inclusive
prefix lists), BST direct-reference response verification with exact leaf DER
pins. HTTP stays in k6/http. Plain SOAP behavior remains available.

```js
import {Client} from 'k6/x/soap';
import http from 'k6/http';
import {check} from 'k6';
const client=new Client({
  url:'https://example.test/service',
  keys:{
    signing:{cert:open('./client-cert.pem','b'),key:open('./client-key.pem','b')},
    trust:[open('./server-cert.pem','b')],
  },
  security:{sign:{}}, // Defaults to required signature and Timestamp on receive.
});
export const options={thresholds:{checks:['rate==1']}};
export default function(){
  const request=client.build('Echo','<Echo>synthetic</Echo>');
  const result=client.parse(http.post(request.url,request.body,{headers:request.headers}));
  check(result,{'authenticated SOAP success':p=>p.ok&&p.sigVerified===true&&p.timestampValid===true});
}
```

A receive-only client can omit signing and use `security:{verify:{signature:true}}`
with `keys.trust`. Trust is an array of 1–8 exact server leaf certificates, with
validity, key size and KeyUsage checked at use. Multiple pins support manual
rotation. A certificate carrying the same public key with different DER is not
trusted. Embedded certificates never grant trust, and no network key resolution,
chain building or system roots are used.

The acceptance path checks configured SOAP version, input/structure limits, unique
IDs, one targeted Security header, one direct BST and one signature, and at most
one Timestamp. Unsupported algorithms, transforms, key representations, encryption
and ambiguous security structure fail closed. Current required custom headers and
WS-Addressing receive paths remain gated until their implementation tasks; present
WS-Addressing headers are rejected by verified core receive.

References must cover the actual direct Body and any present Timestamp. The
provider verifies the exact nodes in one request-local tree. Canonicalization of
SignedInfo and references is bounded before cryptographic verification to prevent
namespace expansion exceeding the configured byte budget. Canonical bytes of that
same Body, including its verified inclusive namespace context, stay private until
all required checks succeed. Fault and XPath processing receives only those bytes,
with namespace bindings retained for the returned inner XML; it cannot reselect a
Body from the original envelope. Namespace copying has a finite expansion budget.

`sigVerified` is true after successful signature/trust/coverage checks, false when
required signature acceptance fails, and null when skipped or not reached.
`timestampValid` is true after its required check, false on that check's failure,
and null when skipped or not reached. A failed required check leaves Body and fault
null; XPath yields `CONTENT_UNAVAILABLE`. XML/transport/availability errors precede
security. After security acceptance, a SOAP fault is retained with `SOAP_FAULT`
even on HTTP 4xx/5xx; other non-2xx responses use `HTTP_STATUS`.

Explicit `verify:{signature:false}` skips cryptographic authentication and freshness,
leaving both flags null even on signed input. Supported signed content may be read
without authentication; unsupported structures/algorithms/key references are still
rejected and never executed. `verify:{signature:true,timestamp:false}` authenticates
Body and any present Timestamp but skips freshness, leaving `timestampValid` null.
The core profile still requires coverage of a present Timestamp.

The existing kernel's default freshness check (300-second age/lifetime, 60-second
skew) remains active when required. Configurable skew/max-age activation and the
full freshness boundary suite are PR-13; nondefault values with required signature
verification currently fail construction with `SOAP_FEATURE_UNAVAILABLE`. Freshness
is distinct from replay detection. Encryption/order/decryption, broader algorithms,
key IDs and custom headers remain gated. No broader signed-response checkpoint is
claimed by this task alone.

Evidence includes hostile exact-coverage/duplicate-ID fixtures, a different DER
certificate with the same public key, overlapping pins, namespace-preserving
projection and canonical expansion limits, and real k6 exchanges against independently
signed WSS4J responses and service faults for both SOAP versions. Metadata-only
logging is checked with synthetic private response sentinels.
