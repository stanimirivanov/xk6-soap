# Verified responses

Responses use the configured RSA or ECDSA SHA-2 policy, exclusive C14N
(including validated inclusive prefix lists), and [X.509 key identifiers](signing.md) with
exact leaf DER pins. The receive defaults are RSA-SHA256 and SHA-256.
[Configure expanded signature and digest allow-lists](signing.md) for peers
using other supported algorithms.

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

Under required verification, BST and inline X509v3 KeyIdentifier forms must
carry the exact DER of a trusted leaf. Issuer/serial, SKI and thumbprint forms
must match exactly one distinct, currently valid pin. If two leaf certificates
match an identifier, verification fails even if they share a public key.
The selected pin must also match the signature algorithm. No key is retrieved
from a network or from system trust.

The acceptance path checks configured SOAP version, input/structure limits, unique
IDs, one targeted Security header, one signature, one supported KeyInfo, and at most
one Timestamp. Unsupported algorithms, transforms, key representations, encryption
and ambiguous security structure fail closed. [Required custom headers and WS-Addressing](headers.md) are subject to the same exact coverage checks.

The [SOAP 1.2 Header compatibility rule](headers.md) applies to ordinary blocks
on the wire and after decryption. A signature over a plaintext Header block
covers the original SOAP 1.1 `mustUnderstand` attribute. Changing that attribute
after signing invalidates the signature. Security metadata and EncryptedHeader
wrapper metadata are validated under their respective rules.

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

PR-13 activates `clockSkewSeconds` (0–300, default 60) and `maxAgeSeconds`
(1–3600, default 300). Required Timestamp fields must be scalar UTC values: exactly
one Created followed by exactly one Expires, with no nested elements or mixed
Timestamp text. XML whitespace remains permitted. The actual
Timestamp, including both fields, must be covered by the trusted signature.
For receive time `now`, acceptance requires all of:

- `Expires > Created` and `Expires - Created <= maxAge`.
- `Created <= now + skew`.
- `now < Expires + skew` (equality is expired).
- `now - Created <= maxAge + skew`.

The age equality cannot override the strict expiry condition: when lifetime equals
maxAge, age at maxAge + skew also reaches expiry + skew and is rejected. Tests use
an injected Go-only clock for nanosecond boundary checks without waiting or changing
production randomness. Receive time is sampled independently of outbound Timestamp
clock offset/TTL; neither silently widens receive tolerance.

Freshness is distinct from replay detection. Repeated parsing of the same valid
response is permitted while it remains fresh; no receive replay cache is introduced.
[Required signed custom headers and WS-Addressing coverage](headers.md) are available.
## Encrypted responses and faults

Supply a decryption identity and explicitly set the receive order. Keep your
usual trust pins for the signing certificate.

```js
const client = new Client({
  url: 'https://example.test/service',
  keys: {
    decryption: {cert: open('./client-cert.pem', 'b'), key: open('./client-key.pem', 'b')},
    trust: [open('./server-signing-cert.pem', 'b')],
  },
  security: {
    verify: {signature: true, order: 'sign-then-encrypt', requireEncryption: true},
  },
});
```

The Body profile uses one wholly encrypted Body region and one local
EncryptedKey identifying the configured RSA decryption certificate by issuer
and serial. The Body content or its sole operation element may be encrypted
with AES-128/256-GCM. Key transport uses RSA-OAEP with SHA-256 and MGF1-SHA256.
[Selected headers](headers.md#encrypting-selected-headers) can also be protected.
Header-only protection does not satisfy required Body encryption.

With `requireEncryption: true`, unauthenticated, plain or partially encrypted
Bodies cannot yield content. Omit that flag to accept either a valid signed
plain reply or a valid signed encrypted reply. Both paths require signature
verification. The explicit receive order is independent of outbound order. Set it to
`encrypt-then-sign` when the peer signs ciphertext.

With sign-then-encrypt, the client recovers the XML before verifying the
signature over the plaintext Body. With encrypt-then-sign, it verifies the
ciphertext Body, the EncryptedKey it will use, required headers and applicable
Timestamp checks before decryption. The client applies the configured order
without fallback. Both orders enforce XML and ID limits after decryption.
Body, Fault and XPath become available only after acceptance. GCM or key failures return `DECRYPTION_FAILED` with a fixed
message. A valid encrypted SOAP fault returns `SOAP_FAULT` with its accepted
fault details after verification.

Evidence includes hostile exact-coverage/duplicate-ID fixtures, a different DER
certificate with the same public key, overlapping pins, namespace-preserving
projection and canonical expansion limits, and real k6 exchanges against independently
signed WSS4J responses and service faults for both SOAP versions, including stale
and future-dated Timestamp fixtures generated before Apache signs them. Metadata-only
logging is checked with synthetic private response sentinels.
