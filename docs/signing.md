# Core signed SOAP requests

PR-11 enables outbound RSA-SHA256 signatures with SHA256 reference digests,
exclusive C14N and a BinarySecurityToken direct reference (`keyId:'direct'` is
an alias for `binary-security-token`). Body and Timestamp are always signed;
a configured UsernameToken is also signed. SOAP 1.1 and 1.2 use the same profile.

```js
import { Client } from 'k6/x/soap';
import http from 'k6/http';

const client = new Client({
  url:'https://example.test/service',
  keys:{signing:{cert:open('./client-cert.pem','b'),key:open('./client-key.pem','b')}},
  security:{
    sign:{},
    // PR-12 adds response verification. Explicitly opt out for this stage.
    verify:{signature:false},
    // Optional: usernameToken:{user:'synthetic-user',password:'synthetic-password'},
  },
});
export default function() {
  const request=client.build('Echo','<Echo>synthetic</Echo>');
  const response=http.post(request.url,request.body,{headers:request.headers});
  // Use client.parse(response) for plain responses only at this stage.
}
```

Send `request.body` unchanged: edits or reparsing/reserialization can invalidate
its signature. Do not log it; signed content remains readable. k6 owns HTTP,
TLS, file loading and credentials supplied by the script.

The default receive signature requirement still follows outbound signing. Until
PR-12, omitting the explicit opt-out above fails at construction. This stage does
not authenticate responses: parse verification flags remain null, and mandatory
response Security headers are rejected by the plain parser. Do not use this
opt-out when your service requires verified responses.

Validated cached signing material stays immutable; only its `crypto.Signer`
interface reaches the provider. Each build owns a fresh XML tree, Timestamp,
optional UsernameToken/nonce and signature. References target the actual Body,
Timestamp and present token. One bounded final serialization follows signing,
with envelope limits checked on the result. Per-build credential overrides are
applied before signing and never mutate constructor defaults.

Other signing algorithms/digests/key IDs, custom signed headers, encryption and
receive security remain unavailable. Unknown options, invalid keys and unsupported
profiles fail before transport. Raw XML payload namespace semantics, including
QName-valued text, retain the limitations documented in the
[signature kernel decision](adr/0002-signature-kernel.md); no inclusive-prefix
configuration is exposed by this core profile.

Tests verify deterministic compatibility with the accepted RSA/canonical fixtures,
exact node coverage and digests after final wire parsing, tamper and size failures,
profile rejection and metadata-only diagnostics. Native k6 exchanges against the
[independent Apache fixture](../test/interop/README.md) cover both SOAP versions
and optional Digest/Text UsernameTokens. These checks do not complete the broader
signed-response checkpoint or enable future profiles.
