# Signed SOAP requests

Signing defaults to RSA-SHA256 with SHA-256 reference digests, exclusive C14N
and a BinarySecurityToken direct reference (`keyId:'direct'` is
an alias for `binary-security-token`). Body and Timestamp are always signed;
a configured UsernameToken is also signed. SOAP 1.1 and 1.2 use the same profile.

```js
import { Client } from 'k6/x/soap';
import http from 'k6/http';

const client = new Client({
  url:'https://example.test/service',
  keys:{signing:{cert:open('./client-cert.pem','b'),key:open('./client-key.pem','b')},
    trust:[open('./server-cert.pem','b')]},
  security:{
    sign:{},
    // Signature and Timestamp verification default true when signing is enabled.
    // Optional: usernameToken:{user:'synthetic-user',password:'synthetic-password'},
  },
});
export default function() {
  const request=client.build('Echo','<Echo>synthetic</Echo>');
  const response=http.post(request.url,request.body,{headers:request.headers});
  const result=client.parse(response); // Body/fault available after acceptance.
}
```

Send `request.body` unchanged: edits or reparsing/reserialization can invalidate
its signature. Do not log it; signed content remains readable. k6 owns HTTP,
TLS, file loading and credentials supplied by the script.

The receive signature requirement follows outbound signing and requires exact
server leaf certificate pins. [Core response verification](receive.md) is available.
An explicit `verify:{signature:false}` skips authentication and leaves result
verification flags null; it does not authenticate the response.

Validated cached signing material stays immutable; only its `crypto.Signer`
interface reaches the provider. Each build owns a fresh XML tree, Timestamp,
optional UsernameToken/nonce and signature. References target the actual Body,
Timestamp and present token. One bounded final serialization follows signing,
with envelope limits checked on the result. Per-build credential overrides are
applied before signing and never mutate constructor defaults.

[Custom signed headers and WS-Addressing](headers.md) are available in PR-16.
Encryption and decryption remain unavailable. Unknown options, invalid keys and unsupported
profiles fail before transport. Raw XML payload namespace semantics, including
QName-valued text, retain the limitations documented in the
[signature kernel decision](adr/0002-signature-kernel.md); no inclusive-prefix
configuration is exposed by this core profile.

Set `security.sign.keyId` to choose the wire identifier:

| Value | Wire representation |
| --- | --- |
| `binary-security-token` (default), `direct` | Local reference to an X509v3 BinarySecurityToken |
| `issuer-serial` | X.509 issuer distinguished name and decimal serial number |
| `x509keyidentifier` | X509v3 KeyIdentifier carrying certificate DER |
| `ski` | KeyIdentifier carrying the certificate's Subject Key Identifier extension |
| `ThumbprintSHA1` | KeyIdentifier carrying the certificate's SHA-1 thumbprint |

SKI requires the extension on the signing certificate. ThumbprintSHA1 names
the certificate only. Signature and reference digest algorithms remain SHA-2.

Set `security.sign.algorithm` to `rsa-sha256`, `rsa-sha384`, `rsa-sha512`,
`ecdsa-sha256`, `ecdsa-sha384` or `ecdsa-sha512`. RSA requires at least 2048
bits. The ECDSA choices require P-256, P-384 and P-521 respectively and use
64-, 96- and 132-byte XMLDSig signature values before Base64 encoding.
`security.sign.digest` independently selects `sha256`, `sha384` or `sha512`
for the reference digests.

To accept a peer's non-default response algorithms, set
`security.verify.signatureAlgorithms` and `security.verify.digestAlgorithms`
explicitly. For example, `{signatureAlgorithms:['ecdsa-sha384'],
digestAlgorithms:['sha384']}` accepts that combination with a pinned P-384
certificate. Outbound settings do not expand the receive defaults.

Tests verify deterministic compatibility with the accepted RSA/canonical fixtures,
exact node coverage and digests after final wire parsing, tamper and size failures,
profile rejection and metadata-only diagnostics. Native k6 exchanges against the
[independent Apache fixture](../test/interop/README.md) cover both SOAP versions
and optional Digest/Text UsernameTokens. Separate receive tests cover independently
signed responses and faults; broader profiles remain separate checkpoint work.
