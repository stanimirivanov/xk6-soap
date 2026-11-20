# UsernameToken and Timestamp exchanges

PR-10 enables outbound UsernameToken (PasswordDigest or PasswordText) and
standalone Timestamp for SOAP 1.1/1.2. HTTP remains in k6/http. Responses in this
stage are plain SOAP; sending credentials does not authenticate a response.
[Core outbound signing](signing.md) can cover the token and Timestamp. Encryption,
required signature/Timestamp verification and decryption remain rejected by the
constructor capability gate.

```js
import { Client } from 'k6/x/soap';
import http from 'k6/http';

const client = new Client({url:__ENV.SOAP_URL, soapVersion:'1.2', security:{
  usernameToken:{user:__ENV.SOAP_USER, password:__ENV.SOAP_PASSWORD},
  timestamp:{ttlSeconds:300, clockOffsetSeconds:0},
}});
export default function () {
  const request = client.build('echo',
    '<m:echo xmlns:m="urn:example"><value>synthetic</value></m:echo>',
    {soapAction:'urn:echo'});
  const response = http.post(request.url,request.body,{
    headers:request.headers, responseType:'text', redirects:0,
  });
  const result = client.parse(response);
  // Inspect result.ok/error/fault. sigVerified and timestampValid stay null.
}
```

Use HTTPS for either password type. PasswordDigest is not transport encryption.
PasswordText is explicitly selected with `passwordType:'PasswordText'` and
places the password in the returned XML. Debug metadata never prints either.

## Wire construction

PasswordDigest defaults to:

`Base64(SHA-1(raw nonce bytes || UTF-8(exact serialized Created) || UTF-8(password)))`.

This is the OASIS UsernameToken protocol use of SHA-1, not XML Signature SHA-1
support. The nonce is 16 fresh CSPRNG bytes, encoded as Base64 on the wire. A
UsernameToken also emits Created and a nonce for PasswordText, so the selected
Apache profile can enforce freshness/replay checks for both forms.
[UsernameToken profile §3.1](https://docs.oasis-open.org/wss-m/wss/v1.1.1/os/wss-UsernameTokenProfile-v1.1.1-os.html).

The candidate XML builder owns namespaces, escaping and final serialization.
A private Timestamp adapter wraps its helper; no provider nodes escape the
adapter. Timestamp defaults to TTL 300 seconds and offset zero. UTC serialization
has three fractional digits; the offset is applied before serialization, and
Expires is Created plus TTL. The digest uses the Created string read from that
actual Timestamp node, not independently formatted nanosecond time. The same
string is emitted in the UsernameToken. SOAP mustUnderstand is namespace-qualified
`1` for 1.1 and `true` for 1.2; the Security header targets the ultimate receiver.

Every build reads the clock again, obtains a fresh nonce and builds a new tree.
Created values can coincide within one millisecond; nonces are not reused or
cached. Fixed IDs are scoped to that message; collisions with payload IDs fail.
A capped streaming serializer enforces the output byte budget, and the completed
wire is checked again against configured XML structural limits. Failures return
no partial request. No production nonce, clock or RNG override is exposed to JS.

All reported RNG errors fail, including an error accompanied by a complete read.
A non-progress read fails immediately; bounded partial reads are supported.
`SOAP_RANDOM_FAILED` and `SOAP_CREDENTIAL_BUILD_FAILED` errors have stage `build`,
without underlying error text. Limits throw `LIMIT_EXCEEDED`. Synchronous library
calls do not promise hard interruption; cancellation is checked around the stage.

## Per-build credentials

`build(operation,payload,{credentials:{user,password}})` overrides both fields
for that build only. Both are required strings; an explicit empty password is
permitted. The configured password type, Timestamp policy, key roles and receive
policy cannot be overridden. Unknown fields, wrong types, custom prototypes,
missing fields and accessor exceptions fail with sanitized local errors. Override
credentials are never placed in the shared key cache or written into defaults.
Supplying credentials without a configured UsernameToken is rejected.

Standalone Timestamp uses `security:{timestamp:{...}}` without UsernameToken.
It does not read randomness or insert credentials. Freshness choices at the
receiver belong to its policy; an unsigned Timestamp grants no authenticity or
replay protection by itself. This PR does not relax plain parse's rejection of
unsupported mandatory response Security headers or encrypted structures.

## CP-T1 evidence and limits

- An independent Python hashlib calculation fixes the Digest vector for raw
  nonce bytes 0–15, `2030-01-02T03:04:05.123Z`, and UTF-8 password `synthetic-π`:
  `Z62LgQEVFLIVUJP/Y7NH9H1eWJM=`. Tests require that digest, exact wire Created,
  nonce encoding, UTC/offset/TTL, correct SOAP attributes and credential escaping.
- Unit/runtime tests cover default isolation, new nonces, RNG failures (including
  full-read errors/non-progress), output limits, ID collisions and no response
  verification claims. Time/random seams are Go-only test inputs.
- `make interop` now builds the real custom-k6 binary before starting Apache.
  Native k6 sends Digest/Text for both SOAP versions, tests replay and wrong
  credentials, successful overrides and default restoration, and parses SOAP
  authentication faults. Standalone Timestamp succeeds at `/ts11` and `/ts12`.
- Independent fixture requests retain missing/expired Timestamp, wrong password,
  future/stale Created and nonce replay controls. New tests isolate missing and
  stale UsernameToken Created from a fresh envelope Timestamp. Apache's default
  Text validator permits absent Created; the fixture adds a presence-only
  validator wrapper requiring nonce/Created, delegating password verification,
  freshness and replay processing to WSS4J. No Go verifier substitutes for Apache.

CP-T1 passes for this selected Apache profile. JMeter capture/migration parity is
**unverified**: no sanitized JMeter capture was supplied. The vector and Apache
results do not replace that comparison or claim interoperability with every SOAP
service. See [policy definitions](security-policy.md) for capabilities that remain
unavailable and [Apache fixture](../test/interop/README.md) for pinned versions.
