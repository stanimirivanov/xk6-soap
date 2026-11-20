# Executable security policy

PR-9 implements typed policy normalization and constructor validation.
[PR-10](username-token.md) activates outbound UsernameToken and Timestamp.
[PR-11](signing.md) activates RSA-SHA256/SHA256/exclusive-C14N/BST signing.
Encryption, additional signing profiles, signature verification and decryption
remain unavailable in the public Client. The internal kernel probes remain
independent gate evidence. Valid requests for unavailable features
throw `SOAP_FEATURE_UNAVAILABLE` at construction, before measured iterations.

Omitting `security`, supplying `{}`, or an explicitly unsigned receive policy
keeps plain SOAP behavior. Both verification result flags remain null. For example:

```js
const client = new Client({url:'https://example.test/service', security:{
  verify:{signature:false, timestamp:false, requireEncryption:false},
}});
```

Policy definitions intentionally precede their implementations. A configuration
can be structurally valid and still unavailable. Future feature tasks must
activate their implemented paths deliberately and preserve rejection tests for
all remaining capabilities. No JavaScript capability override exists.

## Schema and defaults

Records use own named fields; custom prototypes, unknown nested string fields,
enumerable symbol fields, wrong types, null/undefined blocks and explicitly
undefined fields are rejected. No string/number/boolean coercion occurs. Optional
fields obtain defaults only when omitted. Arrays are bounded, reject holes,
extra named properties and duplicate entries. Per-request options cannot change
constructor security policy or key roles.

| Block | Fields and normalized defaults |
| --- | --- |
| usernameToken | Required nonempty `user` and explicit string `password`; `passwordType` defaults to `PasswordDigest`, alternative `PasswordText` |
| timestamp | `ttlSeconds:300` (integer 1–3600), `clockOffsetSeconds:0` (integer -300–300) |
| sign | `algorithm:'rsa-sha256'`, `digest:'sha256'`, `canonicalization:'exclusive-c14n'`, `keyId:'binary-security-token'`, `headers:[]` |
| encrypt | `algorithm:'aes-256-gcm'`, `keyTransport:'rsa-oaep-sha256'`, `target:'content'`; `headers` is required and nonempty only for target `headers` |
| order | Defaults to `sign-then-encrypt` only when sign and encrypt are both present; otherwise must be omitted |
| verify | `signature` defaults to outbound signing presence; `timestamp` follows receive signature; `requireEncryption:false`; `clockSkewSeconds:60` (0–300), `maxAgeSeconds:300` (1–3600) |

Signing or UsernameToken also supplies the default outbound Timestamp when its
block is omitted. It does not enable receive Timestamp verification. Receive
signature/digest allow-lists always default to `['rsa-sha256']` and `['sha256']`,
independent of outbound choices. Explicit allow-lists must be nonempty and unique.

Signature definitions allow `rsa-sha256/384/512` and `ecdsa-sha256/384/512`.
ECDSA requires the corresponding P-256/P-384/P-521 signing key. Reference digest
choices are independently `sha256/384/512`. Key IDs are `binary-security-token`,
`issuer-serial`, `x509keyidentifier`, `ski`, and `ThumbprintSHA1`; `direct` normalizes
to `binary-security-token`. SKI requires the certificate extension. ThumbprintSHA1
is a key identifier, not permission for SHA-1 signature/digest algorithms.

Encryption definitions allow AES-128/256-GCM, RSA-OAEP-SHA256, and targets `body`,
`content`, `headers`. Both orders are defined. Legacy algorithms, old `security.type`
and unsafe `signBody:false` are rejected. Defining an algorithm here does not
claim independent interop coverage beyond the existing kernel ADRs.

Outbound header selectors are unique NCNames, at most 16 entries and 4096 UTF-8
bytes each. Receive `signedHeaders` and `encryptedHeaders` are unique expanded
names `{namespace,localName}` with nonempty XML-safe namespace, NCName local name,
the same entry bound and 4096-byte field bounds. Signing and encrypting the same
header is permitted. Presence/uniqueness of actual header blocks is checked by
the later header-building/receive tasks; currently enabled header-signing/encryption paths are rejected
before build. Credentials are bounded by the 4 MiB message input ceiling; username
and PasswordText must be XML-safe, and all strings must be valid UTF-8. An explicit
empty password is permitted; omission is not.

## Key requirements and receive independence

Outbound signing needs a compatible validated signing identity; encryption needs
an RSA recipient. Required signature verification needs 1–8 valid trust pins and
at least one compatible pin/allowed signature algorithm. Required Timestamp or
required signed/encrypted headers needs signature verification. Required Body
or header encryption additionally needs a decryption identity.

Every decryption key, including one for optional encrypted responses, requires
an explicit `verify.order`. It is never inferred from outbound order or trial
cryptography. Receive order without a decryption key is invalid. In this PR,
requests to use that decryption path remain unavailable. Thus PR-8's permissive
key-only decryption constructor example is intentionally tightened: supported
plain key-loading examples now use signing/recipient/trust material, and private
loader tests continue exercising decryption keys.

## Errors and diagnostics

- `SOAP_POLICY_INVALID`: malformed, conflicting or unsupported policy values.
- `SOAP_POLICY_KEY`: missing, incompatible or invalid required key roles/pins.
- `SOAP_FEATURE_UNAVAILABLE`: valid policy requests an unimplemented operation.

These TypeErrors have stage `security`, fixed code/message and no reflected
inputs. Existing key-container errors retain stage `keys`. Schema decoding also
sanitizes exceptions thrown by security option accessors. Successful compilation
copies all blocks/lists, so later caller mutation cannot change the policy.

`debug:true` enables metadata through the VU/init logger. Events contain only fixed
stage, duration in milliseconds, an allow-listed requested algorithm label and a
stable result code. Constructor compilation/availability and completed build/parse
stages emit events; not every local argument failure emits one. The logger never
receives the policy/options struct, credentials, key/certificate bytes, selectors,
URLs, XML, canonical octets or fault details. Debug defaults false and is per-client.
It is not evidence of successful security processing. Native k6 HTTP debug output
is outside this redaction boundary.

Verification uses typed-policy enum/key/range/copy tables and strict runtime
matrices, including undefined-field downgrade and secret-accessor regressions.
A temporary mutation bypassing constructor availability made the silent-no-op
regression fail; exact source restored. `make smoke` exercises actual k6 option
handling and rejects the synthetic private sentinel if it appears in its policy
probe output. Unit tests independently capture VU logger output. PR-11 activation retains these rejection controls for the remaining unavailable
capabilities.
