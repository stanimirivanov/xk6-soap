# Key material and cache

PR-8 adds init-constructor key loading. Security policy and public message crypto
remain separate tasks: supplying keys alone does not sign/encrypt a request or
verify/decrypt a response. Plain results retain null verification flags.

```js
const client = new Client({url:'https://example.test/service', keys:{
  signing:{cert:open('./signer.pem','b'), key:open('./signer-key.pem','b')},
  recipient:{cert:open('./recipient.pem','b')},
  trust:[open('./peer-leaf.pem','b')],
}});
```

Every certificate/key/container input must be an attached, nonempty ArrayBuffer;
filenames, strings and typed-array views are rejected. Signing/decryption require
exactly `{cert,key}` or `{pkcs12,password}` (password must be an explicit string,
including for an empty password). Recipient accepts only `{cert}`. Trust is an
array of at most eight certificate ArrayBuffers. Missing key roles are permitted;
[Executable policy](security-policy.md) now enforces role requirements. A public
decryption key requires explicit receive order, and the requested decryption path
remains unavailable until its feature task. Supplying a signing/recipient/trust
key alone still enables no message protection. For PKCS#12 signing input, replace
`signing` above with `{pkcs12:open('./signer.p12','b'), password:__ENV.P12_PASSWORD}`.

PEM accepts exactly one CERTIFICATE and one unencrypted PKCS#8 PRIVATE KEY,
PKCS#1 RSA PRIVATE KEY or SEC1 EC PRIVATE KEY. Encrypted PEM, PEM headers,
malformed preambles, extra blocks and trailing non-whitespace fail closed.
DER-encoded PKCS#12 must contain exactly one private key matched to its identity certificate.
Extra certificate bags must be distinct CA chain material, not alternative leaf
identities; chain certificates grant no trust. Ambiguous private-key containers,
wrong passwords and mismatched key/certificate pairs fail.

RSA requires at least 2048 bits. Signing/trust support RSA and ECDSA on P-256,
P-384 and P-521; RSA transport roles reject EC. Certificate validity is checked
at construction, on cache hits, and before build/parse and concrete key use.
Signing/trust require digitalSignature when KeyUsage is present; recipient and
decryption require keyEncipherment. An absent KeyUsage imposes no usage
restriction; an explicitly empty extension permits no role. No system roots,
chain-building, AIA/OCSP/CRL retrieval or trust in embedded certificates is added.
Trust inputs are exact certificate DER pins for future policy consumers.

Failures expose only stable `SOAP_KEY_INVALID`, `SOAP_KEY_ROLE`,
`SOAP_KEY_VALIDITY`, `SOAP_KEY_LIMIT` codes and stage `keys`. Structural/type
errors may use the existing INVALID_ARGUMENT code. Diagnostics never include
key bytes, certificates, passwords or library decoder details.

## Ownership and limits

The RootModule owns a cache shared by its VUs. Each client retains only material
handles and its own trust slice. ArrayBuffers are copied before decoding. The
cache indexes length-delimited format/certificate/key/container/password fields
using HMAC-SHA256 under a fresh private per-cache CSPRNG key. Passwords and role
are deliberately different concerns: password participates in identity; role
and time are validated again on every hit. Wrong passwords cannot reuse entries.

Limits are fixed: 1 MiB per input or password, 256 successful entries and 32 MiB
aggregate encoded input/password accounting. Capacity is conservative even
though original encoded inputs/passwords are not retained. Exhaustion fails;
entries are not silently evicted. Invalid loads consume no entries. Existing
hits remain usable at capacity. A mutex serializes construction-time decoding,
deduplicating concurrent loads without an unbounded pending-operation map.
This favors bounded init-time work over parallel password KDF throughput.

Concrete RSA/EC keys and certificates remain private. RSA validation and
precomputation complete before publication. Certificate/public-key accessors
return independent copies; Sign/Decrypt methods use the owned concrete keys.
Race tests cover RSA signing/OAEP decryption and all three EC signing curves,
not arbitrary crypto.Signer implementations. These internal methods do not
replace the upcoming provider's algorithm/order/coverage allow-lists.

Transient key/container byte copies are cleared where owned. Go/JS immutable
strings, parser allocations and garbage collection prevent guaranteed zeroization.
The encoded-input cache bound is not a measurement of exact retained heap, and
container decoding has no hard wall-clock/KDF interruption guarantee. Inputs are
local init credentials, not a remotely exposed key-upload API.

## Dependency and verification

Decoder: `software.sslmate.com/src/go-pkcs12 v0.7.4`, BSD-3-Clause; checksum
`h1:OvJ7g/OB9RuVAOzahlFLns6HeIcP+SJotsDqmLfhd8w=`; upstream commit
`0bb5b30d698b67e51be1462870f57f3e0bfc7067`. Only DecodeChain is used.
Its multiple-key rejection is supplemented with explicit identity matching,
extra-certificate ambiguity checks and role/algorithm validation.
[API/source](https://pkg.go.dev/software.sslmate.com/src/go-pkcs12@v0.7.4#DecodeChain).

`internal/keys/testdata/openssl3.p12` was generated with OpenSSL 3.5.5 using its
modern defaults and the deliberately public wssec synthetic identity. The
password is `synthetic-only`, never a deployment secret. `ambiguous.p12` imports
that identity twice using keytool (OpenJDK 25.0.5), producing two private-key bags.
Regenerate explicitly with `sh scripts/generate-key-fixtures.sh` from the root;
review the randomized fixture changes. Normal tests need neither OpenSSL nor Java.
Renew the underlying synthetic certificate before its 2036 expiry.

Focused command: `go test -race ./internal/keys . -count=1`. `make verify` runs
these and all repository quality gates; `make smoke` also exercises real k6
`open(...,'b')` inputs across VUs and retains its exit-99 negative control.
`make vuln` audits both source and the custom k6 binary. A temporary mutation
omitting the password from cache identity made the password-isolation regression
fail; the exact source was restored. The key layer has no
filesystem, network, k6/Sobek or XML-security-provider imports; the existing
architecture sensor already permits only the declared keys dependency edges.
