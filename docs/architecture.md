# xk6-soap architecture

This document describes the implemented M01 architecture. [Supported contracts and evidence](contracts.md) ties behavior to tests. The [decision index](adr/README.md) records the architectural gates, and the [M01 plan](../tasks/plan.md) tracks release preparation.

## 1. Objective and scope

The extension builds and consumes SOAP messages with WS-Security. k6 owns HTTP transport, TLS configuration and native HTTP metrics. SOAP interpretation remains a separate boundary.

M01 implements SOAP 1.1/1.2, raw and object payloads, faults/XPath, UsernameToken Digest/Text, Timestamp, RSA/ECDSA SHA-2 signatures, the specified X.509 key identifiers, WS-Addressing signing, AES-GCM/RSA-OAEP, both protection orders, body/content/header targets, PEM/PKCS#12, metrics and metadata-only diagnostics. A pinned WSS4J/CXF fixture supplies independent interoperability evidence.

M02 remains a separately approved legacy profile: RSA-SHA1, SHA-1 XML reference digests, CBC/3DES, RSA v1.5 and OAEP-MGF1P. No automatic algorithm fallback. SAML, secure conversation, Kerberos, MTOM, JKS, WSDL/code generation, WS-SecurityPolicy negotiation, full PKI/revocation infrastructure and other server families are excluded. No pre-signed message cache or Go-side HTTP transport.

## 2. Evidence and dependency decisions

| Component | Current implementation | Evidence |
| --- | --- | --- |
| Module | `github.com/stanimirivanov/xk6-soap`; Apache-2.0 | [License](../LICENSE) |
| Go and k6 | Go 1.27.4, k6 v2.4.0 and the selected Sobek version | [.go-version](../.go-version) · [go.mod](../go.mod) · [Runtime ADR](adr/0001-k6-runtime-contract.md) |
| Crypto and XML | `go-xmlsec/v2` v2.0.2 and `go-xml/v2` v2.2.0 behind `internal/wssec` | [Signature gate](adr/0002-signature-kernel.md) · [Encryption gate](adr/0003-encryption-kernel.md) |
| PKCS#12 | `software.sslmate.com/src/go-pkcs12` v0.7.4 for decoding | [Key formats and validation](keys.md) |
| XPath | `xmlquery` v1.5.2 and `xpath` v1.3.9 on an accepted Body projection | [XPath boundary](plain-api.md#xpath-boundary) |
| Apache fixture | CXF 4.2.4 and aligned WSS4J 4.0.3 runtime modules | [Fixture pins and evidence](../test/interop/README.md) |

The module and build files own current pins. ADRs preserve the versions tested at
the time of each decision. The runtime contract is tested at the current pin. A
broader supported-version matrix is part of release preparation.

## 3. Capability boundaries

| Component | Owns | Depends on |
| --- | --- | --- |
| Root package | Sobek decoding, Client lifecycle, per-VU state, diagnostics and error conversion | k6 runtime, message, key and WS-Security boundaries |
| `internal/message` | SOAP structure, payloads, header selectors, operation names, faults and XPath | Bounded XML and XPath libraries |
| `internal/keys` | Decode, validate and cache immutable cryptographic material | Go crypto and PKCS#12 decoder |
| `internal/wssec` | Policy normalization, one-tree coverage, accepted security state and encryption order | Message, keys and pinned XML security provider |
| Observability | Fixed metadata, timings, result rates | VU metric APIs |

The internal provider adapter binds verified nodes and recovered regions to the content the caller will consume. It owns order-sensitive security processing and withholds plaintext on rejection. Build returns the provider's signed wire bytes. XPath evaluates the accepted Body projection after security acceptance. The adapter is internal to the module.

[HARNESS.md](../HARNESS.md) maps source files, ownership and the tested dependency rules.

## 4. Lifecycle and JavaScript contract

The module registers as `k6/x/soap` and exports the named `Client`. `NewModuleInstance(vu)` returns `modules.Instance`, without an error return. Each VU owns its JS values and message state. The RootModule owns the shared key cache and synchronized per-registry metric registration. Cached key entries are immutable.

Construct clients in init context. Validate all nested option keys/types and load/validate key material there so invalid credentials fail before measured iterations. Reject construction in execution context. `build()` and `parse()` require execution context (including setup/teardown when a k6 state exists); reject init-context calls. The runtime tests cover these context rules and registration. The extension checks cancellation between bounded processing stages; a crypto or library call can run until it returns.

The [runnable examples](../README.md#run-an-example) exercise HTTP transport and SOAP thresholds with the real custom k6 binary.

`build(operation, payload, opts)` returns `{url, body, headers, buildDuration}`; duration is milliseconds. URL is fixed at construction, absolute HTTP(S), without embedded credentials. `opts` permits only `soapAction`, `credentials`, `headers`, `addressing` as defined below. Operation is a validated NCName, also used as the object wrapper. Key roles and security policy cannot be overridden per request. Invalid local arguments, key errors, cancellation or RNG/build failures throw a sanitized error with stable `code` and `stage`.

`parse(res)` accepts a k6 response with numeric `status` and text body. Binary ArrayBuffer bodies are decoded as strict UTF-8; null/discarded bodies produce `BODY_UNAVAILABLE`. Status 0 produces `TRANSPORT_ERROR`. Invalid API argument types throw `INVALID_ARGUMENT`; remote protocol/security failures return results, never uncaught library panics. Callers retain the original response for HTTP timings and raw diagnostics.

## 5. Payload, envelopes and headers

- SOAP version defaults to `1.1`. Match Envelope/Header/Body by namespace URI and position, never prefix/local name alone. One Envelope, at most one Header preceding exactly one Body. No DTD, external entities, processing instructions or namespace-invalid input. UTF-8 only in M01.
- Raw XML is one operation element, with no XML declaration or Envelope/Body wrapper. Insert it as the Body's sole element without adding `operation`. Its local name must equal `operation`; its namespace is supplied in the raw XML. Preserve namespace context and lexical content through the security tree.
- Object payloads require a Client constructor `namespace`. Wrap in `{namespace}operation`; own enumerable string properties follow JavaScript enumeration order captured before Go map conversion. Unprefixed child elements inherit this namespace; unprefixed attributes have no namespace. Prefixes/namespace declarations in object keys are rejected; use raw XML for multi-namespace payloads.
- `@name` supplies scalar attributes; `#text` supplies text. Arrays repeat their named element in array order; empty arrays emit nothing. Strings, finite numbers and booleans map to text; empty object produces an empty element. Reject null, undefined, functions, symbols, BigInt, cycles, non-plain objects, non-finite numbers, mixed `#text` plus child elements and invalid XML names. Do not invent XSD types or reorder fields alphabetically.
- SOAP 1.1 uses `text/xml; charset=utf-8`, quoted `SOAPAction`, empty string when absent. SOAP 1.2 uses `application/soap+xml; charset=utf-8`, optional quoted action parameter, no SOAPAction. Reject action strings containing controls, CR/LF, quotes or backslashes instead of interpolating them into headers. See [SOAP 1.1 §6](https://www.w3.org/TR/2000/NOTE-SOAP-20000508/) and [SOAP 1.2 HTTP binding](https://www.w3.org/TR/soap12-part2/).
- `opts.headers` is an array of `{name, xml}`: stable unique NCName selector and one namespace-qualified SOAP header element. Reject envelope/security elements, injected IDs, and duplicate expanded names. Namespace-qualified actor/role and mustUnderstand attributes must be valid for the SOAP version. The provider assigns security IDs.
- WS-Addressing blocks use the structured `addressing` input; custom XML cannot inject that namespace or claim its four reserved selectors. This keeps URI/action/To validation on one path.
- `opts.addressing`, when supplied, has required `action`, `to`, `messageId`, `replyTo`, using WS-Addressing 2005/08. Emit Action, To, MessageID and ReplyTo headers; selectors are `wsaAction`, `wsaTo`, `wsaMessageID`, `wsaReplyTo`. Reject collisions, require `to === url`, and require `soapAction` to match `action` if both are supplied. URI values are validated; no automatic network lookup or endpoint discovery. Users supply fresh MessageIDs. M01 does not implement response correlation/replay tracking. The wire model follows [WS-Addressing 1.0 Core](https://www.w3.org/TR/ws-addr-core/); this API supports a restricted subset.
- Outbound `wsse:Security` targets the ultimate receiver only; SOAP 1.1 mustUnderstand is `1`, SOAP 1.2 is `true`. Do not promise intermediary-role routing. Reject targeted unknown mandatory response headers; recognized headers are Security and the supported WS-Addressing set. Optional unknown headers are ignored.

## 6. Security configuration

Security uses independent typed blocks. The former `security.type` shape is rejected. Absence of `security` means plain SOAP. Each present feature block is enabled; absence disables it. Unknown or unavailable options fail explicitly.

| Block | Fields and defaults |
| --- | --- |
| `security.usernameToken` | `user`, `password` required; `passwordType: 'PasswordDigest'` or `'PasswordText'` |
| `security.timestamp` | `ttlSeconds: 300`, `clockOffsetSeconds: 0`; TTL integer 1–3600, offset integer -300–300 |
| `security.sign` | `algorithm: 'rsa-sha256'`, `digest: 'sha256'`, `canonicalization: 'exclusive-c14n'`, `keyId: 'binary-security-token'`, `headers: []` of header selectors |
| `security.encrypt` | `algorithm: 'aes-256-gcm'`, `keyTransport: 'rsa-oaep-sha256'`, `target: 'content'`; target `body`, `content` or `headers`; `headers` selector list required only for header target |
| `security.order` | When both sign and encrypt are present, defaults to `sign-then-encrypt`; otherwise omission required. Alternative `encrypt-then-sign` |
| `security.verify` | `signature`, `timestamp`, `requireEncryption`, `order`, `signatureAlgorithms`, `digestAlgorithms`, `signedHeaders: []`, `encryptedHeaders: []`, `clockSkewSeconds: 60`, `maxAgeSeconds: 300` |

Signing always covers the actual SOAP Body. Signing also creates and signs a Timestamp, using the default timestamp block if omitted. A UsernameToken is signed when combined with signing. All generated WS-Addressing headers are signed; `sign.headers` adds custom header selectors. Missing/duplicate selectors fail. The unsafe `signBody: false` switch is removed.

UsernameToken alone adds a Timestamp by default. Overrides in `opts.credentials` require both user and password and never mutate defaults. Nonce is 16 CSPRNG bytes, regenerated with Created on each build. Digest is Base64(SHA-1(nonce bytes + UTF-8(serialized Created) + UTF-8(password))). PasswordText is explicit. This protocol SHA-1 use is distinct from legacy XML signature/digest algorithms. See [UsernameToken profile §3](https://docs.oasis-open.org/wss-m/wss/v1.1.1/os/wss-UsernameTokenProfile-v1.1.1-os.html). HTTPS is recommended; neither password form substitutes for transport security.

Signature algorithms: RSA PKCS#1 v1.5 SHA-256/384/512; ECDSA P-256/SHA-256, P-384/SHA-384, P-521/SHA-512 only. Reference digests SHA-256/384/512. ECDSA wire signatures use the fixed-width r||s representation defined in [XML Signature 1.1](https://www.w3.org/TR/xmldsig-core1/). RSA keys must be at least 2048 bits. Exclusive C14N without comments is the only signature transform; receive supports a validated InclusiveNamespaces prefix list exercised by the independent fixture. External references, XSLT, XPath signature transforms and algorithm fallback are rejected. Application XPath queries are unrelated.

`binary-security-token` is an embedded X509v3 BST with direct reference; `direct` is an alias normalized to it, not another wire format. Other key identifiers are issuer-serial, x509keyidentifier, ski (certificate extension required), and ThumbprintSHA1. Key identifiers locate candidates among pinned trust; they never authorize an untrusted embedded key. ThumbprintSHA1 does not enable SHA-1 signatures.

AES-128-GCM and AES-256-GCM are permitted. `rsa-oaep-sha256` means `http://www.w3.org/2009/xmlenc11#rsa-oaep`, explicit SHA-256 DigestMethod, explicit MGF1-SHA256, empty OAEP label. Generate a fresh content key for each message and fresh 96-bit IV for each encrypted part; authentication tag is 128 bits. No caller-controlled production randomness. Both sending and receiving enforce these parameters.

`content` encrypts SOAP Body children; `body` encrypts the sole operation element inside the Body. Neither replaces the SOAP Body itself. `headers` encrypts the selected complete header blocks using wsse11:EncryptedHeader; unselected Body remains visible. Copy mandatory role/mustUnderstand metadata correctly. These are deliberately limited profiles, not arbitrary encryption graphs. At most one recipient and one EncryptedKey per message; external CipherReference and nested/super encryption are rejected. Use “hybrid encryption,” not a claim of WS-SecurityPolicy symmetric binding.

## 7. Keys and cache

`keys.signing` and `keys.decryption` each accept exactly one of `{cert, key}` or `{pkcs12, password}`. `keys.recipient` accepts `{cert}`. `keys.trust` is an array of PEM certificate bytes. Inputs are ArrayBuffers from init `open(path, 'b')`, copied before caching. No filenames, arbitrary signers or network key retrieval. PEM private keys support unencrypted PKCS#8, PKCS#1 and SEC1 EC; encrypted PEM is explicitly unsupported in M01. PKCS#12 must yield exactly one private-key identity; reject ambiguity, wrong password and mismatched certificate/key.

Check key algorithm/curve/size, certificate validity at use time, and applicable KeyUsage when present: digitalSignature for signing, keyEncipherment for RSA transport. Trust is exact leaf-certificate DER pinning, not system roots or chain building; overlapping pins permit manual rotation. No AIA/OCSP/CRL fetch. Do not trust embedded certificates just because their signature mathematics works.

Cache decoded material using a per-process keyed hash of length-delimited format, bytes and decoding password; never log the key. Validate role-specific constraints even on cache hits. A wrong password must fail even after the same container was cached successfully. Bound cache to 256 entries and 32 MiB of encoded input, fail clearly on exhaustion, and scope it to the module instance/process. Concrete key objects are immutable after loading (including RSA precomputation); validate concurrent use with race tests. Do not cache per-request XML, signatures, secrets from overrides or JS objects. Go/JS cannot promise guaranteed zeroization.

## 8. Receive acceptance and results

Receive policy is independent of outbound order. When omitted, `verify.signature` defaults to whether outbound signing is enabled, `verify.timestamp` follows `verify.signature`, and `requireEncryption` defaults false. Required signature needs nonempty trust; required timestamp requires required signature. Required encryption also requires signature and a decryption key. If encryption is expected/accepted, receive order must be explicitly set; do not infer it from outbound order or trial-decrypt alternatives. Decryption keys require a receive-order policy even for optional encrypted responses.

Receive `signedHeaders` and `encryptedHeaders` are lists of `{namespace, localName}` expanded names, independent of outbound selectors. Each required name must resolve to exactly one direct header block (or its recovered original); missing/ambiguous matches fail. Nonempty encryptedHeaders requires signature verification, a decryption key and explicit receive order. Required encrypted headers must have been wholly encrypted; required signed headers must be covered by the accepted signature (their EncryptedHeader wrapper for encrypt-then-sign). All present supported WS-Addressing headers must be signed when signature verification is enabled.

Inbound signature/digest allow-lists default to RSA-SHA256 and SHA-256, independent of outbound selections; expand explicitly for ECDSA/breadth fixtures. Disabled signature verification yields `sigVerified: null`, even if an unverified signature is present. An explicitly unsigned policy does not confer authenticity. Out-of-profile algorithms and unsupported security structures are still rejected rather than executed.

1. Validate status/body availability and bounded XML syntax/structure; require the configured SOAP version and unique IDs across recognized ID forms. Secured profiles permit one targeted Security header with at most one signature, Timestamp and EncryptedKey. No external URI resolution.
2. Enforce required security presence, algorithms, key selection and encryption targets before expensive work. `requireEncryption` means all SOAP Body application content was encrypted; a header-only encrypted message does not satisfy it.
3. For encrypt-then-sign, verify the untouched ciphertext tree and coverage of the Body, required Timestamp, all selected encrypted header wrappers and EncryptedKey before decryption. Then decrypt accepted regions in private state and retain provenance. For sign-then-encrypt, decrypt authenticated GCM regions in private state, then verify recovered Body/Timestamp/selected headers. Never expose partial plaintext on failure. GCM authentication does not establish a trusted sender.
4. After each decryption, reapply byte/structure/ID limits. Enforce coverage by exact node identity and location, not a matching name or ID string. Faults and XPath consume only the accepted Body. If signature verification is enabled, an encrypted response requires a valid signature even when encryption itself was optional. A parse/projection disagreement fails closed.
5. Validate required signed Timestamp: Created and Expires present, Expires > Created, lifetime at most the configured maxAge (default 300 seconds), Created <= now + skew, now < Expires + skew, and age <= maxAge + skew. Defaults: skew 60 seconds, maxAge 300 seconds; configurable integers 0–300 and 1–3600 respectively. Test equality boundaries. Outbound clock offset does not silently change receive tolerance. Freshness alone is not replay detection.
6. Extract Fault only now. SOAP 1.1: code/reason/actor/detail. SOAP 1.2: expanded code/subcode chain, all localized Reasons, Node/Role and detail. Restrict Fault detection to the direct Body child.

Result shape: `{ok, status, body, fault, error, sigVerified, timestampValid, xpath}`. `body` is the accepted SOAP Body inner XML string, or null when acceptance failed. `fault` is null or `{code, subcodes, reason, reasons, role, node, detail}` with absent fields null/empty. Code is `{namespace, localName}`; reasons is `[{lang, text}]`, reason prefers English then first; detail is inner XML. `error` is null or `{code, stage, message}` with sanitized stable fields. Verification booleans are true/false when attempted or required-but-missing, null when skipped/not reached. `ok` requires HTTP 2xx, accepted XML/security and no Fault. Empty 202/204 is `BODY_UNAVAILABLE` in M01, not supported one-way SOAP.

Error precedence: transport/body availability, XML/limits, security policy/crypto/timestamp, SOAP fault, HTTP status. HTTP 4xx/5xx with an accepted Fault retains that Fault and uses `SOAP_FAULT`; non-2xx without Fault uses `HTTP_STATUS`. Security failures expose no body/fault. Required-but-missing checks fail; they never become a successful “skipped.” Stable error codes include `XML_INVALID`, `LIMIT_EXCEEDED`, `POLICY_VIOLATION`, `SIGNATURE_INVALID`, `TIMESTAMP_INVALID`, `DECRYPTION_FAILED`, `SOAP_FAULT`, and `HTTP_STATUS` in addition to §4 codes.

`xpath(expr, nsMap)` evaluates relative to a read-only accepted Body subtree, never the entire untrusted envelope. Returns `{value, error}`: scalar XPath results retain string/number/boolean type; node-set results are arrays of string-values in document order (no Go nodes). Invalid expressions/prefixes yield `XPATH_INVALID`; unavailable accepted content yields `CONTENT_UNAVAILABLE`. These calls do not emit another parse metric or mutate `ok`. Default XML namespaces require explicit query prefixes.

## 9. Limits, diagnostics and metrics

Default limits: 4 MiB input/output envelope, 4 MiB total recovered plaintext, XML depth 64, 50,000 nodes, 64 attributes per element, 16 signature references/encrypted parts, 16 custom headers, 8 trust pins, 1 MiB per key input, XPath expression 4096 bytes and 1000 result items. Positive client XML limits can only reduce defaults. Output generation and recovered plaintext have separate bounds. XPath has no global compilation cache. Structural checks bound decoded and recovered data before projection.

`debug: true` emits stage, duration, selected algorithm and stable failure code only through the VU logger. Never emit payloads, canonical octets, credentials, UsernameToken digests, keys, certificates, URIs from hostile input or fault details. Canonical-octet artifacts are test-only synthetic data. Native `--http-debug` is outside extension redaction and may disclose wire contents.

| Metric | Semantics |
| --- | --- |
| `soap_build_duration` Trend, ms | One sample per valid execution-context build attempt, including failed builds |
| `soap_parse_duration` Trend, ms | One sample per execution-context parse invocation, including API/remote failures; covers receive crypto |
| `soap_reqs` Counter | One per parse invocation, including repeated parsing of the same response |
| `soap_req_failed` Rate | One per parse invocation; sample is `!ok` |

Register once in init through the pinned k6 registry; no collision-based redefinition. Preserve normal VU tags, with extension-owned values restricted to fixed `soap_version` and `security_mode` enums. Never add operation/user/URL/body/error text as automatic tags. User tags and their cardinality remain user-controlled. Build-only work cannot measure remote success; no cross-call request state or hidden deduplication. HTTP metrics keep k6 semantics even when SOAP fails on HTTP 200. Tests must set a SOAP failure threshold explicitly.

## 10. Verification, performance and delivery

The [contract report](contracts.md) links unit, runtime, E2E and independent
Apache tests. The [matrix manifest](../test/interop/matrix.json) records actual
cross-peer combinations. Core kernel evidence covers both protection orders;
separate native exchanges exercise the signature algorithms, key identifiers,
header coverage, encrypted faults and rejected messages. Golden bytes cover
deterministic wire and C14N artifacts. Randomized crypto uses semantic and
independent verification. Bounded fuzz targets exercise SOAP, complete receive
processing and the JavaScript argument boundary.

The [performance and retention report](../test/perf/README.md) records the pinned
runner and fixtures, cold key init, warmed build/parse timings and allocations,
native k6 throughput and CPU, and post-GC retention. `make bench` compares
against frozen regression limits. The nightly workflow requires the dedicated
runner. The baseline makes no absolute latency claim.

`make verify` runs lint, architecture and documentation reference checks, race
tests, build and dependency verification. `make e2e` and `make interop` run the
public examples with real k6. The other gates include `make smoke`,
`make fuzz-smoke` and `make vuln`.

## 11. Remaining evidence

- [JMeter migration](jmeter-map.md) remains unverified until the plugin and
  reference captures are identified.
- A dedicated nightly benchmark comparison remains outstanding. The frozen
  baseline and shared-host replay outcome are documented separately.
- Target services need their own peer policy and compatibility checks.
  [Scope and limitations](contracts.md#limits-and-deferred-features)
- PR-27 tracks the supported-version matrix, reproducible build instructions and
  release dry-run. [M01 plan](../tasks/plan.md)
