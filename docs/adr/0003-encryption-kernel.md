# ADR-0003: Both protection orders pass the core kernel gate

Date: 19 November 2026. Status: accepted, **CP-K passed for the bounded core
profile below**. Task: [issue #23](https://github.com/stanimirivanov/xk6-soap/issues/23).
This completes the pending kernel decision in [ADR-0002](0002-signature-kernel.md).
Candidate/module/runtime and independent Apache pins remain unchanged. No public
JavaScript crypto configuration is enabled.

## Decision and wire profile

Retain `github.com/knroy/go-xmlsec/v2 v2.0.2` and its pinned XML dependency behind
`internal/wssec`. `Protect` and `Open` are internal kernel probes using standard
Go certificates/RSA keys, bytes, time and an explicit protection order/AES size.
There is no provider replacement or order/algorithm fallback.

The independent matrix passes SOAP 1.1 and 1.2, AES-128 and AES-256-GCM, both
sign-then-encrypt and encrypt-then-sign, in both Go-to-Apache and Apache-to-Go
directions. Exact XML algorithm URIs are:

| Purpose | Required URI |
| --- | --- |
| AES-128-GCM | `http://www.w3.org/2009/xmlenc11#aes128-gcm` |
| AES-256-GCM | `http://www.w3.org/2009/xmlenc11#aes256-gcm` |
| RSA-OAEP | `http://www.w3.org/2009/xmlenc11#rsa-oaep` |
| Explicit OAEP digest | `http://www.w3.org/2001/04/xmlenc#sha256` |
| Explicit MGF | `http://www.w3.org/2009/xmlenc11#mgf1sha256` |

The signature profile remains RSA-SHA256/SHA256/Exclusive C14N and BST direct
reference. Encryption uses one RSA recipient, an issuer/serial key identifier,
one EncryptedKey with one local DataReference and one direct Body-content
EncryptedData. The data key reference must resolve to that exact key node.
The caller explicitly selects the recipient certificate/private key; embedded
key information grants no trust. RSA certificates require >=2048 bits, validity
at the supplied clock and applicable digitalSignature/keyEncipherment usage.

## Order, coverage and provenance

- **Encrypt-then-sign:** verify the untouched ciphertext snapshot first, with
  exactly three local references and exact node-identity coverage of the direct
  Body, targeted Timestamp and EncryptedKey. Only then unwrap/decrypt. Signature
  placement precedes EncryptedKey processing, with the signer BST ahead of the
  signature. The candidate appends signatures; a small provider-XDM tree rebuild
  supplies that sibling layout without changing ancestor namespaces. Outbound
  probe references use Exclusive C14N without InclusiveNamespaces.
- **Sign-then-encrypt:** decrypt GCM privately, then verify exactly two references
  covering the actual recovered Body and Timestamp in that recovered snapshot.
  The clear EncryptedKey is not claimed as signed in this order. GCM validity
  alone does not authenticate the sender.
- Provenance is a deliberately constrained operation: exactly one Type=Content
  replacement in the direct Body, performed by `xenc.DecryptAndReplace` on the
  exact previously selected ciphertext node. Its parser restores namespace
  context; the adapter validates the complete recovered SOAP document again
  before consumption. It does **not** copy a signature-coverage flag to an ID
  selected in a different tree. For encrypt-then-sign, authorization comes from
  the verified ciphertext region/key and the authenticated replacement itself;
  for sign-then-encrypt, coverage is freshly proved on recovered nodes.
- Pre/post parse limits are 4 MiB, depth 64 and 50,000 nodes. Session keys and the
  intermediate plaintext byte buffer are cleared after use. This is best-effort
  memory hygiene, not a promise to erase every immutable-tree/string copy.
- Partial Body encryption, extra encrypted regions/keys, recovered signatures or
  encryption graphs, key-reference chaining, wrong Type, external references,
  OAEP labels and unsupported parameters are refused. No partial result is
  returned on failure. The standalone signature-only `Verify` still refuses
  encryption. No external resolver is installed.

The provider returns serialized replacements rather than a general cross-tree
provenance map. This is sufficient for this single-region gate, not a general
mapping for encrypted headers, attachments or nested operations. Later target
selection work must extend the graph/provenance policy with independent tests;
this ADR does not pre-approve those paths. The probe does not establish arbitrary
QName-valued payload semantics, key loading/caching, PKI/revocation, replay caches,
legacy algorithms, RNG fault injection or JavaScript orchestration.

## Independent fixture serialization correction

Apache WSS4J 4.0.2 `WSSecEncryptedKey.createEncryptedKey` creates the OAEP
`ds:DigestMethod` and `xenc11:MGF` with namespace-aware names but no explicit
namespace declarations. When that EncryptedKey is itself signed, SOAP wire
serialization adds declarations after digest computation. Initially all four
Apache encrypt-then-sign responses failed their EncryptedKey digest.

The candidate, host JDK canonicalizer and the fixture's pinned Apache Santuario
canonicalizer produced byte-identical canonical EncryptedKey output from the
received wire. Removing exactly the two serializer-added declarations reproduced
Apache's recorded DigestValue. This isolated the failure to namespace-incomplete
outbound DOM construction, not to the candidate verifier.

`NamespaceStableSignature` declares these two namespaces before delegating to
Apache's normal SignatureAction. It changes no cryptographic implementation,
algorithm, signature target or receive check. The independent wire test fails
without this correction and passes with it. Keep the correction scoped to the
fixture/pinned version and reassess it when upgrading Apache.

## Verification evidence

- TDD RED: absent probe APIs, absent Apache encryption endpoints, incorrect
  signature/key wire order, signing-only recipient acceptance, recovered extra
  signature acceptance and unsupported KeyReference acceptance. Each became
  GREEN through the corresponding implementation change.
- All eight version/order/AES combinations round-trip against Apache, where
  Apache independently decrypts Go requests and signs/encrypts responses to the
  client's public certificate. No server private key is exported to Go.
- Altered request tags cause Apache SOAP faults. Altered response tags/MGF,
  partial Body and opposite receive order return no Go plaintext.
- Local tests additionally reject wrong private keys/AES size, OAEP digest,
  external key/data references, wrong Type and unsupported graphs.
- A valid trusted signature over Body/Timestamp/EncryptedData but not the exact
  EncryptedKey is rejected. A temporary mutation removing only the key-coverage
  assertion made that regression fail; the exact source was restored.
- Existing signature/golden tests, `make verify`, `make interop` (race-enabled),
  and `make vuln` (source and custom-k6 binary) pass.

Sources: [XML Encryption 1.1](https://www.w3.org/TR/xmlenc-core1/),
[WSS4J configuration](https://ws.apache.org/wss4j/config.html),
[pinned WSS4J source](https://repo.maven.apache.org/maven2/org/apache/wss4j/wss4j-ws-security-dom/4.0.2/wss4j-ws-security-dom-4.0.2-sources.jar),
[candidate encryption source](https://github.com/knroy/go-xmlsec/tree/v2.0.2/xenc).
