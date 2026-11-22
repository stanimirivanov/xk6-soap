# Supported contracts and evidence

Native k6 tests exercise the public API from JavaScript. The Apache tests send
requests over HTTP to a separately implemented CXF/WSS4J peer. Local runtime and
Go tests cover contracts specific to the extension, such as JavaScript object
mapping, metrics and XPath, which a WS-Security peer cannot validate.

## Public client behavior

| Contract | Evidence |
| --- | --- |
| Init-only Client construction and execution-context build/parse. Strict options, stable errors and bounded text/ArrayBuffer XML. | [Plain API](plain-api.md) · [TestPlainClientBindings](../internal/adapter/client_test.go) · [TestClientOptionValidation](../internal/adapter/client_test.go) |
| SOAP 1.1/1.2 raw envelopes, action headers, HTTP status, SOAP faults, and Body-only XPath. | [TestK6SOAPFixture](../test/e2e/http_test.go) · [TestXPathIsolationAndTypes](../internal/message/response_test.go) · [TestLimits](../internal/message/message_test.go) |
| Ordered object payloads with explicit namespace, attributes, text and repeated array elements. | [Object mapping](object-payloads.md) · [TestK6ObjectPayloadEcho](../test/e2e/object_test.go) |
| Custom SOAP headers, mandatory-header validation and structured WS-Addressing 2005/08. | [Headers](headers.md) · [TestHeaderBindings](../internal/adapter/headers_test.go) · [TestMandatoryHeaderVersionMetadata](../internal/message/response_test.go) · [TestK6SignedHeaderExchanges](../test/interop/headers_test.go) |
| PEM and single-identity PKCS#12; separate signing, recipient, decryption and trust roles; bounded cache. | [Key material](keys.md) · [TestFormatsRolesAndCurves](../internal/keys/keys_test.go) · [TestPKCS12PasswordIsolation](../internal/keys/keys_test.go) · [TestCrossVUKeyCache](../internal/adapter/keys_test.go) |
| SOAP outcomes and build/parse Trends. SOAP failure includes HTTP 200 Faults. Debug logs use fixed metadata. | [Metrics](metrics.md) · [TestK6SOAPMetricSummary](../test/e2e/metrics_test.go) · [TestMetadataDiagnosticsNeverReflectInputs](../internal/adapter/security_test.go) |
| Runnable raw, object and signed examples with SOAP thresholds. | [TestDocumentedSOAPExamples](../test/e2e/examples_test.go) · [TestDocumentedSignedExample](../test/interop/examples_test.go) |
| Constructor policy, invalid combinations and bounded recovery of accepted content. | [Policy schema](security-policy.md) · [TestSecurityOptionMatrix](../internal/adapter/security_test.go) · [TestInvalidPolicyMatrix](../internal/wssec/policy_test.go) · [TestRecoveredSnapshotResourceLimits](../internal/wssec/security_fuzz_test.go) |

## Independent WS-Security profiles

Each row below has native-to-Apache evidence for SOAP 1.1 and 1.2. The
[matrix manifest](../test/interop/matrix.json) defines the actual combinations
and expected outcomes. The [fixture report](../test/interop/README.md) records
peer versions, policy, containment and the command to rerun the exchanges.

| Contract | Evidence |
| --- | --- |
| Outbound UsernameToken PasswordDigest/Text, overrides and standalone Timestamp. Apache validates credentials and has an endpoint-local nonce replay cache. | [UsernameToken and Timestamp](username-token.md) · [TestK6UsernameTokenExchanges](../test/interop/username_test.go) · [TestApacheFixture](../test/interop/fixture_test.go) |
| RSA-SHA256 with Body and Timestamp coverage, including optional signed UsernameToken. Verified replies and signed SOAP faults use an exact leaf pin, with content withheld on rejection. | [Signing](signing.md) · [Receive](receive.md) · [TestK6SignedExchanges](../test/interop/signing_test.go) · [TestK6VerifiedResponses](../test/interop/receive_test.go) |
| Signed Timestamp freshness and independent receive age/skew limits. Signed custom headers and WS-Addressing require exact coverage. | [TestK6TimestampFreshness](../test/interop/timestamp_test.go) · [TestK6SignedHeaderExchanges](../test/interop/headers_test.go) |
| RSA PKCS#1 v1.5 with SHA-256/384/512 and ECDSA P-256/384/521 with the matching SHA-2 hash. Exclusive C14N and SHA-256/384/512 reference digests. | [TestK6SignatureAlgorithms](../test/interop/algorithms_test.go) · [TestApacheSignatureGate](../test/interop/signature_test.go) |
| X.509 BST (including the `direct` alias), issuer/serial, X509v3 KeyIdentifier, SKI and ThumbprintSHA1. | [TestK6SignatureKeyIdentifiers](../test/interop/key_identifiers_test.go) |
| AES-128/256-GCM and XML Encryption 1.1 RSA-OAEP with SHA-256 and MGF1-SHA256. Both orders and all three targets are exercised in 24 core rows, including protected replies and SOAP faults. Opposite send/receive order has separate coverage. | [Request encryption](request-encryption.md) · [Encrypted receive](receive.md#encrypted-responses-and-faults) · [TestK6InteropMatrix](../test/interop/matrix_test.go) · [TestK6EncryptedResponsesAndFaults](../test/interop/response_encryption_test.go) |

Sign-then-encrypt and encrypt-then-sign require signing. `content` protects
Body children, `body` protects the operation element, and `headers` protects
selected blocks. Required Body protection and required encrypted header names
are separate receive policies. Set the receive order explicitly for decryption.
An accepted signed response may carry a SOAP Fault and therefore have
`ok:false` with a true signature flag.

## Limits and deferred features

- The [matrix](../test/interop/matrix.json) distinguishes rejected configurations
  from combinations with no independent claim, including the full product of
  algorithms, digests and key identifiers, encryption with UsernameToken or
  WS-Addressing, combined inbound Body/header protection, multiple encrypted
  headers and optional encryption variants.
- M02 legacy options are outside M01: RSA-SHA1, SHA-1 XML reference digests,
  AES-CBC, 3DES, RSA v1.5 key transport and OAEP-MGF1P. The UsernameToken
  PasswordDigest formula and ThumbprintSHA1 use SHA-1 only for their protocol roles.
  There is no algorithm fallback, unsigned encryption, multi-recipient encryption,
  combined outbound Body/header target or external cipher/reference resolution.
- SAML, WS-SecureConversation, Kerberos, MTOM, JKS, encrypted PEM,
  WSDL discovery/code generation and WS-SecurityPolicy negotiation are outside
  the implemented profile. The caller configures transport and TLS in k6.
  Empty one-way replies, intermediary role routing, automatic addressing
  correlation, receive replay detection and payload logging are outside the
  contract. Trust uses explicit leaf pins without chain, revocation or online
  certificate lookup. [Architecture](architecture.md)
- Apache fixture results cover the pinned peer. WCF, Spring-WS, Metro,
  JMeter and production-specific peer profiles require their own evidence.
  [JMeter mapping](jmeter-map.md)

## CP-P performance and release evidence

PR-14 SOAP outcome and processing metrics and PR-15 object payloads have
native k6 evidence linked above. PR-24 supplies the independent matrix.
PR-25 supplies the frozen [performance and retention report](../test/perf/README.md)
and [raw baseline](../test/perf/baseline.json). The workload measures generator
processing and retention, outside HTTP transport. All 24 baseline runs recorded
zero drops. A later shared-host comparison missed budgets, including signed
fixed-VU parse p95 at 82.7 ms against 68.4 ms in the targeted retry. Dedicated
nightly verification is pending a matching self-hosted runner and opt-in.
The [release checklist](release.md) records the compatibility matrix and
release rehearsal.
