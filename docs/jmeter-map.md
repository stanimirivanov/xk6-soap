# JMeter migration mapping

**JMeter parity is unverified.** The source plugin name, artifact/version and
sanitized wire capture are all unavailable. The labels below describe
WSS4J-style concepts from the research plan. Match them to the installed
plugin's settings before translating a test plan.

| Source concept | xk6-soap mapping | Protocol evidence |
| --- | --- | --- |
| SOAP sampler URL, version and action | `Client({url, soapVersion})`, `build(..., {soapAction})`, then `k6/http.post` with generated headers/body | [TestK6SOAPFixture](../test/e2e/http_test.go) |
| UsernameToken identity and `passwordType` | `security.usernameToken.{user,password,passwordType}`. Use `opts.credentials` for a per-build user/password pair. Digest is the default and Text is explicit. | [TestK6UsernameTokenExchanges](../test/interop/username_test.go) |
| Timestamp lifetime and clock adjustment | `security.timestamp.{ttlSeconds,clockOffsetSeconds}`; receive freshness uses `security.verify.{clockSkewSeconds,maxAgeSeconds}`. | [TestK6TimestampFreshness](../test/interop/timestamp_test.go) |
| `signatureParts` | Body and Timestamp are always signed. A configured UsernameToken and structured WS-Addressing are also signed. Custom blocks use `opts.headers` and selectors in `security.sign.headers`. | [TestK6SignedExchanges](../test/interop/signing_test.go) · [TestK6SignedHeaderExchanges](../test/interop/headers_test.go) |
| Signature method, reference digest and `signatureKeyIdentifier` | `security.sign.{algorithm,digest,keyId}`; set receive signature and digest allow-lists independently. Select BST, issuer/serial, X509v3, SKI or thumbprint. | [TestK6SignatureAlgorithms](../test/interop/algorithms_test.go) · [TestK6SignatureKeyIdentifiers](../test/interop/key_identifiers_test.go) |
| `encryptBeforeSign` or `signBeforeEncrypt`, encryption parts and symmetric algorithm | `security.order` and independent `security.verify.order`; `security.encrypt.{algorithm,target,headers}` for AES-GCM content, operation or selected headers. | [TestK6InteropMatrix](../test/interop/matrix_test.go) · [TestK6EncryptedResponsesAndFaults](../test/interop/response_encryption_test.go) |
| Key transport, recipient, signer, decryption and trusted peer | `security.encrypt.keyTransport:'rsa-oaep-sha256'`; `keys.{recipient,signing,decryption,trust}` take bytes from init `open(path, 'b')`. Supply a PEM pair or PKCS#12 identity as documented. | [Key material](keys.md) · [TestK6InteropMatrix](../test/interop/matrix_test.go) · [TestKeyConstruction](../keys_test.go) |
| Password callbacks or keystore aliases | Supply credentials in script inputs and choose the identity before Client construction. The API has no callback or JKS loader. | [Security policy](security-policy.md) · [Key material](keys.md) |
| RSA-SHA1, SHA-1 XML digest, CBC/3DES, RSA v1.5 and OAEP-MGF1P | Deferred legacy profile. | [Unsupported profiles](contracts.md#limits-and-deferred-features) |

The [UsernameToken fixed vector](username-token.md) verifies the protocol digest.
The [Apache fixture](../test/interop/README.md) verifies both SOAP versions for
its selected policies. These are separate from comparing JMeter wire output.

To establish migration evidence, first record the plugin name and artifact
version, JMeter version, relevant sampler and security options, peer policy, and
a reproducible capture identifier using synthetic credentials and keys. Compare
the SOAP namespace, action, security-header order, algorithms and protected parts
for the same operation. Account for regenerated nonce, timestamps, IDs and
ciphertext when comparing structure. Verify signatures and decrypt protected
parts with the selected peer. Any sanitized artifact that edits signed bytes
can serve as structural evidence only. Keep a checked-in summary distinguishing
the tested request/response cases from unresolved differences.
