# ADR-0002: Candidate signature coverage and serialization gate

Date: 19 November 2026. Status: signature gate passed; full kernel decision remains
pending PR-7 encryption/order tests. Task: [issue #21](https://github.com/stanimirivanov/xk6-soap/issues/21).
No public JavaScript signing capability is enabled by this decision.

## Pinned candidate and boundary

- `github.com/knroy/go-xmlsec/v2 v2.0.2`, commit
  `d405efa3335894a5df21471997f68a6f62d94a08`, MIT.
  Module checksum: `h1:eJ7sja4Nn1rBYW3Bd9OwB7Y9pCsCVpp1pGzAI8hYtPw=`.
- Its XML/C14N dependency is `github.com/knroy/go-xml/v2 v2.2.0`, MIT.
- Go/k6 remain the repository pins. Apache remains CXF 4.2.4 / WSS4J 4.0.2
  inside the immutable JDK/Maven image recorded in the fixture documentation.

`internal/wssec` is the only production package importing candidate types. Its
boundary uses Go standard RSA/X.509 identities, bytes and time, and returns no
provider nodes. This is a narrow adapter for a single candidate, not a generic
provider/plugin framework. Key loading/caching and JS integration remain separate tasks.

## Proven profile

RSA PKCS#1 v1.5 SHA-256; SHA-256 reference digests; Exclusive C14N without comments;
BST X509v3 direct reference; exactly two local NCName fragment references covering
the actual direct SOAP Body and the targeted Security header's Timestamp. References
have exactly one Exclusive C14N transform. Other reference forms/transforms,
multiple signatures, encryption and missing required coverage fail closed.

Certificates are explicitly supplied/pinned, checked for RSA >=2048, validity and
applicable digitalSignature KeyUsage. Strict BSP/STR verification is enabled and
the referenced BST must match the supplied certificate DER. No trust is granted
to an embedded certificate and no URI resolver, system-root or online PKI fetch
is supplied. Freshness uses the caller's time, a maximum five-minute timestamp
lifetime/age and one-minute skew. Outbound IDs are fixed within each independently
created message; timestamps and signatures are freshly built per call.

## Source/API decisions

1. `xmlsec.ParseWithLimits` creates the only cryptographic tree, capped at 4 MiB,
   depth 64 and 50,000 nodes. PR-3's bounded SOAP validator supplies an additional
   syntax/namespace/attribute/shape guard; its parser is never used for digesting,
   selecting verified content or serializing signatures.
2. `xmlsec.NewDocument` owns immutable rebuilds. `wss.AssignIDWith`,
   `AddTimestampWithID` and `AddBinarySecurityTokenWithID` supply deterministic IDs.
   Header/body lookups after edits use the latest tree; stale node pointers are
   not passed between different snapshots.
3. `dsig.Sign` receives the actual Security node as Parent, so SignedInfo and
   references are calculated at their final location. The whole document is
   serialized once through the candidate C14N serializer (Inclusive10WithComments),
   following its documented wire-output pattern. Those wire bytes are sent unchanged.
4. `dsig.Verify` receives explicit signature/digest/C14N allow-lists, a pinned
   certificate, StrictBSP, explicit canonicalization and a two-reference limit.
   The adapter checks `coverage.CoversNodes(body,timestamp)` using nodes from that
   same verified document. It consumes only the canonical reference octets of that exact Body (retaining
   the verified reference's InclusiveNamespaces parameters),
   and timestamp values parsed from that exact covered Timestamp.
5. All candidate errors/panics at this boundary become fixed error sentinels,
   without reflecting hostile XML/certificates. Parsing and output are bounded;
   this does not promise hard interruption of arbitrary synchronous crypto calls.

## Namespace and byte evidence

The internal Sign probe optionally accepts at most 16 explicit globally declared
InclusiveNamespace prefixes. It uses those lists for both SignedInfo and reference
C14N; the receive policy bounds and validates PrefixLists. Default Exclusive C14N
covers visibly used namespace bindings only. QName-valued text/attributes require
explicit inclusive prefixes: the adapter cannot infer XSD semantics. Downstream
configuration work must preserve this distinction rather than promise arbitrary
QName semantics without a profile. There is no public configuration change here.

The synthetic RSA key/certificate under `internal/wssec/testdata` are deliberately
public test material, not deployment secrets. Fixed time 2030-01-02T03:04:05Z and
IDs produce checked-in artifacts:

- `request.original.xml`: original SOAP input with an inherited QName-value prefix.
- `request.signed.xml`: exact deterministic wire output, including certificate.
- `body.c14n`, `timestamp.c14n`: actual Exclusive C14N reference octets with the
  explicit `q` prefix rendered. Their stdlib SHA-256 hashes equal DigestValue.

Golden refresh is explicit via `SOAP_UPDATE_GOLDEN=1 go test ./internal/wssec -run
TestGoldenSerialization -count=1` under the pinned toolchain. Review every byte
diff; never regenerate merely to silence a failing test. LF is pinned in Git.
Repeated signing with fixed inputs is byte-identical and verifies after serialization.

## Independent and adversarial verification

`make interop` imports only the fixed client's public certificate into Apache's
fixture keystore. The client private key remains in Go testdata, outside the image.
The runner retrieves the independently generated server certificate as an explicit
Go trust input. `/sig11` and `/sig12` require Timestamp+Signature with CXF's
DefaultCryptoCoverageChecker, and sign Body+Timestamp on the response using
WSS4J DirectReference, RSA-SHA256/SHA256 and InclusiveNamespaces generation.

Observed results:

- Go signatures (including explicit InclusiveNamespaces lists) accepted by Apache
  for SOAP 1.1 and 1.2; tampered requests rejected with SOAP faults.
- WSS4J-signed responses verified and the exact covered Body consumed by Go;
  independent InclusiveNamespaces output was present. Wrong trust and tampered
  responses rejected.
- Valid trusted signatures over a decoy element instead of the consumed Body
  rejected specifically by the node-identity coverage gate. Bypassing that gate
  in a temporary mutation made the regression fail; source restored afterward.
- A covered SOAP Body relocated into the Header retains valid signature math,
  but the adapter rejects the fresh unsigned direct Body/invalid SOAP structure.
- Duplicate IDs, nil/untrusted identities, malformed/oversized XML, external
  reference URIs, missing Body/Timestamp references and QName prefix rebinding fail.
- Unit/golden tests, independent Docker tests and source/binary vulnerability
  checks are required evidence, not upstream README audit/coverage claims.

The candidate passes this signature-only gate. Do not mark CP-K or claim complete
modern WS-Security compatibility until PR-7 independently proves encryption,
parameter choices and both protection orders. This is not a PKI/revocation design,
legacy algorithm implementation or an endorsement of unrelated candidate features.

Sources: [candidate v2.0.2](https://github.com/knroy/go-xmlsec/tree/v2.0.2),
[signature verification/coverage API](https://github.com/knroy/go-xmlsec/blob/v2.0.2/dsig/verify.go),
[CXF WS-Security](https://cxf.apache.org/docs/ws-security.html), and the pinned
Apache source inspected in the PR-5 fixture work.
