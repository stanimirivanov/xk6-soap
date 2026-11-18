# Architecture and M01 plan review

Date: 18 November 2026. Status: proposal; no extension implementation tested.

Reviewed inputs in the parent project folder:

- `Research & Architecture Specification — xk6-soap A k6 Extension for SOAP + WS-Se.md`, revision 3 (423 lines).
- `xk6-soap — M01 Implementation Plan (Revision 2, aligned with spec Rev 3).md` (431 lines).

Line references below refer to those unchanged inputs. Proposed replacements are [architecture revision 4](architecture.md) and [M01 plan revision 3](../tasks/plan.md). This documentation work is tracked in [issue #1](https://github.com/stanimirivanov/xk6-soap/issues/1).

## Assessment

Keep the two-phase transport, byte-based key inputs, per-VU clients, and early independent interoperability gate. Do not implement the current documents verbatim: receive processing is contradictory, several advertised features have no callable API, and the dependency graph does not enforce its stated gates. Retain T0–T3 in M01, but make each claimed capability contingent on explicit tests. The original count of 25 PRs is not a constraint.

## Required corrections

### F01 — High: receive security must follow the protection order

**Evidence:** spec §4.5 lines 181–186 and plan PR20 line 347 always decrypt before verifying. Spec §7.2 line 310 and M02-PR2 require verification before decryption. These rules cannot both hold.

**Consequence:** decrypting an encrypt-then-sign message changes the signed ciphertext representation before verification. Conversely, a signature over plaintext generally cannot be verified until that plaintext is recovered. Fault extraction before decryption misses encrypted faults, and extraction before security acceptance can expose unauthenticated content as trusted.

**Correction:** use a configured receive policy independent of outbound order. Verify ciphertext first for encrypt-then-sign; decrypt into private bounded state and verify recovered plaintext for sign-then-encrypt. Publish application content only after required checks pass. Reject unsupported protection graphs. WSS allows ordering based on dependencies; it does not prescribe the draft's universal pipeline. See [SOAP Message Security §5, §8, §9, §11](https://docs.oasis-open.org/wss-m/wss/v1.1.1/os/wss-SOAPMessageSecurity-v1.1.1-os.html).

### F02 — High: coverage and trust are assertions, not a defined acceptance policy

**Evidence:** spec §5.3 permits `signBody: false`; §4.5 and plan PR17 require Body coverage. `verify` lacks inbound algorithm allow-lists, skew, maximum age, order, and encrypted-part coverage. `requireEncryption` does not say what must be encrypted.

**Consequence:** a valid signature over a decoy Body or an encrypted unrelated header could satisfy a superficial check. Missing, unsigned, or future timestamps have no deterministic outcome.

**Correction:** require the unique direct SOAP Body and required Timestamp to be covered by the accepted signature; bind verification results to the exact consumed nodes. Define pinned-certificate trust, algorithm/transform policy, duplicate ID rejection, timestamp boundaries, and body-content encryption coverage. Encryption alone does not establish sender identity. See [XML Signature Best Practices §3.1](https://www.w3.org/TR/xmldsig-bestpractices/).

### F03 — High: public payload and header APIs cannot express advertised features

**Evidence:** spec §5.2 defines no raw XML wrapping rule and no header input; PR16 signs WS-Addressing headers “when present,” and PR20 encrypts headers. No preceding task creates those headers. Object mapping does not define ordering, namespaces, nulls, scalar conversion, or mixed content.

**Consequence:** implementations can produce incompatible request shapes or impossible configuration options. Go map iteration can destroy XSD sequence ordering.

**Correction:** define raw payload as one operation element inserted without wrapping; define deterministic JS own-property ordering for object payloads, namespace rules, rejected values, and explicit header blocks/WS-Addressing inputs before protection tasks. Reject unsupported object mixed-content use and direct users to raw XML.

### F04 — High: XML and cryptographic resource limits are missing

**Evidence:** spec §7.2 only names DOCTYPE/entities and wrapping. There are no document/decrypted-byte, depth, node, reference, signature, or XPath bounds. The no-network rule is not extended to XML URI resolution.

**Consequence:** malicious responses can consume generator memory/CPU or trigger external resolution through optional library callbacks.

**Correction:** apply explicit finite limits before expensive work and after decryption; reject external references, unsupported transforms, ambiguous IDs and structures; never supply network/file resolvers. Fuzz both pre- and post-decryption boundaries. Context checks between stages do not interrupt an arbitrary synchronous library call.

### F05 — High: redaction promises conflict with canonical-byte diagnostics

**Evidence:** spec §7.5 and PR22 propose redacted envelopes plus the exact canonicalized octets. Body data, usernames, tokens and fault details can contain secrets even if Password elements are redacted. Spec §4.3 also preserves native HTTP debugging.

**Consequence:** canonical-byte dumps bypass redaction. The extension cannot sanitize k6's separate HTTP debug output.

**Correction:** production diagnostics contain fixed metadata and error codes only. Canonicalization dumps are test-only with synthetic fixtures. Document the separate HTTP debug boundary. Redaction tests cover malformed input, nested payload sentinels, token digests, key errors and both success/failure paths from the first security slice.

### F06 — Medium: library research misallocates timestamp work and overstates evidence

**Evidence:** spec §3.3 allocates timestamp work to custom code based on the feature list and describes PKCS#12 as decoding-only. Pinned [go-xmlsec timestamp source](https://github.com/knroy/go-xmlsec/blob/v2.0.2/wss/timestamp.go) exposes `AddTimestamp`, `AddTimestampWithID`, `ParseTimestamp` and `Timestamp.Check`. [go-pkcs12](https://pkg.go.dev/software.sslmate.com/src/go-pkcs12) has encoding APIs too; this extension needs decoding only.

**Correction:** reuse validated timestamp primitives, retain application freshness policy, and write custom UsernameToken only where necessary. Distinguish source inspection, compile evidence and independent interop. Remove star counts as selection criteria and stop calling README audit claims verification. Candidate k6 v2.3.0 and go-xmlsec v2.0.2 both declare Go 1.26.0; a tested exact patch toolchain remains to be selected.

### F07 — Medium: encryption terminology and wire parameters are ambiguous

**Evidence:** spec §4.5 calls RSA-wrapped content encryption “symmetric binding”; §5.3 gives `body|content|headers` without a structural distinction; `rsa-oaep-sha256` does not explicitly specify its MGF or URI.

**Correction:** call the implementation X.509 signature plus hybrid encryption, without promising a WS-SecurityPolicy binding. Keep SOAP Body as the envelope child: `content` encrypts its children; `body` encrypts the sole operation element inside it. Define header selectors and `EncryptedHeader` handling separately. Map OAEP to XML Encryption 1.1 URI, SHA-256 digest, MGF1-SHA256, empty label. [XML Encryption §5.5.2](https://www.w3.org/TR/xmlenc-core1/) distinguishes the digest and MGF; omitted MGF defaults to SHA-1.

### F08 — Medium: cache identity and lifecycle can bypass key decoding or distort load results

**Evidence:** spec §4.6 delays key loading until first use, yet §5.5 says configuration failures occur at construction. The cache is merely “content-hash keyed”; it does not include the PKCS#12 password or role-dependent validation. `crypto.Signer` is an interface, not a concurrency guarantee.

**Consequence:** a warm cache could conceal a wrong container password, and first-iteration timings include key parsing. Shared mutable library state is not made safe by the interface type.

**Correction:** initialize immutable concrete key material during construction, key cache entries by all decoding inputs, validate roles on every lookup, bound the cache, and test mixed correct/incorrect passwords and cross-VU first use. Do not cache runtime objects, request trees or credentials. Document inability to guarantee secret zeroization in Go/JS.

### F09 — Medium: result, error and metric semantics are incomplete

**Evidence:** spec §5.5 promises an “error value” absent from the response shape. No contract covers HTTP status 0, discarded/binary response bodies, malformed input types, repeated parse, or XPath result types. Spec §7.3 bounds tag names, not values. Parse counter semantics are obscured by `soap_reqs` naming.

**Correction:** define structured errors, `ok`, tri-state verification, unavailable-content behavior and XPath results. Count parse invocations explicitly, including repeated calls; a build without parse is not a parsed request. Bound values of extension-owned tags; user-defined k6 tags remain the script's responsibility. Measure parse crypto separately from build and HTTP latency.

### F10 — Medium: deterministic-output tests overreach

**Evidence:** spec §7.1 claims fixed clock/IDs make output reproducible; PR16 requires golden matrices across ECDSA algorithms. Encryption uses random keys/IVs and OAEP randomness; fixed times/IDs do not fix those. ECDSA determinism is implementation-dependent; see the [Go ECDSA signing API](https://pkg.go.dev/crypto/ecdsa).

**Correction:** golden-test deterministic envelope and canonicalized reference bytes and RSA-PKCS1v1.5 cases. Test randomized crypto by independent verification, structure, semantic round-trip and injected test randomness only where supported. An observed uniqueness sample does not prove a secure RNG; inspect the production randomness path and test RNG failure propagation.

### F11 — High: the task DAG does not enforce the advertised gates

**Evidence:** PR15 and PR19 lack a PR7 dependency. PR13 consumes `parse()` without depending on PR10 or the E2E runner. CP-T3 invokes a nightly job from PR23 although only PR21 is required to reach that checkpoint. PR16 and PR20 combine several independent capabilities into estimated 450-line tasks.

**Correction:** make the kernel gate an explicit prerequisite of crypto integration; include every consumed API/harness dependency; split signing/key-ID/header breadth and encryption order/header/receive work. Define checkpoints as dependency sets, not proximity in a numbered list. Keep PRs green without accepting configuration for not-yet-implemented features.

### F12 — Medium: performance, interop and release claims are not acceptance criteria yet

**Evidence:** spec §7.4 and PR23 leave X, N, runner and memory bounds undefined. PR13 can replace a JMeter capture with a spec vector yet still claim migration coverage. PR25 tags a release even though the adopted workflow ends at PR creation. The plan says no repository exists and asks for organization/license despite the checkout.

**Correction:** freeze a recorded performance baseline and numeric regression budget before the performance gate; label unavailable migration evidence as unverified; add both directions of independent interop, encrypted faults and negative cases. Use `github.com/stanimirivanov/xk6-soap`, preserve Apache-2.0, and prepare a release workflow without executing a release. Future issue execution follows the adopted issue/branch/PR workflow.

## Recommendations and unresolved product decisions

- Keep full M01 breadth as requested by the inputs; prioritize RSA/body-content core before breadth. If earlier delivery is more valuable, explicitly move object mapping, ECDSA, extra key IDs and header encryption to a follow-up milestone rather than silently dropping them.
- Default to signed inbound responses when outbound signing is enabled; allow an explicit unsigned-response policy for services that require it. This policy must be documented in examples.
- Do not claim SHA-1-free operation: UsernameToken PasswordDigest and ThumbprintSHA1 are protocol-specific uses, separate from prohibited SHA-1 XML signatures/digests.
- Reject unsafe legacy receive configurations by default in M02. The draft's “encrypt-only default” does not solve CBC authentication or padding-oracle risks. A future legacy spec needs its own threat model and interoperability gate.
- Confirm the actual JMeter plugin/version and sanitized request capture, supported endpoint policies, CI runner, and release targets before their dependent tasks. No WCF/Spring-WS/Metro compatibility claim follows from WSS4J-only tests.

## Review verification

The checkout was clean on `main`, with only Apache-2.0 `LICENSE`, at base commit `02ad8c9`; `git pull --ff-only` reported up to date. No existing issues or milestones were present before this review. Primary protocol documentation and selected pinned dependency sources were inspected. No Go build, cryptographic test, benchmark, dependency audit, or Java fixture was run; the replacement plan explicitly schedules these proofs.
