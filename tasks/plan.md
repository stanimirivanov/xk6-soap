# xk6-soap — M01 Implementation Plan, Revision 3

Status: proposed replacement for plan Rev 2, aligned with [architecture Rev 4](../docs/architecture.md), 18 November 2026. This is planning work only. [Review findings](../docs/review.md) explain the corrections. Implementation is not started by this proposal.

## Repository, scope and task tracking

Repository: `stanimirivanov/xk6-soap`, Go module `github.com/stanimirivanov/xk6-soap`, Apache-2.0. Initial main contained LICENSE only. M01 retains T0–T3 and release preparation; M02 retains legacy algorithms. This plan does not reduce scope to fit the previous arbitrary 25-PR count.

Tasks are tracked in GitHub Issues under **M01: SOAP and modern WS-Security**. The current documentation review is [#1](https://github.com/stanimirivanov/xk6-soap/issues/1). The implementation tasks below are proposals, not already-created or approved issues. On adoption, materialize them using the exact titles below, one issue per task, copying scope, dependencies, acceptance and verification. Replace the proposal IDs in the index with issue links; do not duplicate the execution checklist in another file. Milestone checkpoints are recorded here and do not need separate implementation PRs.

For each authorized task: fast-forward clean main, create/use its dedicated milestone-linked issue, branch `feature/issue-N` or `fix/issue-N`, implement its scope, validate, commit `[#N] summary`, push, create PR titled `[#N] PR-k: title` with `Closes #N`, summary and verification, then stop. Dependencies mean the prerequisite has landed on main before starting; this workflow does not presume stacked branches or authorization to merge. Revisions reuse the issue/branch and happen only on request. No automatic CI polling or release tagging.

## Gates and dependency rules

New commands supplied by PR-1: `make lint`, `make test` (race-enabled), `make vuln`, `make build-k6`. E2E/interop/performance/fuzz commands are added by the tasks that supply those harnesses; no empty successful targets. Pins and exact tool commands are committed in the Makefile/CI. **SG** means lint, race tests and govulncheck for code changes; documentation-only changes use Markdown/link/diff checks. Use focused tests during development and SG once for delivery, with affected E2E/interop tests. Repeat only after relevant changes or failure diagnosis.

| Checkpoint | Required tasks complete | Evidence |
| --- | --- | --- |
| CP-A: runnable plain transport | 1, 2, 3, 4 | Build + E2E, response errors/limits and failing-check exit code |
| CP-K: core kernel viability | 5, 6, 7 | Exact candidate pins; independent sign/verify and encrypt/decrypt, both orders, tamper rejection |
| CP-T1: credentials | 9, 10 | SOAP 1.1/1.2 Digest/Text and stale/replay rejection in server fixture |
| CP-T2: signed exchanges | 11, 12, 13, 16, 17, 18 | Both directions, all advertised signature/key-ID cases, wrapping negatives |
| CP-T3: encrypted exchanges | 19, 20, 21, 22, 23, 24 | Both directions/orders/targets, encrypted faults and hostile-input regressions |
| CP-P: release evidence | 14, 15, 25, 26 | Public API/metrics exercised; frozen benchmark and completed interop documentation |
| CP-R: release ready | 27 | Supported-version matrix and release dry-run; no publication |

PR-11 through PR-24 crypto paths transitively require CP-K via explicit dependencies. Plain SOAP/object work may proceed independently. Serialize commits touching shared options, provider and module lockfiles. Parallel scheduling is optional; this plan does not require additional agents. Core kernel failure blocks dependent work and requires an evidence-based ADR/replan; changing the fixture to weaken required security is not a valid fix.

## Ordered task index

| ID | Proposed issue title | Dependencies | Estimated scope |
| --- | --- | --- | --- |
| 1 | [PR-1: Pin toolchain and establish the k6 module harness](https://github.com/stanimirivanov/xk6-soap/issues/7) | none | Medium |
| 2 | [PR-2: Add a deterministic SOAP E2E harness](https://github.com/stanimirivanov/xk6-soap/issues/9) | 1 | Medium |
| 3 | [PR-3: Implement bounded SOAP parsing and payload contracts](https://github.com/stanimirivanov/xk6-soap/issues/11) | 1 | Medium |
| 4 | PR-4: Deliver plain build and parse with faults and XPath | 2, 3 | Medium |
| 5 | PR-5: Establish the independent WSS4J fixture | 1 | Medium |
| 6 | PR-6: Prove candidate signature coverage and serialization | 3, 5 | Medium |
| 7 | PR-7: Gate the candidate on both encryption orders | 6 | Medium |
| 8 | PR-8: Load and cache validated key material | 1 | Medium |
| 9 | PR-9: Define executable security policy and option validation | 3, 8 | Medium |
| 10 | PR-10: Deliver UsernameToken and Timestamp exchanges | 4, 5, 9 | Medium |
| 11 | PR-11: Build signed SOAP requests with the accepted provider | 7, 10 | Medium |
| 12 | PR-12: Verify responses against exact coverage and trust | 4, 11 | Medium |
| 13 | PR-13: Enforce signed timestamp freshness | 12 | Small |
| 14 | PR-14: Instrument SOAP outcomes and processing costs | 4, 9 | Small |
| 15 | PR-15: Add deterministic object payload mapping | 4 | Small |
| 16 | PR-16: Add header inputs and signed WS-Addressing | 11, 12 | Medium |
| 17 | PR-17: Add independently verified signature algorithms | 13 | Medium |
| 18 | PR-18: Add independently verified X.509 key identifiers | 13 | Medium |
| 19 | PR-19: Build sign-then-encrypt requests | 11 | Medium |
| 20 | PR-20: Accept encrypted responses and encrypted faults | 13, 19 | Medium |
| 21 | PR-21: Implement encrypt-then-sign exchanges | 20 | Medium |
| 22 | PR-22: Encrypt and recover selected SOAP headers | 16, 21 | Medium |
| 23 | PR-23: Fuzz and harden complete security boundaries | 17, 18, 22 | Medium |
| 24 | PR-24: Complete the independent interoperability matrix | 10, 15, 17, 18, 22, 23 | Medium |
| 25 | PR-25: Freeze performance and retention regression budgets | 14, 24 | Medium |
| 26 | PR-26: Document supported contracts and migration evidence | 24, 25 | Medium |
| 27 | PR-27: Prepare reproducible release and compatibility checks | 26 | Small |

Medium means one cohesive contract and its tests, usually 3–5 production/harness files plus fixtures. These are scope estimates, not LOC promises. If a task reveals another independent subsystem, split it before implementation and record new dependencies. No task may quietly defer its security negatives to PR-23.

## Task requirements and acceptance

### PR-1: Pin toolchain and establish the k6 module harness

Scaffold delivered in PR #4; remaining runtime probes and [ADR-0001](../docs/adr/0001-k6-runtime-contract.md) tracked in issue #7.

- **Scope/files:** `go.mod`, `soap.go`, runtime smoke tests, Makefile, CI configuration. Candidate k6 v2.3.0; select exact compatible Go patch and xk6/lint/vulnerability-tool pins. Probe constructor, ArrayBuffer conversion, init/execution contexts and metric registration now.
- **Acceptance:** named Client construction runs through Sobek and custom k6; lifecycle probes settle actual behavior; CI can build and run race/lint/vulnerability checks. A temporary constructor may exist only as a non-release scaffold, with unsupported methods failing explicitly.
- **Verify:** SG, `make build-k6`, smoke script; pin inventory and constructor/context findings in ADR. No SOAP or security support claimed.

### PR-2: Add a deterministic SOAP E2E harness

- **Scope/files:** mock server, E2E runner, synthetic fixtures and `make e2e`; echo/capture plus status 0 simulation, binary/empty bodies, both fault shapes and delays.
- **Acceptance:** real built k6 calls the local server; a failing check with a threshold produces nonzero exit; processes, ports and temporary files are cleaned up and readiness has a deadline.
- **Verify:** runner unit tests and plain-HTTP passing/failing scripts. Captures use synthetic data and are not production log behavior.

### PR-3: Implement bounded SOAP parsing and payload contracts

- **Scope/files:** request/XML validation helpers, options types and tests. Define finite limits and error codes; raw operation input, SOAP namespace/structure and version-specific action formatting.
- **Acceptance:** valid 1.1/1.2 envelopes generated; wrapper/DTD/entity/namespace/header-injection/oversize/depth cases fail predictably; adversarial limits apply before large allocations. Document any measured hard ceilings; default-only limits are acceptable until increases are proved safe.
- **Verify:** focused structural tables, malformed/fuzz seeds and SG. No signature/C14N implementation or custom XML parser.

### PR-4: Deliver plain build and parse with faults and XPath

- **Scope/files:** client bindings, response service, XPath adapter and E2E scripts; pin XPath dependencies. Implement architecture §§4–5 and result contract in §8 for plain mode.
- **Acceptance:** real k6 build/post/parse works; accepted faults, HTTP status 0, non-XML, empty/discarded/binary bodies obey documented precedence; XPath node/scalar/namespace/error/limit behavior is stable and confined to Body.
- **Verify:** SG and affected E2E, including no uncaught panic for hostile remote data and exact JS result types. Reach CP-A.

### PR-5: Establish the independent WSS4J fixture

- **Scope/files:** pinned CXF/WSS4J/JDK container, synthetic key generation, fixture self-tests, `make interop`. Provide policy-controlled request and response endpoints, initially UsernameToken/plain faults.
- **Acceptance:** known reference Digest/Text accepted; bad digest/stale/replayed token rejected by configured server policy; Docker starts in CI with bounded readiness/cleanup. No secrets or insecure fixture keys reused outside tests.
- **Verify:** fixture self-tests independent of the Go provider. Record exact versions, BSP/policy settings and test certificate identity. Do not substitute a provider-backed mock for independent interop.

### PR-6: Prove candidate signature coverage and serialization

- **Scope/files:** `internal/wssec` adapter and probe tests, signature fixture endpoint, kernel ADR. Compile v2.0.2 and reuse its timestamp/ID primitives where correct.
- **Acceptance:** Go signs Body+Timestamp and WSS4J verifies; WSS4J signs and Go verifies with exact consumed-node coverage; duplicates/decoy Body/tamper/untrusted cert fail. Demonstrate namespace/InclusiveNamespaces handling with independent fixtures.
- **Verify:** SG and signature interop; record original/canonical bytes for synthetic deterministic RSA fixtures, source API decisions and constraints. Fail the candidate if it cannot preserve node identity and signed data.

### PR-7: Gate the candidate on both encryption orders

- **Scope/files:** provider encryption probe, WSS4J encryption endpoint, gate tests and ADR. No JS crypto configuration accepted yet.
- **Acceptance:** independently produced AES-128/256-GCM, OAEP-SHA256/MGF1-SHA256 messages succeed both directions and both orders; wrong key/tag/order/parameters and partial encrypted Body fail the required policy; record how the provider protects/recovers coverage and rejects unsupported graphs.
- **Verify:** SG and core interop with exact wire URI/parameters. CP-K requires a written pass or blocking ADR. Provider self-round-trip is supplementary only.

### PR-8: Load and cache validated key material

- **Scope/files:** key loader/cache, runtime byte decoding and synthetic key fixtures; pin PKCS#12 dependency. Implement architecture §7.
- **Acceptance:** valid PEM/PKCS#12 identities load during construction and mismatch/expiry/role/size/ambiguous containers fail; same bytes with wrong password fail even after a cache hit; concurrent same-key loads are deduplicated with bounded memory and immutable published keys.
- **Verify:** key tests, OpenSSL-3-generated fixture decoding, invalid passwords before/after success, cross-VU race tests and SG. No arbitrary crypto.Signer concurrency assertion.

### PR-9: Define executable security policy and option validation

- **Scope/files:** typed security/receive policy, validator, error mapping and safe metadata diagnostics. Policy definitions may precede capabilities, but public construction rejects enabled unavailable features until their task activates them.
- **Acceptance:** validation covers every block, enum, missing-key role, conflicting order and selector; outbound and inbound defaults are separate; errors/logs never reflect secret inputs and use stable codes. Tests prevent a partially implemented configuration from silently doing nothing.
- **Verify:** runtime decoding and invalid-option matrix, nested unknown keys, secret sentinels, SG. Legacy options stay unavailable.

### PR-10: Deliver UsernameToken and Timestamp exchanges

- **Scope/files:** token builder, provider-independent timestamp facade, credential overrides and E2E/interop scripts. Reuse candidate timestamp helper only through an adapter with tested behavior; custom policy owns freshness choices.
- **Acceptance:** independent Digest vector uses exact serialized Created and raw nonce bytes; overrides leave defaults unchanged and RNG failures throw safely; Digest/Text × SOAP 1.1/1.2 succeeds at WSS4J and wrong credentials yield parsed faults.
- **Verify:** SG, E2E, UsernameToken interop including missing/stale Created and replay fixture. CP-T1. Label absent JMeter capture as unverified rather than replacing the migration claim.

### PR-11: Build signed SOAP requests with the accepted provider

- **Scope/files:** sign integration and bindings; activate RSA-SHA256/SHA256/BST. No encryption or additional key-ID support enabled.
- **Acceptance:** actual Body, Timestamp and present UsernameToken signed in one tree; one final wire serialization preserves verified digests; missing coverage/selectors or incompatible keys fail before transport.
- **Verify:** SG, deterministic RSA/canonical fixtures and real k6 → WSS4J signed request; synthetic secret sentinels absent from metadata logs. Depends on the successful PR-7 gate, not merely the existence of its code.

### PR-12: Verify responses against exact coverage and trust

- **Scope/files:** receive service/provider result integration and security-first fault extraction. Activate exact pinned trust, RSA-SHA256 and structured results.
- **Acceptance:** WSS4J response accepted; missing signature, duplicate IDs, decoy Body, unsigned consumed content and wrong trust fail; body/fault/XPath are unavailable when required acceptance fails, and explicit skipped signature yields null.
- **Verify:** SG, hostile unit fixtures and independently signed E2E response. No reparse/reselection of a different application Body after verification.

### PR-13: Enforce signed timestamp freshness

- **Scope/files:** freshness policy and table tests. Separate clock skew/max age from outbound clock offset; require signed Created/Expires for required timestamp.
- **Acceptance:** equality boundaries, future Created, expired/reversed/excess lifetime, missing/duplicate/unsigned Timestamp rejected; explicit skip semantics stable; local wall-clock fixture injectable without changing production randomness.
- **Verify:** SG and independent valid/stale response fixture. Freshness is documented as distinct from replay protection.

### PR-14: Instrument SOAP outcomes and processing costs

- **Scope/files:** metrics helper and summary E2E scripts. Four architecture §9 metrics, including receive duration; no new high-cardinality metadata.
- **Acceptance:** metrics registered once with correct units/types; repeated parse, build failure, skipped parse and remote failure have exact sample counts; init misuse produces an error, not panic/deadlock, and canceled VU sampling is safe.
- **Verify:** SG, metric-summary E2E including a SOAP-failure threshold with HTTP 200. Establish fixed extension tag values, not merely fixed tag names.

### PR-15: Add deterministic object payload mapping

- **Scope/files:** object marshaler and runtime/E2E tests; no XSD-aware schema inference.
- **Acceptance:** JS own-property/array order, attributes, text, escaping and namespace inheritance match §5; invalid types/cycles/mixed content fail; raw multi-namespace XML remains available and unchanged.
- **Verify:** exact envelope fixtures, Sobek tests proving no unordered Go-map conversion, SG and request echo E2E.

### PR-16: Add header inputs and signed WS-Addressing

- **Scope/files:** custom/header addressing builders, selectors and sign/receive coverage integration.
- **Acceptance:** real callers can supply headers/Addressing; missing/colliding selectors and action/To inconsistencies fail; required custom and all generated addressing headers are covered, and response mandatory-header policy is enforced.
- **Verify:** SG, SOAP-version tables, independent signed header exchange and tampered selected-header negative. Define IDs before signing, never mutate protected XML afterward.

### PR-17: Add independently verified signature algorithms

- **Scope/files:** signature policy activation, curve/algorithm mapping and fixture matrix for RSA SHA-384/512 and ECDSA pairs.
- **Acceptance:** every advertised pair verifies both directions; disallowed inbound algorithm and wrong curve fail; ECDSA XMLDSig values use fixed-width r||s (including P-521 width).
- **Verify:** SG and each algorithm's independent interop. Golden canonical bytes plus semantic signature checks; do not require uncontrolled randomized SignatureValue equality.

### PR-18: Add independently verified X.509 key identifiers

- **Scope/files:** key identifier resolver/builder and matrix. Normalize `direct` alias and add issuer-serial, X509, SKI and thumbprint forms.
- **Acceptance:** identifiers resolve only to pinned certificate candidates; missing SKI/ambiguous or forged identifiers fail; all advertised forms work both directions and protocol SHA-1 identifiers do not unlock SHA-1 signature algorithms.
- **Verify:** SG and independent key-ID matrix including a substituted BST/untrusted certificate. CP-T2 additionally requires PR-16/17 and their evidence.

### PR-19: Build sign-then-encrypt requests

- **Scope/files:** outbound integration for content and operation-element targets, both GCM key sizes and fixed OAEP parameters.
- **Acceptance:** SOAP Body remains intact and plaintext sentinel is absent from encrypted target; fresh CSPRNG key/IV and RNG error propagation are tested; signing provenance and wire layout survive encryption.
- **Verify:** SG and real k6 → WSS4J content/body target cases. Observe sample uniqueness as a sanity check, not proof of RNG security.

### PR-20: Accept encrypted responses and encrypted faults

- **Scope/files:** receive integration for sign-then-encrypt, required body encryption coverage, post-decrypt limits and error conversion.
- **Acceptance:** independent encrypted success/Fault parsed only after signature acceptance; plain or partially encrypted Body fails required-encryption policy; bad tags/keys/oversized decrypted XML expose no plaintext or detailed crypto error.
- **Verify:** SG, adversarial post-decryption tests, WSS4J → k6 encrypted response/fault and failed-decrypt log sentinels.

### PR-21: Implement encrypt-then-sign exchanges

- **Scope/files:** order-specific send/receive orchestration, retaining ciphertext coverage/provenance.
- **Acceptance:** verify-before-decrypt enforced for ciphertext signatures; separate outbound/inbound orders work intentionally; tampered EncryptedKey, ciphertext or configured-order mismatch fails without fallback.
- **Verify:** SG and both directions/orders with assertions that no decrypted result escapes before required acceptance. A final round-trip alone is insufficient to prove operation order.

### PR-22: Encrypt and recover selected SOAP headers

- **Scope/files:** header-target integration with wsse11:EncryptedHeader, metadata preservation and coverage rules.
- **Acceptance:** selected headers recovered correctly in both orders; missing/duplicate targets and malformed wrapper/role metadata fail; encrypting only headers never satisfies required Body encryption.
- **Verify:** SG and independent header-target combinations for both SOAP versions and both orders. Bodies and unselected headers remain semantically correct.

### PR-23: Fuzz and harden complete security boundaries

- **Scope/files:** cross-boundary fuzz corpus, resource accounting tests and regression fixes within the specified contracts; `make fuzz-smoke` plus bounded scheduled fuzz job.
- **Acceptance:** pre/post-decrypt XML, ID resolution, Fault/XPath projection and policy parsing have adversarial coverage; all finite limits and sanitized failures are exercised; no panic, external resolution or unbounded cache growth for the corpus.
- **Verify:** SG, fixed-duration fuzz smoke, cancellation/resource tests and regression seed replay. Every bug found here gets a root-cause regression; baseline hardening already ships with its owning task.

### PR-24: Complete the independent interoperability matrix

- **Scope/files:** matrix manifest, missing independent fixture cases and CI integration, without new public features.
- **Acceptance:** explicit rows cover both SOAP versions, Digest/Text, all signature algorithms/key IDs, content/body/header targets, both orders and receive faults; each claimed combination maps to a named test or explicit unsupported configuration; security negatives fail through actual k6 results/thresholds.
- **Verify:** SG, `make e2e`, full `make interop`. Core combinations are exhaustive; broader cross-products can use pairwise coverage only if individual dimensions are independently proved and omitted combinations are documented, not claimed tested. CP-T3.

### PR-25: Freeze performance and retention regression budgets

- **Scope/files:** Go build/parse benchmarks, key-init benchmark, reproducible k6 profiles, retention tests and nightly workflow. Pin runner resources and fixture versions.
- **Acceptance:** baseline records build/parse p95, allocations, generator CPU, dropped iterations and throughput by mode; commit actual numeric thresholds from a reviewed stable baseline with a proposed 20% regression budget; repeated GC-normalized retained-heap/goroutine measurements establish explicit bounds and detect monotonic growth.
- **Verify:** `make bench`, fixed 500 VU × 100 iteration profile and arrival-rate profile, SG. Freeze N, warmup, measurement windows, repeat count and bytes/goroutine thresholds in the first baseline artifact before enabling gating; no X/N placeholders at acceptance and no automatic baseline refresh to make failures pass.

### PR-26: Document supported contracts and migration evidence

- **Scope/files:** README, executable examples, API/security limitations, interop/benchmark reports, JMeter mapping and ADR index.
- **Acceptance:** examples run as written with SOAP thresholds; every supported feature points to independent evidence and every deferred feature is named; JMeter plugin/version/capture identity is recorded, or migration comparison remains explicitly unverified. No misleading compatibility claim from a spec-example fallback.
- **Verify:** docs/link checks, example E2E and named-test reference validation. CP-P includes PR-14/15. Proposed architecture becomes a description of tested behavior, with discrepancies resolved explicitly.

### PR-27: Prepare reproducible release and compatibility checks

- **Scope/files:** supported-version CI matrix, release workflow dry-run, dependency update policy, release checklist and license/dependency notices.
- **Acceptance:** declared Go/k6 combinations pass, reproducible xk6 build instructions work, govulncheck remains a required gate; artifacts/metadata pass dry-run; registry requirements and limits for custom binaries are documented without assuming cloud availability.
- **Verify:** full supported matrix and release dry-run once. Prepare `v0.1.0` notes but do not tag, publish or merge. Deliver the PR and stop; CP-R is readiness evidence only.

## Traceability and changes from plan Rev 2

| Original scope | Revised tasks |
| --- | --- |
| PR1/2 scaffold, architecture | This docs proposal; 1 |
| PR3 configuration | 3, 8, 9 |
| PR4/6/7 harness and kernel gate | 2, 5, 6, 7 |
| PR8/9/10 plain SOAP, marshaling, parsing | 3, 4, 15 |
| PR11 metrics | 14, now includes parse duration |
| PR12/13 UsernameToken | 10 |
| PR14 keys | 8 |
| PR15/16/17/18 signing breadth/receive | 11, 12, 13, 16, 17, 18 |
| PR19/20/21 encryption breadth/receive | 19, 20, 21, 22, 24 |
| PR22 diagnostics | 9 and every security task, cross-checked in 23 |
| PR23 performance | 25 |
| PR24/25 docs/release | 26, 27 |

| Review finding | Resolution tasks |
| --- | --- |
| F01 order/fault acceptance | 7, 12, 20, 21 |
| F02 coverage/trust/freshness | 6, 9, 12, 13, 18, 20 |
| F03 payload/header API | 3, 4, 15, 16, 22 |
| F04 bounds | 3, 4, 7, 20, 23 |
| F05 safe diagnostics | 9, 10, 11, 20, 23, 26 |
| F06 source evidence | 1, 6, 8, 10 |
| F07 encryption profiles | 7, 19, 20, 21, 22 |
| F08 cache/lifecycle | 1, 8, 25 |
| F09 results/metrics | 4, 9, 14 |
| F10 randomized testing | 6, 7, 17, 19 |
| F11 dependencies/sizing | Revised DAG and checkpoints above |
| F12 measurable claims/delivery | 5, 24, 25, 26, 27 |

## Remaining decisions and M02

Confirm actual target-service response policies and the JMeter plugin/capture before claiming migration equivalence. Choose CI runner capacity and exact dependency pins through the assigned tasks. M01 remains substantial; any choice to defer breadth needs an explicit scope revision, not weakened acceptance criteria.

M02 starts with an approved legacy threat model and signing/encryption candidate spike. Do not assume an encrypt-only CBC default is safe or that verification can always precede decryption. Candidate providers, receive restrictions, downgrade controls, native build costs and rollout compatibility must be resolved before a legacy implementation plan or issues are approved. No legacy dependency/stub is required in M01.
