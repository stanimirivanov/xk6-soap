# Test strategy

The strategy covers the [supported SOAP and WS-Security client contracts](contracts.md).
WSDL discovery, parsing, and schema caching are outside this scope. k6 owns
HTTP, TLS, and HTTP authentication. The extension owns message construction,
response acceptance, and the JavaScript contract around those operations.

## Evidence by layer

| Layer | What it proves |
| --- | --- |
| Go and Sobek tests | Envelope and payload encoding, SOAP Fault projection, parser limits, security policy and response acceptance, adapter behavior, and concurrent access to shared keys and metrics. Use focused cases for edge conditions and run the suite with the Go race detector through `make verify`. |
| Public k6 suite | `make compatibility` checks the pinned custom k6 build and runs smoke and public E2E tests for lifecycle, transport outcomes, metrics, receiver-side assertions, and the forced exit-99 threshold control. |
| Native k6 race suite | `make e2e-race` builds a separate race-instrumented k6 binary and verifies signed replies and isolation under a fixed multi-VU workload. |
| Independent CXF/WSS4J suite | A separate implementation produces or verifies wire messages for the supported combinations in the [interop matrix](../test/interop/matrix.json). Run `make interop` against the cold fixture. |
| Vulnerability checks | `make vuln` scans the Go source and the pinned custom k6 binary with govulncheck. |
| Fuzzing | Go tests replay the committed seeds. Scheduled fuzzing searches the XML, XPath, policy, and receive boundaries. Retain minimal synthetic regressions for new findings. |
| Performance and retention | `make bench` checks frozen throughput, latency, allocation, and Go retention budgets on the reference host. The scheduled runner remains tracked in [#72](https://github.com/stanimirivanov/xk6-soap/issues/72). The multi-VU correctness run carries no performance or retention budgets. |

The loopback suite adapts W3C SOAP 1.2 cases T12 and T15 to response acceptance.
An unknown mandatory header targeted at the ultimate receiver withholds the
Body. The same header targeted at an unrelated role leaves it queryable.
Record the upstream case ID, source, applicable contract, expected public
result, and any adaptation for future additions. Use material with appropriate
provenance and reuse terms. [W3C T12](https://www.w3.org/TR/soap12-testcollection/#T12) ·
[W3C T15](https://www.w3.org/TR/soap12-testcollection/#T15)

## Public runtime acceptance

Use an explicit action and an omitted action for each SOAP version. At the
receiver, parse the media type and XML and assert the UTF-8 charset and
Envelope namespace along with the version-specific headers.

| SOAP version | Explicit `urn:echo` | Omitted action |
| --- | --- | --- |
| 1.1 | `text/xml` and `SOAPAction: "urn:echo"` | `text/xml` and `SOAPAction: ""` |
| 1.2 | `application/soap+xml` with `action="urn:echo"` and no `SOAPAction` header | `application/soap+xml` with neither an `action` parameter nor a `SOAPAction` header |

The public JavaScript suite asserts each version's Fault code, reason, and
detail. It also checks nested-null payload and typed-array body rejection.
A verified HTTPS exchange exercises k6 transport configuration with synthetic
Basic Auth and a missing-auth control. Keep credentials and keys synthetic and
diagnostics bounded.

The hosted Linux race job runs 16 VUs with 20 fixed iterations each. Each
iteration builds a signed request using shared immutable key material. The
loopback peer echoes the exact received bytes. The receiver requires all
320 expected VU and iteration markers exactly once. The client checks the
matching marker after signature and Timestamp verification. A separate control
returns an earlier, still-valid signed reply and proves that the marker check
fails. Fixture and process deadlines bound each run.

## Merge policy

The active `main` ruleset requires the GitHub Actions `required-ci` and
`vulnerabilities` checks. `required-ci` passes only when Go quality, public
k6 compatibility, native k6 race, WSS4J interop, and vulnerabilities all report
explicit success. The requirement applies to every PR targeting `main`,
including docs-only PRs. Scheduled fuzz searches and reference-host performance
comparisons run separately. [Active ruleset](https://github.com/stanimirivanov/xk6-soap/rules/27548817)

WSS4J reports provisioning and assertions as distinct stages. A terminal Maven
artifact-transfer HTTP 429, 502, 503, or 504 from a configured repository
permits one cold image build retry within the 35-minute job ceiling. CI retains
both attempts' diagnostics and runs the assertions once after provisioning
succeeds. A missing artifact after resolution, an unclassified failure, a
failed assertion, or an outage that persists after the retry blocks merging.
[ADR-0007](adr/0007-required-independent-interop.md)

## Completed rollout

| Change | Delivery evidence |
| --- | --- |
| Receiver-side wire, Fault, W3C, and HTTPS checks | [Public SOAP wire and standards tests](https://github.com/stanimirivanov/xk6-soap/pull/101) |
| Native race workload and isolation controls | [Native multi-VU k6 race workload](https://github.com/stanimirivanov/xk6-soap/pull/103) |
| WSS4J provisioning retry and failure evidence | [Bounded Maven outage retry](https://github.com/stanimirivanov/xk6-soap/pull/105) |
| Stable aggregate, hosted timing and cancellation evidence, and active enforcement | [Required CI rollout](https://github.com/stanimirivanov/xk6-soap/pull/107) · [Activation runbook](ci-activation.md) |
