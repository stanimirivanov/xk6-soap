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

The loopback suite adapts W3C SOAP 1.2 cases to client response acceptance.
An unknown mandatory header withholds the Body when it targets the ultimate
receiver or `next`, or omits the role. The same block leaves the Body queryable
when it targets `none` or an unrelated role, or uses an optional value. A
synthetic SOAP 1.1 reply exercises projection of a qualified
`VersionMismatch` Fault.
Record the upstream case ID, source, applicable contract, expected public
result, and any adaptation for future additions. Use material with appropriate
provenance and reuse terms. The [coverage inventory](soap12-coverage.md) maps
all 125 upstream cases to client test evidence or a scope decision.
[W3C T12](https://www.w3.org/TR/soap12-testcollection/#T12) ·
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

### Native race payload corpus

The [native race payload migration](https://github.com/stanimirivanov/xk6-soap/issues/153)
stores 320 literal Echo operations in one JSON array. Each line pairs one
exchange marker with its complete operation XML, in VU and iteration order. k6 loads the corpus at
initialization and selects by the current marker, then passes the XML unchanged
to `Client.build()`. Envelope construction and signing remain part of the test.
[Native race corpus](../test/fixture/testdata/soap12/native-race-operations.json)

The receiver derives the expected marker set independently of the corpus. It
rejects missing, extra, or duplicate entries, an incorrect Echo namespace, and
any XML marker that disagrees with its key. Before substituting a stale reply,
the receiver compares the raw Body operation bytes in each signed request with
the corpus entry. The client checks each verified reply against its own runtime
marker. Swapping two valid operations fails the client check. Sending a
different Echo serialization with the same marker fails the receiver byte
comparison. Failure diagnostics omit SOAP bodies.

`make e2e-race` checks that signing preserves the operation bytes for all 320
inputs and requires 320 verified and 320 matching replies. The stale-reply
control reuses `1-0` and `1-1` and requires 2 verified and 1 matching reply with
exit code 99. The focused corpus and byte checks run under `make verify`.
Public k6 E2E and the WSS4J pre-push gate cover the surrounding runtime and
interop paths.

### Public HTTP and HTTPS XML fixtures

The public k6 scripts load five byte-stable XML inputs from
`test/fixture/testdata/soap12/`. They cover the SOAP 1.1 declaration Echo
operation, a complete SOAP 1.2 Fault Envelope with two Code/Value elements,
one plain-client EncryptedData Envelope per SOAP version, and the HTTPS
Echo operation. [Public fixture migration](https://github.com/stanimirivanov/xk6-soap/issues/155)

Both Echo requests go through `Client.build()`. The receiving harness reads
each fixture independently and compares the raw Body operation bytes. It also
checks the SOAP 1.1 request's UTF-8 declaration. The HTTPS receiver checks
Basic Auth before reading the body. The loopback receiver captures the
complete malformed Fault request for byte comparison. The plain client passes
the two complete EncryptedData Envelopes to `Client.parse()`. The Fault Detail
probe uses the reply, and the transport probes keep their existing stubs.

The HTTP run requires 58 requests and checks status, errors, and content
withholding. The forced HTTP failure must exit 99. The HTTPS run uses loopback
TLS and requires HTTP 200 with Basic Auth and HTTP 401 without it. Both HTTPS
interruption controls must exit 99. A temporary byte-only Echo change that
preserves the marker fails the receiver comparison. Mismatch diagnostics report
byte counts without logging SOAP bodies.

Focused HTTP and HTTPS checks, `make verify`, public `make e2e`, and the cold
WSS4J pre-push gate provide delivery evidence.

### WSS4J matrix Echo fixtures

The [matrix Echo migration](https://github.com/stanimirivanov/xk6-soap/issues/157)
pins two literal operation inputs. An unprotected companion build compares the
raw Body operation with the fixture bytes for each SOAP version and outcome.
The matrix sends 48 live protected exchanges. The
[interop fixture guide](../test/interop/README.md#matrix-echo-fixtures) records
the fixture provenance, quote-style control, and verification commands.

### WSS4J matrix Header fixtures

The [matrix Header migration](https://github.com/stanimirivanov/xk6-soap/issues/159)
pins Trace and Other. A plain companion build for each SOAP version compares
their ordered raw XML before WS-Security. The matrix retains all 48 protected
exchanges and the selective encryption and visibility checks. The
[interop fixture guide](../test/interop/README.md#matrix-header-fixtures)
records the quote-style control and verification commands.

### Dedicated WSS4J Header encryption fixtures

The dedicated suite pins the Echo and Trace inputs and reuses the identical
matrix Other block. Plain builds compare the raw Body and ordered Header bytes
before WS-Security. The four live exchanges check wire visibility and verify
the decrypted and signed reply, which must also fail the stricter Body
encryption policy. See the
[interop fixture guide](../test/interop/README.md#dedicated-header-encryption-fixtures)
for provenance, the quote-style control, and verification commands.

### WSS4J signed receive Echo fixtures

The signed receive suite pins the success Echo and reuses the identical
matrix Fault trigger. Plain builds compare exact Body operation bytes
before signing. The four live exchanges retain independent replies and
the trust, tampering, and verification-skip controls. See the
[interop fixture guide](../test/interop/README.md#signed-receive-echo-fixtures)
for provenance, the quote-style control, and verification commands.

### WSS4J encrypted response Echo fixtures

The encrypted response suite pins the success Echo and reuses the identical
matrix Fault trigger. Plain builds compare the raw Body operation bytes for
both SOAP versions and outcomes before WS-Security. The 16 live exchanges
cover encrypted success and Fault replies, authenticated content projection,
and withholding after tampering. See the
[interop fixture guide](../test/interop/README.md#encrypted-response-echo-fixtures)
for provenance, the quote-style control, and verification commands.

### WSS4J signed Timestamp freshness Echo fixtures

The Timestamp freshness suite pins the success Echo and reuses the identical
matrix Fault trigger. Plain builds compare the raw Body operation bytes for
both SOAP versions and outcomes before signing. The 12 live exchanges retain
runtime-generated fresh, stale, and future signed replies and the separate
signature, freshness, and content withholding checks. See the
[interop fixture guide](../test/interop/README.md#signed-timestamp-freshness-echo-fixtures)
for provenance, the quote-style control, and verification commands.

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
| Checked-in native race operations and signed-wire byte comparison | [Native race payload corpus](https://github.com/stanimirivanov/xk6-soap/issues/153) |
| WSS4J provisioning retry and failure evidence | [Bounded Maven outage retry](https://github.com/stanimirivanov/xk6-soap/pull/105) |
| Stable aggregate, hosted timing and cancellation evidence, and active enforcement | [Required CI rollout](https://github.com/stanimirivanov/xk6-soap/pull/107) · [Activation runbook](ci-activation.md) |
