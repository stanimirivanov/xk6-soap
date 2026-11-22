# Repository map and verification

## Map and ownership

Paths in the map are relative to the repository root.

```text
AGENTS.md                    agent skill routing and runtime boundaries
internal/AGENTS.md           internal-layer and security constraints
harness/HARNESS.md           repository map and verification guidance
harness/archtest/            tested AST import/layer sensors, including tagged source
soap.go                      blank-import registration shim
internal/adapter/            named module, lifecycle and Client bindings
internal/adapter/object_payload.go           ordered per-VU Sobek capture, no payload map export
internal/message/object.go  bounded XML encoding for ordered object payloads
internal/adapter/metrics.go                  registry-owned metrics and cancellation-aware sampling
test/e2e/metrics.js          exact summary counts and HTTP-200 SOAP failure threshold
test/e2e/object.js           object envelopes through native k6 HTTP echo
internal/message/           bounded SOAP validation, faults and isolated XPath
internal/keys/              byte-based key validation, private material and bounded cache
internal/adapter/keys.go, test/keys.js        constructor key decoding and actual k6 key-input probe
internal/adapter/security.go, internal/wssec/policy.go  strict policy decoding and typed validation
internal/adapter/diagnostics.go, test/security.js      metadata-only diagnostics and capability gate
internal/adapter/credentials.go, internal/wssec/username.go  per-build overrides and outbound UT/Timestamp
internal/wssec/signing.go            single-tree outbound core RSA signing
internal/wssec/receive.go            exact-coverage receive acceptance and trust
internal/wssec/timestamp.go          required signed Timestamp freshness
test/interop/{username,signing,receive,timestamp}.js  public k6-to-Apache security exchanges
test/AGENTS.md              runtime/interop fixture rules
test/smoke.js               actual custom-k6 positive and negative runtime probe
test/fixture/              bounded synthetic SOAP HTTP server and capture
test/e2e/                  bounded subprocess runner and raw SOAP k6 script
test/perf/                 fixed workloads, frozen baseline and comparison runner
Makefile, .go-version        canonical commands and exact tool versions
scripts/                    smoke runner and non-destructive hook installer
.githooks/pre-commit         local quality checks (opt-in)
.githooks/pre-push           cold Docker/Maven interop for committed HEAD
.github/workflows/ci.yml     same gates on every PR/main push
.github/dependabot.yml       Go dependency and action update proposals
.github/pull_request_template.md  concise evidence at handoff
```

The root registration shim imports only `internal/adapter`. The adapter may depend on
message, keys, clock and wssec. wssec may depend on message/keys/clock. The other three
are independent foundations. Missing runtime packages remain uncreated until a feature
needs their boundary. New production packages fail closed until reviewed in the
[architecture checker](archtest/rules.go).

| State/resource | Owner | Constraint/evidence |
| --- | --- | --- |
| Sobek values and module bindings | Per-VU adapter instance | Runtime isolation/lifecycle tests; k6/Sobek imports confined to the adapter |
| XML/message state | Per request/response | Never shared; exact covered-Body projection and hostile security tests |
| Decoded key cache | Adapter RootModule-owned immutable material | 256 entries/32 MiB encoded input; concrete-key and cross-VU race tests |
| Extension metrics | Adapter RootModule references per k6 registry; per-call samples | Once-per-registry registration; fixed tag enums; cancellation tests |
| HTTP, TLS, cookies, HTTP metrics | k6/http in script | Production direct transport imports forbidden |
| Fixture servers/files | test directory | Exempt from production import rules, never imported into runtime |
| Harness AST/filesystem operations | harness/archtest | Runtime imports of harness forbidden |

## Verification commands

Run the commands in this table from the repository root.

| Command | Sensor and failure meaning | Where |
| --- | --- | --- |
| `make fmt` | Explicit formatting mutation | Developer command only |
| `make lint` | Declaration style, gofmt, go vet, Staticcheck, Actionlint, shell syntax | Local/CI |
| `make arch` | Architecture rules, diagnostic tests and documentation references in `harness/archtest` | Local/CI |
| `make test` | Go race tests; Go compilation is the type checker | Local/CI |
| `make deps` | Non-mutating module tidy diff and downloaded-module checksum verification | Local/CI |
| `make test-hooks` | Existing-hook preservation, snapshot refusal, check-failure propagation | Local/CI |
| `make build` | All module packages compile | Local/CI |
| `make perf-budget-test` | Budget comparison and committed baseline integrity | Local/CI |
| `make verify` | All of the preceding non-mutating checks | Pre-commit/CI quality |
| `make smoke` | Pinned xk6 builds a binary; valid runtime succeeds and forced failed check exits 99 | CI runtime |
| `make bench` | Frozen Go, native k6 and post-GC budgets on the pinned host | Dedicated nightly runner |
| `make fuzz-smoke` | Bounded Go fuzz runs for SOAP, security receive and JavaScript policy boundaries | Local and scheduled CI |
| `make interop` | Independent Docker CXF/WSS4J credentials, signature and encryption/order fixture | CI interop |
| `make e2e` | Real k6 HTTP fixture scenarios and exact exit-99 negative control | CI runtime |
| `make vuln` | govulncheck source and the actual custom k6 binary | CI vulnerabilities; online database |

Actionlint validates workflow structure/expressions; optional ambient ShellCheck/Pyflakes
executables are disabled so host installations do not change the gate. POSIX scripts
receive syntax and behavioral tests; this is not a full shell static-analysis claim.

Initial downloads need network; cached compilation/tests do not intentionally contact
external services. Vulnerability results depend on the current advisory database and
are not deterministic across dates. No tool claims to prove behavioral or security
correctness. The architecture checker examines direct first-party imports and source
syntax, not arbitrary transitive library behavior. Dependency review, compiled-binary
vulnerability scanning and independent interop address different risks.

The architecture sensor parses build-tagged Go files regardless of the host OS. It rejects
unknown production directories, reverse/lateral imports, runtime access from lower layers,
provider leakage, direct transport/filesystem/process/unsafe imports, linkname and implicit
generation. The production scan excludes test files, test fixtures and harness tooling.
Declaration-style checks also cover the Go files in the harness. Unit tests inject
violations and the repository test runs the same architecture checker over real files.
Format/compiler errors and sensor diagnostics identify a file/rule and corrective direction.

## Local hooks

`make hooks` is opt-in and refuses conflicting hooksPath or legacy pre-commit/pre-push configuration. The hook
never stashes/resets edits: it refuses unstaged/untracked changes so verification is not
silently performed against a different snapshot than the commit. Hooks are bypassable;
CI plus server-side required checks are the merge boundary. The hook does not install tools
unless the invoked Make target needs a missing/outdated pinned tool.

## CI and server-side enforcement

[CI](../.github/workflows/ci.yml) runs quality, compatibility, vulnerability and
independent interoperability checks. It uses pinned actions and read-only
repository permissions. The active `main` ruleset requires pull requests and
the GitHub Actions `vulnerabilities` check, and blocks deletion and non-fast-forward
updates. [Fuzzing](../.github/workflows/fuzz.yml), [performance](../.github/workflows/performance.yml)
and [release rehearsal](../.github/workflows/release-dry-run.yml) have their own
entry points. The [release checklist](../docs/release.md) records dependency policy
and release verification.

## Declaration style

Go struct fields and var/const declarations use one name per declaration line.
The AST declaration-style sensor runs in `make lint`, including test, fixture and
build-tagged Go files. It rejects grouped names and semicolon-packed declarations
with a file/line diagnostic. Function signatures and multi-value assignments use
ordinary Go syntax. This rule does not inspect declaration-like text inside strings
or comments.

## Cold delivery gate

The pre-push hook requires a clean committed HEAD matching every pushed commit
(annotated tags are resolved to commits). It runs `make interop` once before refs
are published; deletion-only pushes need no build. Interop always passes Docker
`--no-cache`, so cached Maven build layers cannot hide missing dependencies.
Docker, GNU timeout and network access are required for this local gate. Hook
regressions cover snapshot mismatch, dirty work, failure propagation and existing
hook preservation. Hooks remain opt-in/bypassable; CI remains required.

The local gate verifies the local network at push time. It cannot guarantee future
availability from GitHub's different network. The fixture bounds Maven validation
per endpoint and can fall back to Google's regional Central mirrors. The [interop fixture guide](../test/interop/README.md)
records the recovery policy and availability limits.


Run `make fuzz-smoke` for two seconds per target with two workers. The weekly
workflow runs the same targets for 15 seconds each under a ten-minute job
limit. Seed cases replay in the regular Go test suite. For a new finding,
replay the reported command and keep a minimal synthetic regression:

```sh
go test ./internal/wssec -run 'FuzzReceiveSecurity/<reported-id>'
```

The fuzz inputs and generated certificates are synthetic. Keep production
messages, credentials and keys out of the corpus.
