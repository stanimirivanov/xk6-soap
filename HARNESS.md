# Coding and architectural harness

This repository uses ordinary Go tooling as its mechanical controls. Agent instructions
are a short navigation aid. They neither make a model deterministic nor replace review.
The goal is deterministic checks for specified properties, with explicit limits.

## Map and ownership

```text
AGENTS.md                    task loop and root adapter constraints
internal/AGENTS.md           internal-layer and security constraints
internal/archtest/           tested AST import/layer sensors, including tagged source
soap.go, client.go           named module, lifecycle and plain Client bindings
internal/message/           bounded SOAP validation, faults and isolated XPath
internal/keys/              byte-based key validation, private material and bounded cache
keys.go, test/keys.js        constructor key decoding and actual k6 key-input probe
security.go, internal/wssec/policy.go  strict policy decoding and typed validation
diagnostics.go, test/security.js      metadata-only diagnostics and capability gate
credentials.go, internal/wssec/username.go  per-build overrides and outbound UT/Timestamp
internal/wssec/signing.go            single-tree outbound core RSA signing
internal/wssec/receive.go            exact-coverage receive acceptance and trust
internal/wssec/timestamp.go          required signed Timestamp freshness
test/interop/{username,signing,receive,timestamp}.js  public k6-to-Apache security exchanges
test/AGENTS.md              runtime/interop fixture rules
test/smoke.js               actual custom-k6 positive and negative runtime probe
test/fixture/              bounded synthetic SOAP HTTP server and capture
test/e2e/                  bounded subprocess runner and raw SOAP k6 script
Makefile, .go-version        canonical commands and exact tool versions
scripts/                    smoke runner and non-destructive hook installer
.githooks/pre-commit         local fast delivery checks (opt-in)
.github/workflows/ci.yml     same gates on every PR/main push
.github/dependabot.yml       Go dependency and action update proposals
.github/pull_request_template.md  concise evidence at handoff
```

The root JS adapter may depend on message, keys, clock and wssec. wssec may depend on
message/keys/clock. The other three are independent foundations. Missing runtime packages remain uncreated until a feature needs their boundary. `internal/archtest/rules.go` is the executable
source for allowed first-party edges; new packages fail closed until reviewed there.

| State/resource | Owner | Constraint/evidence |
| --- | --- | --- |
| Sobek values and module bindings | Per-VU root instance | Runtime isolation/lifecycle tests; internal imports forbidden |
| XML/message state | Per request/response | Never shared; exact covered-Body projection and hostile security tests |
| Decoded key cache | RootModule-owned immutable material | 256 entries/32 MiB encoded input; concrete-key and cross-VU race tests |
| HTTP, TLS, cookies, HTTP metrics | k6/http in script | Production direct transport imports forbidden |
| Fixture servers/files | test directory | Exempt from production import rules, never imported into runtime |
| Harness AST/filesystem operations | internal/archtest | Runtime imports of harness forbidden |

## Guides and sensors

Root/scoped AGENTS.md files use native directory discovery. No duplicated Cursor/Copilot
rule catalogs, model/version prompts, prompt-length quotas, forced chain-of-thought,
mandatory multi-agent loops, or custom agent supervisor. These add no demonstrated
control here. Add a guide after a real failure; prefer an executable regression when
possible. Remove guidance that duplicates an effective check.

| Command | Sensor and failure meaning | Where |
| --- | --- | --- |
| `make fmt` | Explicit formatting mutation | Developer command only |
| `make lint` | Declaration style, gofmt, go vet, Staticcheck, Actionlint, shell syntax | Local/CI |
| `make arch` | First-party AST architecture and sensor negative tests | Local/CI |
| `make test` | Go race tests; Go compilation is the type checker | Local/CI |
| `make deps` | Non-mutating module tidy diff and downloaded-module checksum verification | Local/CI |
| `make test-hooks` | Existing-hook preservation, snapshot refusal, check-failure propagation | Local/CI |
| `make build` | All module packages compile | Local/CI |
| `make verify` | All of the preceding non-mutating checks | Pre-commit/CI quality |
| `make smoke` | Pinned xk6 builds a binary; valid runtime succeeds and forced failed check exits 99 | CI runtime |
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
generation. It excludes tests and test fixtures intentionally. Its unit tests inject
violations; the repository test runs the same checker over real files. Format/compiler
errors and sensor diagnostics identify a file/rule and corrective direction.

## Plan, execute, verify

For each issue, name affected boundaries and select focused tests. Add the failing case,
make the change, and read the actual diagnostic before correcting it. Before delivery,
run `make verify` and affected runtime/security checks, inspect the diff, and put exact
commands/outcomes in the PR. Never automatically retry a flaky failure until it passes.
Do not rerun unchanged successful expensive checks for reassurance. CI rechecks the
committed snapshot independently.

`make hooks` is opt-in and refuses existing hooksPath/pre-commit configuration. The hook
never stashes/resets edits: it refuses unstaged/untracked changes so verification is not
silently performed against a different snapshot than the commit. Hooks are bypassable;
CI plus server-side required checks are the merge boundary. The hook does not install tools
unless the invoked Make target needs a missing/outdated pinned tool.

## CI integration and server-side enforcement

CI has fixed `quality`, `runtime`, and `vulnerabilities` jobs with timeouts, read-only
permissions, immutable action references and no repository secrets. It runs on every PR,
main push and manual dispatch; no path filters hide a required check. Dependency tidy uses `-diff` and must leave go.mod/go.sum unchanged. No auto-merge, release, recurring agent or CI poller.

**Main was unprotected when bootstrapped.** After this PR lands, a repository administrator
must require these three checks and pull requests, block force pushes/deletion and apply
rules to administrators as appropriate. This repository configuration alone cannot
prevent an administrator changing CI or its branch rules. Review changes to gates and
pins as changes to the quality contract, not routine suppressions. The setup is not
claimed to be a remotely enforced merge policy until that setting is activated.

For example, in GitHub Settings → Rules → Rulesets, target `main`, require pull requests
and status checks `quality`, `runtime`, `vulnerabilities` from GitHub Actions, require
branches up to date, and block force pushes/deletion. Choose review counts consistent
with the maintainer team; do not lock a sole maintainer out with a self-approval requirement.
No server setting is silently changed by local bootstrap.

## Progressive hardening

| Stage/trigger | Add mechanical evidence | Remains reviewed |
| --- | --- | --- |
| Now: scaffold | Format/vet/static analysis, architecture negative tests, race/lifecycle tests, actual binary smoke and audit | Scope, API semantics, rule changes |
| Plain SOAP task | Table/fuzz seeds for limits, namespaces, faults, payloads; real HTTP fixture | Schema/mapping decisions |
| Key/cache task (implemented) | Password/role/certificate negatives, concurrent cache hits, real capacity and k6 byte-input tests | Secret lifecycle and future security policy |
| Kernel feasibility | Independent WSS4J both-direction/order gate before crypto integration | Candidate selection and residual risk |
| Secured receive task | Wrapping/coverage/downgrade tests; bounded post-decrypt parsing and secret-output negatives | Security model and independent review |
| Stable functionality | Frozen benchmark runner/budgets; bounded fuzz jobs and heap/goroutine checks | Changes to budgets and release scope |

Do not add fake `interop`, performance or coverage targets now. No arbitrary coverage
percentage or file-size quota substitutes for meaningful assertions. Add measured budgets
when there is a workload and baseline. Tool pins in Makefile/.go-version require an
intentional refresh and all gates; Dependabot covers Go module/action pins only.

## Rationale and sources

- [Birgitta Böckeler on martinfowler.com](https://martinfowler.com/articles/harness-engineering.html)
  distinguishes feedforward guides from feedback sensors and computational checks from
  inferential judgment. We use that distinction, not a claim that tests prove intent.
- [OpenAI's harness engineering report](https://openai.com/index/harness-engineering/)
  motivates a short repository map and mechanical boundary enforcement. Its autonomous
  workflow choices are not requirements for this repository.
- [Mitchell Hashimoto's account](https://mitchellh.com/writing/my-ai-adoption-journey)
  motivates improving the environment in response to observed failures; this is not a
  reason to keep an agent running or to add an orchestration layer here.
- [Native AGENTS.md guidance](https://developers.openai.com/codex/guides/agents-md/)
  supplies directory-scoped instructions. No model-specific compatibility shim is needed.

## Bootstrap dependency evidence

The initial k6 v2.3.0 graph failed audit. Explicit minimum selections now use x/net
v0.62.0, x/crypto v0.59.0, brotli v1.2.7 and compress v1.20.2 (with their required
transitive updates). Both source and rebuilt-binary govulncheck scans passed on
18 November 2026. These overrides are maintained until the selected k6 version
includes equivalent or newer fixes. Revalidate them on upgrades; do not remove them
merely because source-only analysis passes. Relevant advisory evidence:
[x/net](https://pkg.go.dev/vuln/GO-2026-6866),
[x/crypto](https://pkg.go.dev/vuln/GO-2026-5932),
[brotli](https://pkg.go.dev/vuln/GO-2026-6888), and
[compress](https://pkg.go.dev/vuln/GO-2026-6865).

## Declaration style

Go struct fields and var/const declarations use one name per declaration line.
The AST declaration-style sensor runs in `make lint`, including test, fixture and
build-tagged Go files. It rejects grouped names and semicolon-packed declarations
with a file/line diagnostic. Function signatures and multi-value assignments use
ordinary Go syntax. This rule does not inspect declaration-like text inside strings
or comments.
