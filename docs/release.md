# Compatibility and release rehearsal

## Supported build matrix

| Go | k6 | xk6 | Platform | Runtime evidence |
| --- | --- | --- | --- | --- |
| 1.27.4 | v2.4.0 | v1.5.1 | Linux amd64 | Build identity, native smoke and race-enabled E2E |

The initial matrix has one supported combination. k6 v2.3.0 does not compile
against the current Sobek pin. Replacing Sobek with the version used by
k6 v2.3.0 leaves the extension's object mapper without `Object.GetIdx`.
Go 1.27.4 is the module's declared minimum. Add another row only after it
passes the same gates. [.github/workflows/ci.yml](../.github/workflows/ci.yml)

Run from a checkout of the exact candidate commit with Go, Make, Python 3.11
or newer and a C compiler for race-enabled tests:

```sh
make compatibility
bin/k6 version
```

Make installs the pinned xk6 and uses [.go-version](../.go-version) and
[go.mod](../go.mod). The resulting binary contains `k6/x/soap`. The runtime job
checks the linked k6 module and actual Go version before running examples.
Pin the source commit, toolchain and k6 version for repeat builds. xk6 records
the local replacement's absolute path in Go build information. For matching
rehearsal hashes use the same absolute checkout path and target platform.

## Dry run

From a clean checkout on Linux amd64:

```sh
make release-dry-run
(cd bin/release-dry-run && sha256sum --check SHA256SUMS)
```

Choose an unused path with `RELEASE_OUTPUT=bin/release-dry-run-again` to keep a
previous run. The rehearsal makes two builds with trimmed paths, CGO disabled
and a fixed amd64 target. It checks build information and exact binary bytes,
runs source and binary govulncheck, and validates the archive member list,
contents, permissions and SHA-256. The archive contains the executable,
candidate notes, source commit, build metadata and linked dependency notices.
The GitHub workflow has read-only repository permissions and stores JSON and
checksums as short-lived run artifacts. The binary archive stays in the build
workspace. [Release dry-run workflow](../.github/workflows/release-dry-run.yml)

## Release checklist

- [ ] Choose the exact reviewed main commit and confirm all compatibility rows,
  `make verify`, the independent `make interop` suite and the dry run.
- [ ] Confirm the required source and custom binary govulncheck gate is green.
  Keep `vulnerabilities` as a required status check in the main ruleset where
  merge enforcement is configured. The release rehearsal also requires both
  scans to pass before staging artifacts.
- [ ] Review [v0.1.0 candidate notes](../RELEASE_NOTES.md), archive metadata and
  checksums. Review [third-party notices](../THIRD_PARTY_NOTICES.md), including
  linked modules without root notice files and corresponding source for any
  distributed custom k6 binary.
- [ ] Record outstanding claims from the [evidence report](contracts.md).
  Dedicated-runner performance and JMeter migration evidence remain pending.
- [ ] Obtain separate release authorization before creating a tag, publishing
  artifacts or making a registry submission.

## Dependency updates

Dependabot proposes updates to Go modules, GitHub Actions, the Maven fixture
and its Docker base. Review scope, dependency changes and runtime impact. A
Go or k6 update needs the compatibility, race and vulnerability checks.
A Go, k6 or crypto-provider update also needs a review of the performance runner
and frozen baseline. Keep provider API and interoperability evidence current.
Update WSS4J as an aligned family and run the uncached Apache gate for fixture
changes. Review registry compatibility and notices when dependency pins move.
[Dependabot configuration](../.github/dependabot.yml) · [Interop fixture](../test/interop/README.md) ·
[Performance protocol](../test/perf/README.md)

## Registry and hosted execution

For a community registry submission, check the public README, supported k6
versions, examples, OSS license, `xk6` repository topic, a versioned release and
the policy for recent k6 builds. Prepare the community entry using the registry's
current contribution format. Acceptance and managed execution depend on Grafana's
review and supported-extension catalog. [Registry requirements](https://grafana.com/docs/k6/latest/extensions/create/extensions-registry/) ·
[Submission procedure](https://grafana.com/docs/k6/latest/extensions/submit-extension/) ·
[Registry source](https://github.com/grafana/k6-extension-registry)

Use the custom binary on a generator you control. Grafana Cloud k6 provisions
extensions from its supported catalog. Validate availability for the chosen
managed execution mode before migrating a script. [Grafana Cloud extension support](https://grafana.com/docs/grafana-cloud/observe-and-act/testing/k6/author-run/use-k6-extensions/)
