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
the local replacement's absolute path in Go build information. The release rehearsal converts that replacement to a relative path in its
packaged build recipe so it can compare rebuilds from different directories.

## Dry run

From a clean checkout on Linux amd64:

```sh
make release-dry-run
(cd bin/release-dry-run && sha256sum --check SHA256SUMS)
```

Choose an unused path with `RELEASE_OUTPUT=bin/release-dry-run-again` to keep a
previous run. The rehearsal captures xk6's generated entry point and exact Go
module graph. It builds the distributed executable from the corresponding
source archive twice, using separate extraction directories and empty module
caches. It compares binary bytes and checks the linked modules and build
settings against the initial xk6 build. It also runs source and binary
govulncheck and validates the archive contents, permissions and checksums.

The binary archive contains the executable, notes, notices, and metadata.
The source archive contains the exact extension Git snapshot, generated build
recipe and verified Go module sources in a file-based proxy. From a clean
extraction and with the pinned Go toolchain on `PATH`, run:

```sh
mkdir source
tar -xzf xk6-soap-v0.1.0.source.dry-run.tar.gz -C source
sh source/rebuild.sh ./k6-rebuilt
sha256sum ./k6-rebuilt
```

Compare the rebuilt SHA-256 with `binary_sha256` in `metadata.json`. The recipe
uses the bundled file proxy with the recorded module checksums. It needs no
network module fetches. When distributing the binary, make the matching source
archive available alongside it using the verified manifest and checksums.
The read-only rehearsal workflow retains only JSON and checksums as short-lived
run artifacts. [Release dry-run workflow](../.github/workflows/release-dry-run.yml)

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
