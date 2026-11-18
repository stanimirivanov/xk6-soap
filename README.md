# xk6-soap

A Go extension for SOAP and WS-Security in k6. **Current status: module scaffold only.**
`Client` is registered; configuration, `build()` and `parse()` intentionally reject with
`SOAP_NOT_IMPLEMENTED`. No SOAP, cryptography or interoperability support is claimed.

## Development

Requires Git, Make, a Go installation capable of downloading the pinned toolchain,
a C compiler for Go's race detector, and network access for initial dependencies/audits.
Linux is the initial CI host; commands also target POSIX developer environments.

```sh
make tools
make verify
make smoke e2e vuln
make hooks  # optional; refuses to overwrite an existing hook setup
```

[HARNESS.md](HARNESS.md) maps files, commands, ownership, CI enforcement and the hardening
roadmap. Go is pinned in [.go-version](.go-version), k6 in [go.mod](go.mod), and tools in
[Makefile](Makefile). `make` uses that exact Go toolchain, without a floating `latest`.

The proposed [architecture and M01 plan](https://github.com/stanimirivanov/xk6-soap/pull/2)
remain under review. This scaffold implements the foundation authorized in
[issue #3](https://github.com/stanimirivanov/xk6-soap/issues/3); it does not merge or approve
all proposed API defaults. License: [Apache-2.0](LICENSE).

## Local SOAP E2E harness

`make e2e` builds the pinned custom k6 binary and runs race-enabled tests against
an in-process loopback fixture. The script sends synthetic raw SOAP 1.1/1.2
messages with k6/http; extension build/parse behavior is introduced in later tasks.
Both successful execution and an intentional failed-check threshold (exit 99)
are required to pass the harness.

Fixture endpoints are `/echo`, `/fault11`, `/fault12`, `/empty`, `/binary`,
`/delay` (250 ms) and `/disconnect` (close before HTTP response). Request capture
is memory-only, limited to 128 requests of at most 64 KiB each, with copied headers.
The fixture is test-only and is not an independent WS-Security implementation.

Focused commands after a binary has been built:

```sh
GOTOOLCHAIN=go1.27.4 go test -race ./test/fixture ./test/e2e
GOTOOLCHAIN=go1.27.4 go test -race -tags=e2e ./test/e2e -run TestK6SOAPFixture -count=1 -timeout=60s
```

The server binds an ephemeral loopback listener before returning; no polling is
needed for readiness. Test cleanup closes its connections/listener. The runner
waits/reaps each child, caps diagnostics at 32 KiB, and enforces a 30-second maximum
per process (15 seconds in the HTTP cases), plus a one-second pipe cleanup bound.
No temporary script or server process is created. Expected transport warnings for
`/delay` and `/disconnect` are asserted as k6 status 0, not ignored failures.
