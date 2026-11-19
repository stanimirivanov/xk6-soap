# xk6-soap

A Go extension for SOAP and WS-Security in k6. Raw SOAP 1.1/1.2 build/parse,
fault extraction and Body-scoped XPath are available. See the [plain Client API](docs/plain-api.md).
Security/key support and object payload mapping are planned follow-up tasks.

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

The [architecture](docs/architecture.md) and [M01 plan](tasks/plan.md) describe the
full target; the plain API documentation distinguishes implemented features from
planned security and payload capabilities. License: [Apache-2.0](LICENSE).

## Local SOAP E2E harness

`make e2e` builds the pinned custom k6 binary and runs race-enabled tests against
an in-process loopback fixture. The script sends synthetic raw SOAP 1.1/1.2
messages with k6/http; the public build/parse API is exercised against those responses.
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

The internal [plain message boundary](docs/message-boundary.md) now provides bounded
SOAP structure validation and raw-envelope generation for the upcoming JS bindings.
The public Client bindings use this boundary before response inspection.

## Independent Apache fixture

`make interop` runs the pinned CXF/WSS4J container and independent HTTP self-tests
for UsernameToken Digest/Text, timestamps, replay rejection and SOAP faults. See
[test/interop/README.md](test/interop/README.md) for pins, synthetic identities,
policy settings, Docker requirements and cleanup guarantees.

The internal [signature kernel gate](docs/adr/0002-signature-kernel.md) now proves
RSA Body/Timestamp signing and exact coverage against independent Apache endpoints.
This does not enable public Client signing; encryption/order gating remains PR-7.

Key loading and cache ownership are documented in [Key material and cache](docs/keys.md).
Keys can be validated at construction; public security policy/message crypto remains planned.
