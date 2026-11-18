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
make smoke vuln
make hooks  # optional; refuses to overwrite an existing hook setup
```

[HARNESS.md](HARNESS.md) maps files, commands, ownership, CI enforcement and the hardening
roadmap. Go is pinned in [.go-version](.go-version), k6 in [go.mod](go.mod), and tools in
[Makefile](Makefile). `make` uses that exact Go toolchain, without a floating `latest`.

The proposed [architecture and M01 plan](https://github.com/stanimirivanov/xk6-soap/pull/2)
remain under review. This scaffold implements the foundation authorized in
[issue #3](https://github.com/stanimirivanov/xk6-soap/issues/3); it does not merge or approve
all proposed API defaults. License: [Apache-2.0](LICENSE).
