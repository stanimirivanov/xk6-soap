# xk6-soap

A Go extension for building and inspecting SOAP 1.1 and 1.2 messages in k6.
It supports raw XML and deterministic object payloads, SOAP faults, Body-scoped
XPath, UsernameToken and Timestamp, and bounded WS-Security signing, verification
and encryption. Use `k6/http` to send the generated request and retain native HTTP,
TLS and timing behavior. [Supported contracts and evidence](docs/contracts.md)

## Run an example

Build the pinned custom binary from the repository root:

```sh
make build-k6
SOAP_URL="$SERVICE_URL" bin/k6 run examples/plain.js
SOAP_URL="$SERVICE_URL" bin/k6 run examples/object.js
```

Set `SERVICE_URL` to a SOAP 1.2 endpoint that accepts an `Echo` operation in
`urn:example` with action `urn:echo`. The object example also expects the
response to echo the two `item` elements in order. The scripts send one request
and enforce both the application checks and the `soap_req_failed` threshold.
Run `make e2e` to execute these same files with a loopback fixture, including
an HTTP 200 SOAP Fault that must fail the threshold.

The [signed example](examples/signed.js) sends the Apache fixture's SOAP 1.2
`echo` operation and requires a verified response signature and Timestamp.
Run `make interop` to execute it with the fixture's synthetic identities. For a
matching service, supply real paths and a service URL:

```sh
SOAP_URL="$SERVICE_URL" SOAP_SIGN_CERT="$CLIENT_CERT" SOAP_SIGN_KEY="$CLIENT_KEY" \
  SOAP_TRUST_CERT="$PEER_LEAF_CERT" bin/k6 run examples/signed.js
```

Use absolute PEM paths for the environment variables and configure the peer to
trust the client signing certificate. The response pin is the peer's exact
signing leaf. Send generated signed XML unchanged. For another SOAP operation,
adapt the operation name, payload, namespace, action and receive policy to that
service. [Client API](docs/plain-api.md) · [Key formats](docs/keys.md) ·
[Security policy](docs/security-policy.md) · [Metrics](docs/metrics.md)

## Evidence and migration

- [Supported profiles and limitations](docs/contracts.md) links each capability to executable evidence.
- [Apache fixture and matrix](test/interop/README.md) describes the pinned, independent WSS4J exchanges.
- [Performance and retention report](test/perf/README.md) records the runner, workload and frozen limits.
- [JMeter migration mapping](docs/jmeter-map.md) maps protocol settings. JMeter parity is unverified.
- [Architecture](docs/architecture.md), [decision index](docs/adr/README.md) and [M01 plan](tasks/plan.md) describe ownership, architectural proof and remaining work.

## Development

Requires Git, Make, the pinned Go toolchain and a C compiler for the race
detector. Initial dependency downloads and vulnerability checks require network
access. The interop gate requires Docker and GNU `timeout`.

```sh
make verify
make smoke e2e
make vuln
make interop
make hooks
```

Hooks are opt-in. Once installed they run verification before commit and the
uncached Apache fixture before push. [Harness](HARNESS.md) · [Go pin](.go-version) ·
[k6 and dependency pins](go.mod) · [Tool pins](Makefile) · [Apache-2.0 license](LICENSE)
