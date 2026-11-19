# Independent Apache fixture

`make interop` builds and starts a real Apache CXF/WSS4J service, then runs the
Go self-tests over HTTP. Docker, GNU `timeout`, Make and the pinned Go toolchain
are required. The Go extension/provider is not imported by these tests. Apache
owns token authentication, timestamp validation, BSP enforcement and replay checks.

## Pins

| Component | Pin |
| --- | --- |
| CXF | 4.2.4 |
| WSS4J | 4.0.2, matching CXF's dependency management |
| Jetty | 12.1.13, selected by the CXF BOM |
| Maven | 3.9.16 inside the pinned base |
| Temurin JDK | 21.0.12.1 inside the pinned base |
| Base image | `maven:3.9-eclipse-temurin-21@sha256:99e61abcff91a9b1333463bd8451fb18495d6eba9250ac66a338b518f8278320` |

The image digest is immutable, even though its human-readable tag moves. Both
build and runtime stages use it. Compiler/resources/JAR/dependency plugins are
pinned in pom.xml; runtime transitive dependencies follow the CXF BOM. Builds
need Maven Central on a cold cache; there are no snapshot dependencies. This is
a test fixture, not a production deployment or a Java/container vulnerability
audit. The repository's govulncheck gates cover Go source/binaries only.

## Service and policy

- `/ut11`: SOAP 1.1; `/ut12`: SOAP 1.2. Both provide `echo` in namespace
  `urn:xk6-soap:fixture`, action `urn:echo`. Responses are plain SOAP.
- Both require the WSS4J actions `Timestamp UsernameToken`, BSP compliance,
  strict timestamp expiry, and Expires. Timestamp and UsernameToken lifetime
  limits are 300 seconds, with 60 seconds of future clock tolerance.
- Digest and Text tokens are accepted for the synthetic identity
  `fixture-user` / `fixture-password`. Text tokens in this profile also carry
  Nonce and Created. These constants are public test data, never production credentials.
- CXF nonce replay caching is explicitly enabled with an endpoint-owned WSS4J
  MemoryReplayCache. Nonces are retained by Apache's TTL behavior and the cache
  is discarded with the container. The tests are sequential; they do not claim
  distributed replay protection or atomic concurrent replay exclusion.
- Echoing the value `fault` invokes a synthetic service fault after authentication.
  Authentication/policy errors also return SOAP faults. No payload logging
  interceptors are installed. Only bounded server logs are shown on failure.

The HTTP self-tests hand-assemble the OASIS PasswordDigest formula using Go's
stdlib SHA-1, raw nonce bytes and the exact serialized Created string. They test
both SOAP versions and password types: valid reference messages, exact replay,
wrong passwords/digests, stale/future timestamps/tokens, stale Timestamp with a
fresh UsernameToken, nonce-cache poisoning resistance, unknown users, missing Timestamp/UsernameToken/Expires,
missing security and
plain service faults. Responses must have the requested SOAP Envelope/Body
namespace and the expected success content or Fault. No k6 `Client.build()` or
provider self-round-trip can substitute for this test.

Fresh CSPRNG nonces and current UTC timestamps prevent cross-test cache collisions;
negative times are ten minutes away from the acceptance window, not exact timing
boundaries. Clocks must be synchronized between host and container. This is
independent interoperability evidence for these profiles only, not general
WSS4J/WCF/JMeter compatibility or signature/encryption evidence.

## Keys and containment

The Docker build runs `wss4j/generate-keys.sh` into a fresh directory. It creates
an RSA-2048/SHA256withRSA PKCS#12 identity and public PEM certificate:

- alias `fixture-server`
- subject `CN=xk6-soap-test-only,OU=Synthetic Fixture`
- public test store/key password `fixture-only`
- runtime files `/fixture/test-keys/server.p12`, `server.pem`, `identity.txt`

`identity.txt` records that build's certificate fingerprint; the exact random key,
serial and certificate bytes are intentionally not source-controlled or fixed.
The server key is used by the signature endpoints. It is not used by UsernameToken
endpoints. Encryption remains a future fixture task. Never use them as production trust.
The generator refuses an existing destination and does not overwrite key material.

The runner publishes port 8080 on an ephemeral host **loopback** port. It runs as
UID/GID 10001 with a read-only root, a bounded /tmp, no Linux capabilities,
no-new-privileges, and finite memory/CPU/PID budgets. Readiness probes both WSDL
endpoints with one 30-second deadline. Requests have five-second deadlines;
response reads are capped at 64 KiB. The test suite has a 90-second timeout and
Docker build/start/inspect/log/cleanup calls have separate deadlines.

The trap removes only the container recorded in the runner's private cidfile,
then its temporary files, on success, failure or interrupt. Cleanup failure is
reported as failure. Built images/layers remain as Docker build cache; the runner
does not prune other work. Runtime state and test keys are never copied into the
repository. `make interop` fails if Docker or the fixture is unavailable; it does
not skip or silently fall back to the Go mock.

CI runs the same target in the `interop` job on PRs and main pushes. Administrators
can add that check to the main ruleset after this PR lands. No branch setting is
changed by the fixture bootstrap.

Sources: [CXF WS-Security interceptors](https://cxf.apache.org/docs/ws-security.html),
[WSS4J configuration](https://ws.apache.org/wss4j/config.html),
[CXF 4.2.4 parent pins](https://repo.maven.apache.org/maven2/org/apache/cxf/cxf-parent/4.2.4/cxf-parent-4.2.4.pom),
and the pinned WSS4J UsernameTokenProcessor source (4.0.2 source JAR on Maven Central).

## Signature gate

`/sig11` and `/sig12` require Timestamp+Signature and exact Body/Timestamp coverage
through CXF's DefaultCryptoCoverageChecker. Responses are independently signed
with the generated fixture-server identity, RSA-SHA256, SHA-256 digests, BST direct
reference and Exclusive C14N/InclusiveNamespaces. The test suite asserts those
namespace parameters are present, verifies the response in Go and rejects tampering
and wrong trust.

The runner constructs a temporary build context and imports only
`internal/wssec/testdata/signing-cert.pem` as the trusted client public certificate
(alias fixture-client). Its deliberately public test private key stays outside
the image and is used only by the Go test driver. No production trust roots are
loaded. The runner copies the generated server public certificate into temporary
storage for explicit Go pinning, then removes it with other per-run files.

See [ADR-0002](../../docs/adr/0002-signature-kernel.md) for the gate outcome,
canonical-byte artifacts and remaining PR-7 encryption decision. Independent
integration tests require the full runner so that endpoint readiness and trust
material are available; missing fixture inputs are failures, not skipped tests.
