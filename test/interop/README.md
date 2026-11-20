# Independent Apache fixture

`make interop` builds and starts a real Apache CXF/WSS4J service, then runs the
Go self-tests over HTTP. Docker, GNU `timeout`, Make and the pinned Go toolchain
are required. The Go tests use the internal security adapter as the client; Apache independently
owns token authentication, timestamp validation, BSP enforcement and replay checks.

## Pins

| Component | Pin |
| --- | --- |
| CXF | 4.2.4 |
| WSS4J | 4.0.3 for the complete runtime artifact family; explicit overrides of the CXF BOM |
| Jetty | 12.1.13, selected by the CXF BOM |
| Maven | 3.9.16 inside the pinned base |
| Temurin JDK | 26.0.2.1 inside the pinned base; compiler release remains 21 |
| Base image | `maven:3.9-eclipse-temurin-26@sha256:b2c1ad85954592f9928e84327c65201f308ad9b5d8ed7d5b823717c97bf23fbb` |

The image digest is immutable, even though its human-readable tag moves. Both
build and runtime stages use it. Compiler/resources/JAR/dependency/Enforcer plugins are
pinned in pom.xml. Runtime transitive dependencies follow the CXF BOM except for
the explicitly aligned WSS4J family. Builds
need Maven Central on a cold cache; there are no snapshot dependencies. This is
a test fixture, not a production deployment or a Java/container vulnerability
audit. The repository's govulncheck gates cover Go source/binaries only.

## WSS4J alignment gate

[Issue #27](https://github.com/stanimirivanov/xk6-soap/issues/27) reproduces the
failure introduced by the DOM-only upgrade in PR #20: the image packaged DOM
4.0.3 alongside common, bindings, policy and both StAX modules at 4.0.2.
DOM 4.0.3 called `DateUtil.getTimestampReplayExpiry(Instant, Instant, int)`, absent
from the loaded common 4.0.2, causing NoSuchMethodError and HTML 500s across the
security tests. Successful WSDL readiness did not exercise that path.

Local dependencyManagement entries now override all six WSS4J runtime modules
through the same `wss4j.version` property. Importing the CXF BOM alone or changing
only DOM's version does not align its managed siblings. Maven Enforcer 3.7.0 runs
in `validate`: transitive `org.apache.wss4j:*` dependencies are banned except for
the exact `[${wss4j.version}]` release. The brackets are significant; an unbounded
version expression would not enforce the selected release exactly. See
[Apache's rule documentation](https://maven.apache.org/enforcer/enforcer-rules/bannedDependencies.html).

The normal `make interop` Docker build runs this check before compilation and
packaging. It first rejected the original mixed graph; a deliberate common-only
4.0.2 downgrade also failed with BannedDependencies before starting a server.
The exact aligned POM was restored afterward. The full independent UsernameToken,
signature and both-order/AES/SOAP encryption matrix then passed on the aligned
4.0.3 graph. This is a WSS4J family check, not a general Java dependency audit.

The readiness banner reports package manifest versions for CXF, WSS4J DOM and
common instead of a hard-coded release. Keep the WSS4J property and full family
alignment together during future Dependabot upgrades. The pre-signing namespace
correction was rechecked against 4.0.3 source and remains necessary; no coverage,
BSP, replay or algorithm policy was relaxed by this fix.

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
and the pinned WSS4J UsernameTokenProcessor source (4.0.3 source JAR on Maven Central).

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
canonical-byte artifacts and [ADR-0003](../../docs/adr/0003-encryption-kernel.md) for the encryption decision. Independent
integration tests require the full runner so that endpoint readiness and trust
material are available; missing fixture inputs are failures, not skipped tests.

## Encryption kernel gate

`/ste12811`, `/ste25611`, `/ets12811`, `/ets25611` and corresponding `12`
endpoints exercise both orders/AES sizes for SOAP 1.1/1.2. Apache requires
Timestamp+Signature+Encryption and Body/Timestamp signature coverage, decrypts
with its own server key, and signs/encrypts responses to fixture-client. `ste`
signs then encrypts; `ets` encrypts then signs Body, Timestamp and EncryptedKey.
OAEP uses the XML Encryption 1.1 URI with explicit SHA-256 digest/MGF1-SHA256.
Go enforces the exact receive order, graph and algorithm/coverage profile.

`NamespaceStableSignature` materializes the OAEP parameter namespaces before
Apache signs its EncryptedKey. This fixes a pinned WSS4J namespace-incomplete DOM
whose signature changed on SOAP serialization; it relaxes no validation or
coverage. ADR-0003 records the three-canonicalizer diagnosis and scope.

The matrix checks decrypted protected application content, absence of clear Body
values, altered request tag rejection by Apache, and Go rejection of altered
response tags/MGF, partial Body and the opposite receive order. All HTTP reads
in signature/encryption tests are capped at 4 MiB, matching the kernel limits.

## Public UsernameToken/Timestamp exchanges (CP-T1)

`make interop` builds the custom k6 binary and runs `username.js` through the
same bounded subprocess runner as plain E2E. The script uses public Client.build,
k6/http and Client.parse for Digest/Text × SOAP 1.1/1.2, replay, wrong credentials,
successful overrides/default restoration and parsed authentication faults.
`/ts11` and `/ts12` require only Timestamp and exercise standalone generation.
The child has a 25-second deadline, five-second HTTP timeouts, capped diagnostics
and a failing checks threshold; the suite retains its 90-second deadline.

The selected UT profile requires nonce and Created for both password forms.
`FreshUsernameToken` adds only those presence checks before delegating to Apache's
normal validator. This was needed because default WSS4J accepts PasswordText
without Created. Independent negative requests isolate missing/stale token Created
from a fresh envelope Timestamp; all earlier expiry/replay/credential controls stay.
No password hashing, replay cache or freshness arithmetic is implemented in Java
fixture glue. Sending credentials confers no response-authenticity flag.

[CP-T1 evidence](../../docs/username-token.md) records the fixed vector and scope.
JMeter capture/migration parity remains unverified; no capture was supplied.
