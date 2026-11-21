# v0.1.0 candidate release notes

First candidate for SOAP 1.1 and 1.2 in a custom k6 build.

- Build raw XML or ordered object payloads using the named Client. Use k6 HTTP
  for transport and inspect SOAP faults and Body-scoped XPath results.
- Send UsernameToken Digest or Text and Timestamp. Sign or verify selected
  SOAP profiles with RSA or ECDSA SHA-2 and exact X.509 trust pins.
- Protect Body content, an operation element, or selected headers using
  AES-GCM and RSA-OAEP in either supported signature/encryption order.
- Track SOAP failure, build and parse timings, and parse counts alongside
  native HTTP metrics.

The initial build row uses Go 1.27.4, k6 v2.4.0 and xk6 v1.5.1 on Linux amd64.
Interop evidence covers the pinned Apache profiles. JMeter parity and the
dedicated nightly performance comparison remain unverified. Legacy
cryptography and hosted extension availability are outside this candidate's
support claims. [Supported contracts](docs/contracts.md) ·
[Release checklist](docs/release.md)
