# Glossary

## SOAP exchange

**SOAP exchange** — A prepared SOAP request and a parsed SOAP response. The
k6 script owns sending the request over HTTP, including TLS and any retries.

**Envelope** — The SOAP XML document that contains a required Body and an
optional Header. Its namespace identifies the SOAP version.

**Body** — The direct SOAP Envelope child that carries the application payload
or a SOAP Fault. The response API exposes the accepted Body's inner XML.

**Operation** — The application action represented by the request payload's
root element. Its XML identity consists of a namespace and local name.

**Action** — The message's dispatch value, carried by the SOAP version's
HTTP binding and by WS-Addressing when enabled. It can differ from the
operation's local name.

**Header block** — A direct child of the SOAP Header, identified on the wire
by its namespace and local name. An outbound header selector is a local
configuration label used to choose a block for signing or encryption.

**SOAP Fault** — The structured error carried by a SOAP Body. Its presence
can make the SOAP outcome fail even when HTTP and message verification succeed.

## Message protection

**Security policy** — The configured rules for outbound message protection
and inbound response acceptance. The [security policy reference](docs/security-policy.md)
defines defaults and supported combinations.

**UsernameToken** — A WS-Security header token that carries a username and
password credentials in PasswordText or PasswordDigest form.

**Timestamp** — A WS-Security header block carrying creation and expiry
times. **Freshness** is acceptance of those times under the configured
age and clock-skew limits. A fresh response can be parsed more than once.

**Signature coverage** — The XML elements authenticated by a message
signature. Required coverage applies to the actual Body and any other
required elements, including a present Timestamp under signature verification.

**Protection order** — The sequence of signing and encryption within one
message. The outbound order and the order expected on encrypted responses
are configured separately.

## Key roles

**Signing identity** — The local private key and matching certificate used
to sign outbound messages.

**Encryption recipient** — The peer certificate whose public key protects
the outbound content encryption key.

**Decryption identity** — The local private key and matching certificate
used to recover an inbound content encryption key.

**Trust pin** — An explicitly configured peer leaf certificate, matched
using its exact DER encoding, that can authenticate an inbound signature.
Message trust and HTTP TLS trust are configured independently.

**X.509 key identifier** — Data in a message used to identify a certificate.
For response signature verification, it must identify one configured
trust pin.

## Response and evidence

**Response acceptance** — The decision to release response content after
the SOAP structure and configured receive checks pass. Acceptance can occur
under an unsigned policy.

**Accepted response content** — The Body contents available after acceptance,
including any SOAP Fault details and the XML available to Body-scoped XPath.

**SOAP outcome** — The parsed response's overall success or failure, reported
by `ok`. Success requires accepted content, a successful HTTP status, and
the absence of a SOAP Fault.

**Independent interoperability evidence** — An exchange in which a separate
WS-Security implementation generates or verifies the wire message. The
[WSS4J matrix](test/interop/matrix.json) records the combinations covered
by that evidence.
