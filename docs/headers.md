# Custom headers and WS-Addressing

PR-16 enables per-build custom SOAP blocks and the WS-Addressing 2005/08 subset
for SOAP 1.1 and 1.2. HTTP remains owned by k6.

```js
const request = client.build('Echo', '<Echo/>', {
  headers: [{name:'trace', xml:'<t:Trace xmlns:t="urn:trace">request-1</t:Trace>'}],
  addressing: {
    action:'urn:echo',
    to:'https://example.test/service', // Exactly client.url, without normalization.
    messageId:'urn:uuid:unique-per-request',
    replyTo:'http://www.w3.org/2005/08/addressing/anonymous',
  },
});
```

Header records contain only `name` and `xml`, both primitive strings. There are
at most 16 custom blocks; each is one standalone namespace-qualified element.
Selectors are unique NCNames, and expanded names cannot repeat. XML budgets
apply to each block and the entire envelope. Envelope/security structures and
injected IDs are rejected throughout custom blocks. SOAP metadata must use the
correct namespace and version: SOAP 1.1 actor and `mustUnderstand="0|1"`, or
SOAP 1.2 role, relay and `mustUnderstand="0|1|false|true"`. Role/actor values
must be absolute URIs. Missing fields, array holes, extra fields, proxies,
custom record prototypes and accessor exceptions fail with sanitized errors.

Use `addressing` for WS-Addressing blocks; custom XML cannot inject that namespace.
It requires four absolute URI strings and emits Action, To, MessageID and ReplyTo
(with Address). The four reserved selectors are `wsaAction`, `wsaTo`,
`wsaMessageID`, `wsaReplyTo`. `to` must equal the client URL. An explicitly supplied
SOAP action must equal the addressing action, including when empty. Otherwise,
the addressing action supplies SOAPAction for 1.1 or the content-type action for
1.2. There is no URI resolution, endpoint discovery, MessageID generation,
response correlation or replay cache. Supply fresh MessageIDs in real workloads.

With `security.sign` enabled, all generated addressing blocks are signed along
with Body, Timestamp and any UsernameToken. `security.sign.headers:['trace']`
adds custom selectors; missing selectors fail before transport. Provider-assigned
IDs precede signing, and the final signed tree is serialized once. The total
signature reference limit is 16, including Body, Timestamp, token and headers;
selecting too many blocks fails instead of dropping coverage. Send the resulting
body unchanged.

For responses, configure `security.verify.signedHeaders` with expanded names:
`[{namespace:'urn:trace',localName:'Trace'}]`. Each required name must match exactly
one direct header block covered by the accepted trusted signature. All present
supported addressing blocks (Action, To, MessageID, ReplyTo, RelatesTo) also
require exact-node coverage whenever signature verification is enabled; duplicate
supported blocks fail. References may target direct custom/addressing blocks,
Body and Timestamp, with at most 16 references. Nested decoys do not satisfy policy.
A configured required signed custom header is understood for mandatory-header
handling; unknown targeted mandatory blocks are rejected. Plain/skipped verification
makes no authenticity claim. Body, Fault and XPath remain unavailable on failure.

Evidence: `TestHeaderInputs`, `TestHeaderVersionMetadataAndBudgets`,
`TestPublicSignedHeaderInputs`, `TestHeaderSignatureCoverage` and native
`TestK6SignedHeaderExchanges`. The Apache fixture constructs its own DOM headers
and signs them with WSS4J; its coverage checker independently requires selected
request blocks. Tests cover both SOAP versions, header/addressing tampering and
mathematically signed responses with uncovered headers. See the
[Apache coverage checker source](https://github.com/apache/cxf/blob/main/rt/ws/security/src/main/java/org/apache/cxf/ws/security/wss4j/CryptoCoverageChecker.java)
and the [independent fixture](../test/interop/README.md).
