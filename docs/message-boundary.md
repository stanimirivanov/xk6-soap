# Plain SOAP message boundary

PR-3 introduces `internal/message` as the transport/runtime-independent message
layer admitted by the architectural harness. It exposes internal Go contracts:

- `Build(operation, payload, Options)` validates one standalone raw operation,
  preserves its bytes inside a SOAP envelope, and returns body and HTTP headers.
- `ValidateEnvelope(document, version, Limits)` validates plain SOAP structure.
- `Error` reports stable `Code` and `Stage` fields without echoing XML, action
  values or parser diagnostics. Codes are `INVALID_ARGUMENT`, `XML_INVALID`
  and `LIMIT_EXCEEDED`.

Version is `1.1` by default or `1.2`. SOAP 1.1 emits a quoted SOAPAction, including
an empty quoted action when absent; SOAP 1.2 omits SOAPAction and includes the
optional action parameter in Content-Type. Invalid UTF-8, control characters,
quotes and backslashes in action values are rejected. Raw operation local names
must match the validated NCName supplied by the caller. The prefixed envelope
wrapper does not introduce a default namespace into an unqualified payload.

Limits are finite and may only be reduced. Zero selects the default; negative
values and increases are rejected until larger budgets have measured evidence.

| Limit | Default/maximum |
| --- | --- |
| Input/output document bytes | 4 MiB |
| Element depth | 64 |
| Decoder tokens | 50,000 |
| Attributes per element, including namespace declarations | 64 |

`Nodes` conservatively counts every token returned by the standard decoder,
including start/end tags, text and comments; it is not a DOM element count.
Input byte limits are checked before decoding. Depth/attribute/token budgets
are checked as tokens arrive. The decoder may allocate a single token within
the bounded input before its attributes are counted; this is not a claim of
zero allocation before every limit check. There is no retained document tree.
Output byte length is checked before concatenation, and the completed document
is checked against all limits again. Build depth/token limits include the SOAP
wrapper, not just the standalone payload. Action bytes are bounded by the same
byte budget independently of document size.

The standard [encoding/xml decoder](https://pkg.go.dev/encoding/xml#Decoder.RawToken)
owns lexical XML parsing. The validation layer uses RawToken to retain prefixes,
checks matching tags, and applies [XML namespace constraints](https://www.w3.org/TR/REC-xml-names/)
that the standard Token API does not enforce, including declared prefixes,
reserved bindings and duplicate expanded attribute names. XML 1.0 NCName rules
apply to operation and qualified-name components. DTDs, processing instructions,
unknown entities and invalid UTF-8 are rejected. Comments, CDATA and
predefined/numeric character references remain valid.

Complete inbound SOAP Envelopes may start with one well-formed
[XML 1.0 declaration](https://www.w3.org/TR/xml/#sec-prolog-dtd), optionally
preceded by a UTF-8 BOM. The encoding may be omitted or set to UTF-8. The
original wire bytes and the declaration token count toward input limits.
The inbound parser removes the declaration before passing the Envelope to
either XML tree parser. Outbound fragments and internal Body projections
still reject declarations.

Envelope checks use expanded names and positions: one root Envelope, at most
one Header before exactly one Body, no extra envelope children, and no nested
SOAP Envelope/Header/Body wrappers. Raw payloads reject elements in SOAP envelope
namespaces. This is a deliberately limited plain-message contract, not general
XSD validation or a WS-Security acceptance check.

No signature canonicalization or XML reserialization is implemented. Secured
messages must use the selected provider's tree/coverage validation; these helpers
must not serialize a signed message or substitute for signature verification.
Public JavaScript build/parse bindings, HTTP result handling, faults and XPath
belong to PR-4, and object mapping belongs to PR-15.

Focused verification:

```sh
GOTOOLCHAIN=go1.27.4 go test ./internal/message -count=1
GOTOOLCHAIN=go1.27.4 go test ./internal/message -run '^$' -fuzz '^FuzzValidateEnvelope$' -fuzztime=5s -parallel=2
GOTOOLCHAIN=go1.27.4 go test ./internal/message -run '^$' -fuzz '^FuzzBuild$' -fuzztime=5s -parallel=2
```

The ordinary test suite runs each fuzz seed. Mutation/tamper/namespace/limit
regressions are deterministic tables; fuzz runs add bounded exploration and do
not establish interoperability or cryptographic correctness.
