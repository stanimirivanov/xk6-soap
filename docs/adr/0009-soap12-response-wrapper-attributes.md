# ADR-0009 · Enforce SOAP 1.2 response wrapper attribute rules

**Status** — Accepted

## Context

Previously accepted SOAP 1.2 replies may carry an unqualified attribute on
the Envelope or SOAP 1.2-qualified `encodingStyle` on the Envelope or Body.
The SOAP 1.2 specification forbids these placements. WS-Security also uses
qualified wrapper metadata, including `wsu:Id` on a signed Body.
[SOAP 1.2 §5.1][envelope] · [§5.1.1][encoding] · [§5.3][body]

## Decision

Reject these three shapes in inbound SOAP 1.2 replies. Match attributes by
expanded name and preserve namespace declarations and qualified extension
attributes. A non-Fault Body child can carry SOAP 1.2-qualified `encodingStyle`.
Peers that send one of the three invalid shapes may now see client rejection.

Wire validation returns `XML_INVALID` at stage `xml` before signature
verification or decryption. A structurally invalid recovered Envelope returns
`DECRYPTION_FAILED` at stage `security`. Both outcomes withhold response
content. The [W3C coverage inventory][coverage] records how the client
regressions adapt receiving-node cases that generate Faults.

[envelope]: https://www.w3.org/TR/soap12-part1/#soapenv
[encoding]: https://www.w3.org/TR/soap12-part1/#soapencattr
[body]: https://www.w3.org/TR/soap12-part1/#soapbody
[coverage]: ../soap12-coverage.md#soap-12-envelope-and-body-attributes
