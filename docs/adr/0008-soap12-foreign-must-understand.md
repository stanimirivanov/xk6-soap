# ADR-0008 · Interpret SOAP 1.1 mustUnderstand as foreign metadata in SOAP 1.2 replies

**Status** — Accepted

## Context

Rejecting all SOAP 1.1 Envelope attributes on SOAP 1.2 Header blocks can
withhold an otherwise acceptable Body. In [W3C T34], a SOAP 1.2 receiving
node ignores an unknown request Header block carrying a SOAP 1.1-qualified
`mustUnderstand`. [SOAP 1.2 §5.2.3] defines the SOAP 1.2 attribute by its
expanded name.

## Decision

On ordinary Header blocks in SOAP 1.2 replies, treat SOAP 1.1-qualified
`mustUnderstand` as foreign metadata. The SOAP 1.2-qualified attribute
determines whether the block is mandatory, regardless of attribute order.
Apply the same rule to plain, signed and recovered Header blocks.

This accepts a narrow form of mixed-version metadata for peers that send it.
Other cross-version attributes, SOAP 1.1 replies, outbound Header validation,
and the validation of Security and EncryptedHeader retain their existing rules.
The original attribute stays in the XML and participates in signature coverage
when the block is signed. Response acceptance still requires all configured
trust, coverage, freshness and encryption checks.

[W3C T34]: https://www.w3.org/TR/soap12-testcollection/#T34
[SOAP 1.2 §5.2.3]: https://www.w3.org/TR/soap12-part1/#soapmu
