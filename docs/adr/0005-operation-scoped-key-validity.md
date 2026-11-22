# ADR-0005 · Scope runtime certificate validity to the operation

**Status** — Accepted direction for future implementation

## Context

Client construction validates configured key material. Today, both
`build()` and `parse()` also revalidate all configured certificates before
processing a message. An expired receive-only trust pin can therefore
block an outbound build even if the build uses a valid signing identity.
During pin rotation an obsolete pin must be removed before expiry.

## Decision

Keep construction-time validation. In a future change, scope runtime
validity checks to the roles an operation uses and the certificate it
selects. Any certificate used for message protection or authentication
must be valid at use. Specify and test pin eligibility and ambiguous
identifiers as part of implementing the change. The
[current key contract](../keys.md) still describes client-wide
revalidation before both operations.

## Why

Client-wide revalidation gives a uniform failure whenever any configured
certificate expires. Operation-scoped checks allow an exchange direction
to proceed with valid material while a certificate in another role is
being rotated. They require explicit tests for expiry, key selection and
rollover at the operation that consumes the material.
