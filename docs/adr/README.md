# Architecture decision records

| Decision | Status and evidence |
| --- | --- |
| [ADR-0001 · k6 runtime integration](0001-k6-runtime-contract.md) | Accepted lifecycle, module registration, ArrayBuffer handling and metric contract. The ADR records the original k6 pin. Current versions are in [go.mod](../../go.mod). |
| [ADR-0002 · signature coverage and serialization](0002-signature-kernel.md) | Core signature gate passed against Apache. Includes exact Body/Timestamp coverage and canonical-byte evidence. |
| [ADR-0003 · encryption and protection orders](0003-encryption-kernel.md) | Accepted bounded XML security kernel. Both protection orders passed the core gate. Completes the provider decision started in ADR-0002. |
| [ADR-0004 · explicit message trust](0004-explicit-message-trust.md) | Accepted exact leaf pins and separate TLS trust. |
| [ADR-0005 · operation-scoped certificate validity](0005-operation-scoped-key-validity.md) | Accepted direction for future implementation. Current runtime checks span all configured roles. |
| [ADR-0006 · receive verification defaults](0006-receive-verification-defaults.md) | Accepted signature and freshness defaults with explicit receive overrides. |
| [ADR-0007 · required independent interoperability](0007-required-independent-interop.md) | Accepted and enforced on `main` through `required-ci`. |

The ADRs preserve the evidence and versions used for their decisions. Current
public behavior is documented in the [architecture](../architecture.md) and
[contract evidence](../contracts.md).
