# Internal layers

Root AGENTS.md applies. `archtest` is repository tooling, never a runtime dependency.
Runtime package boundaries are defined by the rules in `archtest/rules.go`:

- `adapter`: k6/Sobek bindings and per-VU state. May use message/keys/clock/wssec.
- `message`: SOAP structure and payloads; no k6, keys or provider dependencies.
- `keys`: byte-based key decoding and immutable material; no VU/runtime/transport.
- `clock`: time/random injection boundary; no higher-layer imports.
- `wssec`: message security policy and provider integration; may use message/keys/clock.

Do not create empty packages just to fill this map. A feature adds its owning package,
focused tests and narrower AGENTS.md only if it needs additional local guidance.

For security code, prove exact consumed-node coverage, bounded pre/post-decrypt parsing,
trust selection and order handling. A provider self-round-trip is not independent interop.
Shared mutable caches need race tests and finite capacity. No external XML URI resolvers.
