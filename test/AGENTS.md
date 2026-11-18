# Runtime and future interoperability fixtures

`smoke.js` is a real custom-k6 runtime probe, not a SOAP interoperability test.
A check must have a failing threshold to make the process fail. Preserve the negative
control that proves this, and keep fixtures deterministic except for production crypto.

Future servers may use local network/filesystem access here, never in runtime packages.
Use synthetic identities, bounded readiness/timeouts and cleanup. WSS4J evidence must
exercise independently produced messages in both directions. Never relabel a provider
self-round-trip or a skipped/unavailable fixture as a passing interop test.
