# Internal layers

Follow the repository instructions. Use the [architecture checks](../harness/archtest/rules.go) for allowed dependency directions.

- `adapter` owns k6/Sobek bindings and per-VU state. It may use message, keys, clock and WS-Security.
- `message` owns SOAP structure and payloads. Keep it independent of k6, keys and the security provider.
- `keys` decodes byte inputs and owns immutable material. Keep it independent of VU state and transport.
- `clock` is the time and randomness injection boundary. Keep it independent of higher layers.
- `wssec` owns message security policy and provider integration. It may use message, keys and clock.

Security changes must preserve exact consumed-node coverage, bounded pre- and post-decryption parsing, trust selection, and protection order. External XML URI resolution is prohibited. Shared mutable caches require finite capacity and race coverage. Independent interoperability uses WSS4J-produced or WSS4J-verified messages.
