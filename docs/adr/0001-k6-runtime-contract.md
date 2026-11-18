# ADR-0001: Pinned k6 runtime integration contract

Status: accepted for the scaffold. Date: 18 November 2026.
Task: [PR-1 / issue #7](https://github.com/stanimirivanov/xk6-soap/issues/7).

## Decision and evidence

Use Go 1.27.4 and k6 v2.3.0, with the Sobek version selected in go.mod.
Verification tools are pinned in Makefile: Staticcheck v0.8.2, govulncheck
v1.10.0, xk6 v1.5.1 and Actionlint v1.7.12. Dependency checks and binary audits
remain required; version pins alone do not establish safety.

The runtime tests establish these integration contracts:

- `NewModuleInstance` returns `modules.Instance`; named Client uses a Sobek
  constructor callback. Returning `call.This` preserves `instanceof Client`.
- Client construction belongs to init context. Execution-context construction
  is rejected. Client objects and bindings belong to their individual VU.
- Binary input is a Sobek ArrayBuffer, not a typed-array view. `copyArrayBuffer`
  rejects other values and detached buffers and clones bytes immediately.
  Empty attached buffers are valid at this boundary; future key validation
  decides whether they constitute valid key material. Mutation on either side
  cannot change the other's bytes. No JS object is retained by this helper.
- Metrics register through `vu.InitEnv().Registry.NewMetric` during init.
  Identical registrations share the descriptor; a conflicting type errors.
  Execution sampling uses `metrics.Sample`, `lib.State.Samples`, and
  `metrics.PushIfNotDone` with the VU context. Init sampling is refused by the
  test adapter; cancellation prevents further samples. A buffered channel
  avoids requiring a separate consumer in the probe.

`soap_test.go`, `bytes_test.go` and `runtime_contract_test.go` exercise these
contracts with the actual pinned runtime. `make smoke` separately builds a real
custom k6 binary, imports the named Client and proves threshold failures exit 99.
The byte ownership helper is internal and is not yet a public key-loading API.
The metric adapter is test-only and registers no production SOAP metrics.

## Limits and follow-up

These probes establish integration feasibility, not SOAP/security correctness.
SOAP methods and configuration still reject explicitly. Key-size/format limits,
VU tag propagation, production metric definitions and result semantics belong
to their respective feature tasks. No independent crypto interop claim follows
from runtime success. The current build supports the pinned versions only;
expanding that matrix requires testing each additional combination.
