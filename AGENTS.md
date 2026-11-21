# xk6-soap

Go extension for k6; k6 owns HTTP transport. Start with [README](README.md).
Read [HARNESS](HARNESS.md) for the repository map and check selection; read only the
relevant spec section and source/tests for the current issue. The full architecture is in docs/architecture.md; use the implemented source and
tests to distinguish shipped behavior from planned APIs.

## Work loop

1. Plan: identify the issue's acceptance criteria, owning layer and focused checks.
2. Execute: implement the smallest coherent change; add a failing regression for behavior.
3. Verify: run focused checks, read the actual failure location/rule, fix the cause,
   then run the delivery gates. Do not skip tests, silence diagnostics or weaken a
   rule to obtain green. Repeat only after a relevant change or unresolved failure.

Use installed skills only when directly useful. No mandatory agents, model routing,
full-repository rereads, transcript files or extra approval rituals.

## Boundaries

- The root package registers the extension through `internal/adapter`. Only the adapter owns Sobek/k6 bindings and per-VU state.
- No production transport/filesystem/process access; key inputs will be bytes.
- Keys may eventually be immutable shared data; XML trees and JS values are per VU/request.
- Never implement XML canonicalization or crypto primitives locally; provider selection is gated.
- No secrets, bodies or credentials in logs. Test keys must be synthetic and clearly labeled.
- Go style: gofmt, explicit errors, narrow concrete types; introduce interfaces at proven seams.
- New production packages or changed dependency directions require a boundary rationale and
  an update to the tested architecture rules, not a suppression.

## Delivery

Follow the user's issue/PR workflow: clean main + ff-only pull, dedicated milestone issue,
feature/issue-N or fix/issue-N, focused implementation, final diff review, stage only scope,
commit `[#N] summary`, push and linked PR, report verification, stop. Preserve existing work.
Do not merge, release, poll CI or revise a delivered PR unless requested.
