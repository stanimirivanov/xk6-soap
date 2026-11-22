# xk6-soap

Go extension for SOAP and WS-Security. k6 owns HTTP transport. Start with the [README](README.md).

## Agent skills

Use the installed `mattpocock/skills` package as the primary workflow for planning, triage, TDD, diagnosis, review, and PR writing. Load skills through native discovery when relevant. The repository's technical constraints and GitHub delivery conventions still apply.

### Issue tracker

Use GitHub Issues for `stanimirivanov/xk6-soap`. See [tracker and delivery conventions](docs/agents/issue-tracker.md).

### Triage labels

Use the canonical state and category labels in the [triage mapping](docs/agents/triage-labels.md).

### Domain docs

Use the single repository context described in [domain docs](docs/agents/domain.md).

## Technical constraints

- The root package registers the extension through `internal/adapter`. Only the adapter owns Sobek/k6 bindings and per-VU values. Keep message and XML state per request or response. See [architecture](docs/architecture.md).
- Keep production transport, filesystem and process access outside the extension. Accept key inputs as bytes and use the pinned provider for canonicalization and cryptographic primitives.
- Keep secrets, bodies and credentials out of logs. Use synthetic test keys and identities.
- Follow gofmt, explicit errors, narrow concrete types, and the declaration style in the [verification guide](harness/HARNESS.md). Update the tested architecture rules when an approved change adds a production package or changes a dependency direction.
- Use `make verify` and the affected runtime gates from the [verification guide](harness/HARNESS.md). Preserve the required checks and report their results.
