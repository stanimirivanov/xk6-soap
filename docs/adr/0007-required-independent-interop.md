# ADR-0007 · Require independent interoperability before merging

**Status** — Accepted. Enforced on `main` since 23 November 2026.

Require successful independent CXF/WSS4J exchanges on every pull request to
`main` through the GitHub Actions `required-ci` aggregate. The ruleset also
requires `vulnerabilities`. A terminal Maven artifact-transfer response of
HTTP 429, 502, 503, or 504 from a configured repository permits one cold image
build retry. Assertion failures, missing artifacts after repository resolution,
unclassified failures, and persistent outages block merges.

An advisory or path-filtered check would reduce the disruption from external
dependency outages, but could allow merges without fresh independent wire
evidence, including when a dependency or fixture changes. We accept that a
prolonged outage can also delay documentation-only merges. The
[test strategy](../test-strategy.md) records the enforced checks and evidence.
