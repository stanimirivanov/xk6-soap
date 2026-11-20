# SOAP metrics

PR-14 instruments build and parse processing through k6's registry and sample
channel. HTTP requests, TLS and HTTP metrics remain owned by k6/http.

| Metric | Type / unit | Sampling |
| --- | --- | --- |
| `soap_build_duration` | Trend / milliseconds | One per execution-context build attempt, including thrown failures |
| `soap_parse_duration` | Trend / milliseconds | One per execution-context parse attempt, including API, transport, XML, security, SOAP and HTTP failures |
| `soap_reqs` | Counter | One per parse invocation |
| `soap_req_failed` | Rate | One per parse invocation: 1 when it fails, otherwise 0 |

Constructor and init-context build/parse misuse emit no samples. Calls rejected
because the VU context is already canceled emit no samples. Active-call failures,
including bad arguments or key checks, are counted. Build-only work emits no remote
outcomes. Re-parsing one response counts again; XPath emits nothing. There is no
cross-call request state or deduplication. Parse duration includes receive crypto,
freshness checks and result projection. Durations use elapsed wall time, independently
of the test-only security clock seam, and are emitted in milliseconds.

Each parse emits its three related samples in one container. Delivery observes VU
cancellation even when the output channel is blocked; canceled shutdown may drop
that whole container. A missing sample channel (for example an inactive test state)
emits nothing. No samples are queued globally or sent during init.

Four metric names are registered once per k6 registry during module initialization;
additional VUs/Clients reuse the references. Reserve these names: do not declare
custom metrics with them. Names found before extension registration are rejected,
including matching types, and missing registries or registration conflicts produce
a sanitized `SOAP_METRIC_REGISTRATION` constructor error rather than a Go panic.
k6's registry retains its own atomic type/unit checks; this is not a security boundary
against a script deliberately writing to an existing metric.

Current VU tags and metadata are copied for each emission. The extension overrides
only its reserved tag keys on the sample, leaving VU state intact:

| Tag | Allowed extension values |
| --- | --- |
| `soap_version` | `1.1`, `1.2` |
| `security_mode` | `plain`, `timestamp`, `username_token`, `signed`, `signed_username_token` |

Security mode describes configured send/receive policy, not authentication success.
A signature policy on either direction uses a signed mode; UsernameToken adds the
signed_username_token mode. Timestamp is the remaining standalone policy. No
operation name, URL, credentials, received content or error text becomes an automatic
tag or metadata value. User-supplied tags/metadata and their cardinality remain the
user's responsibility.

```js
export const options={thresholds:{
  soap_req_failed:['rate==0'],
  soap_build_duration:['p(95)<100'],
  soap_parse_duration:['p(95)<100'],
}};
```

These duration budgets are illustrative script choices, not repository performance
gates. A valid SOAP Fault on HTTP 200 records `soap_req_failed=1` while
`http_req_failed` retains HTTP semantics. Set a SOAP threshold explicitly; checking
only HTTP failure rate misses that outcome. k6 Trend threshold aggregations do not
include count: exact duration sample counts are asserted from handleSummary using
`summaryTrendStats:['count','min','max']` in the native E2E fixture.

Tests assert registration/types/units, concurrent VU initialization, exact sample
counts, failed builds, repeated parse, security failures, fixed tag values, current
VU tags/metadata, init misuse and cancellation after the initial context check.
`test/e2e/metrics.js` runs native k6, emits a bounded summary and proves a SOAP failure
threshold exits 99 for an HTTP-200 Fault while HTTP failure rate stays zero. The same
scenario with the expected nonzero SOAP failure rate passes, so the negative control
cannot pass merely because k6 setup failed.
