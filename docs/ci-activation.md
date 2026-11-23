# Verify and manage required CI on main

The `main` ruleset has required both `required-ci` and `vulnerabilities` from
the GitHub Actions app since 23 November 2026. Activation added `required-ci`
to the existing status-check rule and preserved the branch freshness policy
and other protections. Successful checks on PR #107 and its merged `main`
commit established readiness. After activation, GitHub's effective branch
rules confirmed both requirements. [Active ruleset](https://github.com/stanimirivanov/xk6-soap/rules/27548817) ·
[Rollout and hosted evidence](https://github.com/stanimirivanov/xk6-soap/pull/107)

The [CI workflow](../.github/workflows/ci.yml) publishes one stable
`required-ci` result for quality, public k6 compatibility, native k6 race,
WSS4J interoperability, and vulnerabilities. It evaluates every direct result
and requires explicit success from all five. Its job condition lets GitHub cancel
the aggregate before it starts or while it runs. A workflow that never reports
the context leaves the check outstanding. The individual jobs remain visible,
including versioned runtime matrix jobs. [GitHub's required-check behavior](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks)

## Verify effective enforcement

From the target checkout, read the effective rules and inspect the revision
used by the merge box on a representative PR. Set `candidate_sha` to that
revision before running the check query.

```sh
gh api 'repos/{owner}/{repo}/rules/branches/main'
gh api "repos/{owner}/{repo}/commits/$candidate_sha/check-runs" \
  --jq '.check_runs[] | select(.name == "required-ci" or .name == "vulnerabilities") | {name, conclusion, app: .app.slug, head_sha, html_url}'
```

Confirm that the effective `required_status_checks` rule lists both contexts
with GitHub Actions integration ID `15368`. When a representative PR is open,
confirm the merge box marks both checks as required on its candidate. A pending
or failing aggregate blocks merging. Use the PR status without merging a probe.

## Evidence before reactivation

Use this checklist if `required-ci` must be reactivated after a rollback.

1. If the workflow changed, merge the reviewed changes through the active
   ruleset. Record a successful `main` push run and a successful `pull_request` run for a
   representative PR using the merged workflow. Include each run URL, event,
   and the candidate SHA GitHub evaluated. A manual dispatch can provide timing
   data. Use an eligible PR run for branch enforcement evidence.
2. Record three successful hosted native k6 race runs, including a manual
   dispatch with `cold_race_build=true`. Collect the separate build and test
   times from the logs and confirm headroom within the job timeout.
3. Link the cold WSS4J run and the retry regressions covering recovery,
   exhaustion, and an assertion failure without retry. Record the controlled
   `TestRequiredCICheck` results for failed, skipped, cancelled, and missing job
   results. The test exercises the evaluator and checks its workflow wiring locally.
   Link the hosted cancellation probes that confirm the scheduler reports the
   aggregate as cancelled both before it starts and while it runs.
4. In the representative PR, verify GitHub reports `required-ci` and
   `vulnerabilities` as successful from the GitHub Actions app on the revision
   used by the merge box. GitHub expects a recent success before a context can
   be selected. Do not use stale results or similarly named jobs.

## Restore the required context after a rollback

With separate authorization, export the active ruleset from the target checkout.
Keep the snapshot with the reactivation evidence.

```sh
gh api 'repos/{owner}/{repo}/rulesets/27548817' > main-ruleset-before.json
```

Confirm from the live rules that the ruleset still targets `main` and that
GitHub Actions is the expected source for `vulnerabilities`. In the existing
status-check rule, append `required-ci` with the same GitHub Actions source.
Keep `vulnerabilities` and preserve the current freshness policy, enforcement,
branch targets, bypass actors, and every other rule. Review the diff as a single
added check context before saving. See the [ruleset API](https://docs.github.com/en/rest/repos/rules#update-a-repository-ruleset).

After saving, compare the live ruleset with the snapshot and repeat the
[effective enforcement checks](#verify-effective-enforcement).

## Roll back activation wiring errors

If activation itself causes a lockout, read the live ruleset and remove only
the `required-ci` context. Compare the remaining contexts with the
snapshot and verify that `vulnerabilities` is still required. Preserve other
rules and any unrelated edits made since the snapshot. A WSS4J assertion failure
or a provisioning outage that persists after the bounded retry is an intended
merge blocker. Fix the failure and rerun CI.
