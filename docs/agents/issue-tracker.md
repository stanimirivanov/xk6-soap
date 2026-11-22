# Issue tracker

Use [GitHub Issues](https://github.com/stanimirivanov/xk6-soap/issues) for specs and tickets. Run `gh` from the repository and verify the target with `gh repo view --json nameWithOwner` before filing work. Publish a spec or ticket as an issue. Fetch a ticket with `gh issue view NUMBER --json number,title,body,labels,comments`. Use `--body-file` for multiline issue and PR bodies. Apply the repository's [triage labels](triage-labels.md) when triage is requested.

## Pull requests as a triage surface

**PRs as a request surface: no.**

## Issue relationships

Use GitHub sub-issues and native issue dependencies for parent and blocking relationships. The installed `gh` may predate the corresponding flags. In that case, obtain the child's or blocker's numeric database ID with `gh api repos/{owner}/{repo}/issues/NUMBER --jq .id` and use:

```sh
gh api --method POST 'repos/{owner}/{repo}/issues/PARENT/sub_issues' -F sub_issue_id=CHILD_DATABASE_ID
gh api --method POST 'repos/{owner}/{repo}/issues/CHILD/dependencies/blocked_by' -F issue_id=BLOCKER_DATABASE_ID
```

Check open blockers with `gh api 'repos/{owner}/{repo}/issues/NUMBER' --jq .issue_dependencies_summary.blocked_by`. If the tracker lacks native relationships, use `Part of #PARENT` or `Blocked by: #BLOCKER` in the issue body. A ticket can start when all blockers are closed.

For Wayfinder, create one `wayfinder:map` issue and link child tickets using sub-issues. Label each child by type using `wayfinder:research`, `wayfinder:prototype`, `wayfinder:grilling`, or `wayfinder:task`. Unassigned open children without open blockers are available to claim.

## Delivery conventions

- Start from a clean checkout, switch to `main`, and run `git pull --ff-only`. Preserve any existing work.
- Use a dedicated issue and the applicable milestone. Branch as `feature/issue-N` or `fix/issue-N`.
- Review the final diff, stage scoped files, and commit as `[#N] summary`. Use the repository [verification guide](../../harness/HARNESS.md) for gates.
- Push and open an issue-linked PR titled `[#N] PR title` with `Closes #N`. Use the installed PR skill for structure and report verification. Stop after delivery. Merge, release, CI polling, and revisions require a user request.
