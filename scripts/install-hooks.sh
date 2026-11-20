#!/bin/sh
set -eu
current=$(git config --get core.hooksPath || true)
if [ -n "$current" ] && [ "$current" != '.githooks' ]; then
    printf 'Existing core.hooksPath=%s; integrate repository checks there instead.\n' "$current" >&2
    exit 1
fi
for hook in pre-commit pre-push; do
    legacy=$(git rev-parse --git-path "hooks/$hook")
    if [ -z "$current" ] && [ -e "$legacy" ]; then
        printf 'Existing %s hook at %s; integrate repository checks there instead.\n' "$hook" "$legacy" >&2
        exit 1
    fi
done
git config --local core.hooksPath .githooks
