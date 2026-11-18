#!/bin/sh
set -eu
current=$(git config --get core.hooksPath || true)
if [ -n "$current" ] && [ "$current" != '.githooks' ]; then
    printf 'Existing core.hooksPath=%s; integrate make verify there instead.\n' "$current" >&2
    exit 1
fi
legacy=$(git rev-parse --git-path hooks/pre-commit)
if [ -z "$current" ] && [ -e "$legacy" ]; then
    printf 'Existing pre-commit hook at %s; integrate make verify there instead.\n' "$legacy" >&2
    exit 1
fi
git config --local core.hooksPath .githooks
