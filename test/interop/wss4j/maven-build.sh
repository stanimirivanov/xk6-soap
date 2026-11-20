#!/bin/sh
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
resolution_log=$(mktemp)
trap 'rm -f "$resolution_log"' EXIT

# Resolve the model/dependency graph and enforce alignment before compiling or
# running tests. -U prevents a prior not-found result poisoning this attempt.
if mvn -U -B -ntp validate > "$resolution_log" 2>&1; then
    cat "$resolution_log"
    set --
else
    result=$?
    cat "$resolution_log" >&2
    # Recover only the observed Central missing-import-BOM response. Semantic
    # validation failures, compilation and tests never enter this path.
    if ! grep -F 'Non-resolvable import POM' "$resolution_log" >/dev/null \
        || ! grep -F 'Could not find artifact' "$resolution_log" >/dev/null; then
        exit "$result"
    fi
    printf 'Central import-BOM lookup failed; trying the alternate official Central endpoint once.\n' >&2
    set -- --settings "$script_dir/central-fallback.xml"
    mvn -U -B -ntp "$@" validate
fi

# Exactly one build/test invocation; keep its exit status and selected endpoint.
rm -f "$resolution_log"
exec mvn -B -ntp "$@" package dependency:copy-dependencies -DincludeScope=runtime
