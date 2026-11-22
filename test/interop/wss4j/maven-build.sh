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
    # Recover an imported BOM lookup that is missing or rate-limited by Central.
    # Require the Central endpoint and HTTP status on the same import error line.
    central_429='Non-resolvable import POM.*Could not transfer artifact .* from/to central \(https://repo\.maven\.apache\.org/maven2/?\): status code: 429([,[:space:]]|$)'
    if ! grep -Fq 'Non-resolvable import POM' "$resolution_log" ||
        { ! grep -Fq 'Could not find artifact' "$resolution_log" && ! grep -Eq "$central_429" "$resolution_log"; }; then
        exit "$result"
    fi
    printf 'Central import-BOM lookup failed; trying the independently hosted Central mirror once.\n' >&2
    set -- --settings "$script_dir/central-fallback.xml"
    mvn -U -B -ntp "$@" validate
fi

# Exactly one build/test invocation; keep its exit status and selected endpoint.
rm -f "$resolution_log"
exec mvn -B -ntp "$@" package dependency:copy-dependencies -DincludeScope=runtime
