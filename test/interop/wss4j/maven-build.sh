#!/bin/sh
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
resolution_log=$(mktemp)
trap 'rm -f "$resolution_log"' EXIT

# These properties use the pinned Maven 3.9 native HTTP transport's keys.
# Bound individual requests as well as total time on each validation endpoint.
export MAVEN_OPTS="${MAVEN_OPTS:-} -Daether.connector.connectTimeout=10000 -Daether.connector.requestTimeout=20000 -Daether.connector.http.retryHandler.count=1 -Daether.connector.http.retryHandler.intervalMax=5000"

central_429='Non-resolvable import POM.*Could not transfer artifact .* from/to central \(https://repo\.maven\.apache\.org/maven2/?\): status code: 429([,[:space:]]|$)'
mirror_transfer='Could not transfer artifact .* from/to google-maven-central \(https://maven-central\.storage-download\.googleapis\.com/maven2/?\):.*(status code: (429|50[0234])([,[:space:]]|$)|[Tt]imed out|[Tt]imeout)'

for endpoint in Central Americas EU; do
    case "$endpoint" in
        Central) set -- ;;
        Americas) set -- --settings "$script_dir/central-fallback.xml" ;;
        EU) set -- --settings "$script_dir/central-fallback-eu.xml" ;;
    esac
    printf 'Validating the fixture using %s (120s deadline).\n' "$endpoint"
    # -U bypasses Maven's cached negative lookups before trying the next endpoint.
    if timeout -k 5s 120s mvn -U -B -ntp "$@" validate >"$resolution_log" 2>&1; then
        cat "$resolution_log"
        break
    else
        result=$?
    fi
    cat "$resolution_log" >&2
    if [ "$result" -eq 124 ]; then
        printf '%s Maven validation timed out after 120s.\n' "$endpoint" >&2
    fi
    case "$endpoint" in
        Central)
            if [ "$result" -ne 124 ] &&
                ! grep -Eq "$central_429" "$resolution_log" &&
                { ! grep -Fq 'Non-resolvable import POM' "$resolution_log" ||
                  ! grep -Fq 'Could not find artifact' "$resolution_log"; }; then
                exit "$result"
            fi
            printf 'Central validation could not complete. Trying the Americas mirror.\n' >&2 ;;
        Americas)
            if [ "$result" -ne 124 ] && ! grep -Eq "$mirror_transfer" "$resolution_log"; then
                exit "$result"
            fi
            printf 'Americas mirror validation could not complete. Trying the EU mirror.\n' >&2 ;;
        EU) exit "$result" ;;
    esac
done

# Exactly one build/test invocation, using the endpoint that validated.
rm -f "$resolution_log"
exec mvn -B -ntp "$@" package dependency:copy-dependencies -DincludeScope=runtime
