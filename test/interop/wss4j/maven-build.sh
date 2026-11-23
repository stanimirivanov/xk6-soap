#!/bin/sh
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
resolution_log=$(mktemp)
trap 'rm -f "$resolution_log"' EXIT

# These properties use the pinned Maven 3.9 native HTTP transport's keys.
# Bound individual requests as well as total time on each validation endpoint.
export MAVEN_OPTS="${MAVEN_OPTS:-} -Daether.connector.connectTimeout=10000 -Daether.connector.requestTimeout=20000 -Daether.connector.http.retryHandler.count=1 -Daether.connector.http.retryHandler.intervalMax=5000"

central='central [(]https://repo[.]maven[.]apache[.]org/maven2/?[)]'
americas='google-maven-central [(]https://maven-central[.]storage-download[.]googleapis[.]com/maven2/?[)]'
eu='google-maven-central-eu [(]https://maven-central-eu[.]storage-download[.]googleapis[.]com/maven2/?[)]'
central_429="Non-resolvable import POM.*Could not transfer artifact .* from/to $central: status code: 429([,[:space:]]|$)"
mirror_transfer="Could not transfer artifact .* from/to $americas:.*(status code: (429|50[0234])([,[:space:]]|$)|[Tt]imed out|[Tt]imeout)"

fail_maven() {
    # Inspect only this invocation. Any other actionable error makes the
    # failure ambiguous, even when Maven also reports a transient transfer.
    if [ "$1" -lt 124 ] && awk -v central="$central" -v americas="$americas" -v eu="$eu" '
        BEGIN {
            transfer = "Could not transfer artifact [^[:space:]]+ from/to (" central "|" americas "|" eu "): status code: (429|502|503|504)([,[:space:]]|$)"
        }
        /^\[ERROR\]/ {
            sub(/^\[ERROR\][[:space:]]*/, "")
            if ($0 ~ /^($|\[ERROR\] Some problems were encountered while processing the POMs:|The build could not read [0-9]+ project|The project .* has [0-9]+ error(s)?$|To see the full stack trace|Re-run Maven|For more information|\[Help [0-9]+\] https?:)/) next
            if ($0 ~ /^Failed to execute goal .* (could not be resolved:|Could not (resolve|collect) dependencies for project [^[:space:]]+:?)$/) next
            if ($0 ~ /^(dependency: [^[:space:]]+ [(][[:alpha:]]+[)]|Failed to read artifact descriptor for [^[:space:]]+:?|Plugin [^[:space:]]+ or one of its dependencies could not be resolved:|-> \[Help [0-9]+\])$/) next
            line = $0
            # An aggregate may report only one cause for several artifacts.
            if ($0 ~ /The following artifacts could not be resolved: .*[,].*: Could not transfer artifact/ ||
                $0 !~ transfer || gsub(/Could not (find|transfer) artifact/, "", line) != 1) other = 1
            else found = 1
        }
        END { exit !(found && !other) }
    ' "$resolution_log"; then
        printf '%s\n' WSS4J_TERMINAL_MAVEN_TRANSFER_RETRYABLE >&2
        exit 75
    fi
    exit "$1"
}

for endpoint in Central Americas EU; do
    case "$endpoint" in
        Central) set -- ;;
        Americas) set -- --settings "$script_dir/central-fallback.xml" ;;
        EU) set -- --settings "$script_dir/central-fallback-eu.xml" ;;
    esac
    printf 'Validating the fixture using %s (120s deadline).\n' "$endpoint"
    # -U bypasses Maven's cached negative lookups before trying the next endpoint.
    if timeout -k 5s 120s mvn -U -B -ntp -Dstyle.color=never "$@" validate >"$resolution_log" 2>&1; then
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
                fail_maven "$result"
            fi
            printf 'Central validation could not complete. Trying the Americas mirror.\n' >&2 ;;
        Americas)
            if [ "$result" -ne 124 ] && ! grep -Eq "$mirror_transfer" "$resolution_log"; then
                fail_maven "$result"
            fi
            printf 'Americas mirror validation could not complete. Trying the EU mirror.\n' >&2 ;;
        EU) fail_maven "$result" ;;
    esac
done

# Exactly one build/test invocation, using the endpoint that validated.
if mvn -B -ntp -Dstyle.color=never "$@" package dependency:copy-dependencies -DincludeScope=runtime >"$resolution_log" 2>&1; then
    cat "$resolution_log"
else
    result=$?
    cat "$resolution_log" >&2
    fail_maven "$result"
fi
