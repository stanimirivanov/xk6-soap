#!/bin/sh
set -eu
bin/k6 run --quiet --no-usage-report test/keys.js
if security_output=$(bin/k6 run --quiet --no-usage-report test/security.js 2>&1); then
    case "$security_output" in
        *POLICY_PRIVATE_SENTINEL*) printf 'Security diagnostics leaked the synthetic private sentinel\n' >&2; exit 1 ;;
    esac
    printf '%s\n' "$security_output"
else
    printf '%s\n' "$security_output" >&2
    exit 1
fi
bin/k6 run --quiet --no-usage-report test/smoke.js
# A failed check is only useful as a sensor if the threshold exits nonzero.
set +e
SOAP_SMOKE_FORCE_FAILURE=1 bin/k6 run --quiet --no-usage-report test/smoke.js
status=$?
set -e
if [ "$status" -ne 99 ]; then
    printf 'Expected threshold exit 99, got %s\n' "$status" >&2
    exit 1
fi
