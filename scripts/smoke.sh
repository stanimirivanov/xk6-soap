#!/bin/sh
set -eu
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
