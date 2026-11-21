#!/bin/sh
set -eu

# Go accepts a duration or an iteration count. Keep each target isolated so
# corpus reproduction and resource limits are explicit.
duration=${FUZZ_TIME:-2s}
while read -r package target; do
    printf 'Fuzzing %s %s for %s\n' "$package" "$target" "$duration"
    go test "$package" -run '^$' -fuzz "^$target\$" -fuzztime "$duration" -parallel 2 -timeout 90s
done <<'TARGETS'
./internal/message FuzzValidateEnvelope
./internal/message FuzzBuild
./internal/message FuzzParsePlainResponse
./internal/message FuzzBodyXPath
./internal/wssec FuzzReceiveSecurity
./internal/wssec FuzzRecoveredXML
. FuzzSecurityOptions
TARGETS
