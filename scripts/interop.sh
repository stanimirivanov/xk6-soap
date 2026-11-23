#!/bin/sh
set -eu

run_fixture() {
    scratch=$1
    image=$2
    printf '%s\n' "Starting the WSS4J fixture."
    timeout --foreground 30s docker run --detach --init --read-only --tmpfs /tmp:rw,nosuid,size=64m \
        --cap-drop=ALL --security-opt=no-new-privileges --memory=512m --cpus=2 \
        --pids-limit=256 --publish 127.0.0.1::8080 --cidfile "$scratch/container" "$image" >/dev/null
    container=$(cat "$scratch/container")
    timeout --foreground 10s docker cp "$container:/fixture/test-keys/server.pem" "$scratch/server.pem"
    for bits in 256 384 521; do
        timeout --foreground 10s docker cp "$container:/fixture/test-keys/client-ec$bits.p12" "$scratch/client-ec$bits.p12"
        timeout --foreground 10s docker cp "$container:/fixture/test-keys/server-ec$bits.pem" "$scratch/server-ec$bits.pem"
    done
    address=$(timeout --foreground 10s docker port "$container" 8080/tcp)
    case "$address" in 127.0.0.1:[0-9]*) ;; *) printf 'Unexpected fixture address: %s\n' "$address" >&2; exit 1 ;; esac
    printf '%s\n' assertions > "$scratch/phase"
    printf '%s\n' "Running WSS4J interoperability assertions."
    if ! SOAP_INTEROP_URL="http://$address" SOAP_INTEROP_SIGNATURE_TRUST="$scratch/server.pem" go test -race -tags=interop ./test/interop -count=1 -timeout=90s; then
        printf '%s\n' "WSS4J interoperability assertions failed." >&2
        exit 1
    fi
}

if [ "${1:-}" = --run-fixture ]; then
    run_fixture "$2" "$3"
    exit
fi

scratch=$(mktemp -d)
cleanup() {
    result=$?
    if [ -s "$scratch/container" ]; then
        container=$(cat "$scratch/container")
        if ! timeout -k 2s 13s docker rm --force "$container" >/dev/null 2>&1; then
            printf 'Failed to remove fixture container %s\n' "$container" >&2
            result=1
        fi
    fi
    rm -rf "$scratch"
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir "$scratch/build"
cp test/interop/wss4j/Dockerfile test/interop/wss4j/pom.xml test/interop/wss4j/maven-build.sh test/interop/wss4j/central-fallback.xml test/interop/wss4j/central-fallback-eu.xml test/interop/wss4j/generate-keys.sh "$scratch/build/"
cp -R test/interop/wss4j/src "$scratch/build/src"
# Apache trusts only the committed synthetic client's public certificate.
cp internal/wssec/testdata/signing-cert.pem "$scratch/build/client-cert.pem"
# Plain progress exposes the Maven stage exit status in BuildKit output.
# Require both the stage's declared classification and its terminal exit code.
build_log="$scratch/build.log"
for attempt in 1 2; do
    printf 'Building the cold WSS4J fixture image (attempt %s/2).\n' "$attempt"
    rm -f "$scratch/image"
    if timeout -k 5s 595s docker build --no-cache --progress=plain --iidfile "$scratch/image" "$scratch/build" >"$build_log" 2>&1; then
        cat "$build_log"
        break
    else
        result=$?
    fi
    cat "$build_log" >&2
    printf 'WSS4J fixture image build attempt %s failed (exit %s).\n' "$attempt" "$result" >&2
    if [ "$attempt" -ne 1 ] || [ "$result" -ne 1 ] ||
        ! grep -Eq '^#[0-9]+ [0-9.]+ WSS4J_TERMINAL_MAVEN_TRANSFER_RETRYABLE$' "$build_log" ||
        ! grep -Eq '^ERROR: .*process "/bin/sh -c sh maven-build[.]sh" did not complete successfully: exit code: 75$' "$build_log"; then
        exit "$result"
    fi
    printf '%s\n' "Retrying the cold WSS4J fixture build after a terminal Maven transfer failure." >&2
done

image=$(cat "$scratch/image")
printf '%s\n' startup > "$scratch/phase"
# 270s for startup and assertions, 5s to terminate, 10s for logs, and 15s for cleanup.
if timeout -k 5s 270s sh "$0" --run-fixture "$scratch" "$image"; then
    exit 0
else
    result=$?
    phase=$(cat "$scratch/phase")
    printf 'WSS4J fixture stage %s failed (exit %s).\n' "$phase" "$result" >&2
    if [ "$phase" = assertions ]; then
        timeout -k 2s 8s docker logs --tail 100 "$(cat "$scratch/container")" >&2 || true
    fi
    exit "$result"
fi
