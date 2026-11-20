#!/bin/sh
set -eu
scratch=$(mktemp -d)
cleanup() {
    result=$?
    if [ -s "$scratch/container" ]; then
        container=$(cat "$scratch/container")
        if ! timeout 15 docker rm --force "$container" >/dev/null 2>&1; then
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
cp test/interop/wss4j/Dockerfile test/interop/wss4j/pom.xml test/interop/wss4j/maven-build.sh test/interop/wss4j/central-fallback.xml test/interop/wss4j/generate-keys.sh "$scratch/build/"
cp -R test/interop/wss4j/src "$scratch/build/src"
# Apache trusts only the committed synthetic client's public certificate.
cp internal/wssec/testdata/signing-cert.pem "$scratch/build/client-cert.pem"
timeout 600 docker build --iidfile "$scratch/image" "$scratch/build"
image=$(cat "$scratch/image")
timeout 30 docker run --detach --init --read-only --tmpfs /tmp:rw,nosuid,size=64m \
    --cap-drop=ALL --security-opt=no-new-privileges --memory=512m --cpus=2 \
    --pids-limit=256 --publish 127.0.0.1::8080 --cidfile "$scratch/container" "$image" >/dev/null
container=$(cat "$scratch/container")
timeout 10 docker cp "$container:/fixture/test-keys/server.pem" "$scratch/server.pem"
address=$(timeout 10 docker port "$container" 8080/tcp)
case "$address" in 127.0.0.1:[0-9]*) ;; *) printf 'Unexpected fixture address: %s\n' "$address" >&2; exit 1 ;; esac
if ! SOAP_INTEROP_URL="http://$address" SOAP_INTEROP_SIGNATURE_TRUST="$scratch/server.pem" go test -race -tags=interop ./test/interop -count=1 -timeout=90s; then
    timeout 10 docker logs --tail 100 "$container" >&2 || true
    exit 1
fi
