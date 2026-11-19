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
timeout 600 docker build --iidfile "$scratch/image" test/interop/wss4j
image=$(cat "$scratch/image")
timeout 30 docker run --detach --init --read-only --tmpfs /tmp:rw,nosuid,size=64m \
    --cap-drop=ALL --security-opt=no-new-privileges --memory=512m --cpus=2 \
    --pids-limit=256 --publish 127.0.0.1::8080 --cidfile "$scratch/container" "$image" >/dev/null
container=$(cat "$scratch/container")
address=$(timeout 10 docker port "$container" 8080/tcp)
case "$address" in 127.0.0.1:[0-9]*) ;; *) printf 'Unexpected fixture address: %s\n' "$address" >&2; exit 1 ;; esac
if ! SOAP_INTEROP_URL="http://$address" go test -race -tags=interop ./test/interop -count=1 -timeout=90s; then
    timeout 10 docker logs --tail 100 "$container" >&2 || true
    exit 1
fi
