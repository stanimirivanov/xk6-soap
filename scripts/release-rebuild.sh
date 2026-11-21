#!/bin/sh
# The source archive installs this recipe as rebuild.sh.
set -eu

kit=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
output=$(realpath -m -- "${1:?usage: sh rebuild.sh OUTPUT}")
expected=go$(cat "$kit/extension/.go-version")
export GOTOOLCHAIN=local GOENV=off GOWORK=off GOFLAGS=
if [ "$(go env GOVERSION)" != "$expected" ]; then
    printf 'Put %s on PATH before rebuilding.\n' "$expected" >&2
    exit 1
fi

cache=$(mktemp -d)
trap 'go clean -modcache' EXIT
trap 'exit 1' HUP INT TERM
export GOMODCACHE="$cache" GOPROXY="file://$kit/proxy"
export GOSUMDB=off GOPRIVATE= GONOPROXY= GONOSUMDB= GOEXPERIMENT=
export GOOS=linux GOARCH=amd64 GOAMD64=v1 CGO_ENABLED=0

cd "$kit/build"
go build -mod=readonly -trimpath -buildvcs=false \
    '-ldflags=-s -w -X=go.k6.io/k6/v2/internal/build.BuildOrigin=xk6' -o "$output"
