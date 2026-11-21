#!/bin/sh
set -eu

tools=$1
output=$2
xk6_version=$3
if [ -n "$(git status --porcelain)" ]; then
    printf 'Release rehearsal requires a clean source checkout.\n' >&2
    exit 1
fi
if [ -e "$output" ]; then
    printf 'Choose a new RELEASE_OUTPUT directory: %s already exists.\n' "$output" >&2
    exit 1
fi

export GOENV=off GOWORK=off GOAMD64=v1
version=$(go list -m -f '{{.Version}}' go.k6.io/k6/v2)
toolchain=go$(cat .go-version)
actual_xk6=$(go version -m "$tools/xk6" | awk '$1 == "mod" && $2 == "go.k6.io/xk6" {print $3}')
if [ "$actual_xk6" != "$xk6_version" ]; then
    printf 'Unexpected xk6 tool version: %s\n' "$actual_xk6" >&2
    exit 1
fi
mkdir -p "$(dirname "$output")"
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
trap 'exit 1' HUP INT TERM

TMPDIR="$scratch" GOFLAGS= "$tools/xk6" build "$version" --with github.com/stanimirivanov/xk6-soap=. \
    --os linux --arch amd64 --cgo=0 --race-detector=0 --skip-cleanup \
    --build-flags=-trimpath --build-flags=-buildvcs=false '--build-flags=-ldflags=-s -w' \
    --output "$scratch/k6"
set -- "$scratch"/k6foundry*
if [ "$#" -ne 1 ] || [ ! -f "$1/go.mod" ]; then
    printf 'Expected one xk6 build recipe.\n' >&2
    exit 1
fi
"$tools/govulncheck" ./...
python3 scripts/release.py "$scratch/k6" "$toolchain" "$version" \
    --driver "$1" --output "$output" --xk6 "$xk6_version" --govulncheck "$tools/govulncheck"
(cd "$output" && sha256sum --check SHA256SUMS)
