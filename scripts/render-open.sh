#!/usr/bin/env bash
# Fill in share/open.sh for a release: its version and the SHA-256 of each
# binary (rveil-<os>-<arch> in <dir>).
#   scripts/render-open.sh <version> <dir> > open.sh
set -euo pipefail
version=$1 dir=$2
repo=$(cd "$(dirname "$0")/.." && pwd)
sum() {
    if command -v shasum >/dev/null; then shasum -a 256 "$1" | cut -d' ' -f1; else sha256sum "$1" | cut -d' ' -f1; fi
}
script=$(cat "$repo/share/open.sh")
script=${script//@VERSION@/$version}
for target in darwin-arm64 darwin-amd64 linux-arm64 linux-amd64; do
    placeholder=@SHA256_$(printf '%s' "${target//-/_}" | tr '[:lower:]' '[:upper:]')@
    if [ -f "$dir/rveil-$target" ]; then
        script=${script//$placeholder/$(sum "$dir/rveil-$target")}
    else
        script=${script//$placeholder/missing}
    fi
done
printf '%s\n' "$script"
