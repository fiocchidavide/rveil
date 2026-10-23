#!/usr/bin/env bash
# Open a file someone sent you with `rveil share`.
#
#   curl -fsSL <this release's open.sh URL> | bash -s -- <passphrase> <file.age>
#
# What it does:
#   1. Finds <file.age> in the current folder or in ~/Downloads.
#   2. Downloads rveil @VERSION@ (github.com/fiocchidavide/rveil) into a
#      temporary folder and checks it against the SHA-256 written below.
#      Nothing is installed.
#   3. Runs `rveil open`, which decrypts, checks and unpacks next to the file.
#      It never overwrites: if a name is taken, it unpacks into <name>.unsealed.
#   4. Removes the temporary folder.
set -euo pipefail

VERSION=@VERSION@
BASE_URL=${RVEIL_OPEN_BASE_URL:-https://github.com/fiocchidavide/rveil/releases/download/$VERSION}
rveil_sha256() {
    case $1 in
        darwin-arm64) echo @SHA256_DARWIN_ARM64@ ;;
        darwin-amd64) echo @SHA256_DARWIN_AMD64@ ;;
        linux-arm64)  echo @SHA256_LINUX_ARM64@ ;;
        linux-amd64)  echo @SHA256_LINUX_AMD64@ ;;
        *) return 1 ;;
    esac
}

die() { printf '✘ %s\n' "$*" >&2; exit 1; }

# Everything runs from main, called on the last line, so bash has read the
# whole script before doing anything (it arrives through a pipe).
main() {
    [ $# -eq 2 ] || die "Usage: … | bash -s -- <passphrase> <file.age>"
    local pass=$1 want=$2 file='' stem dir newest os arch expected got

    # Browsers rename repeat downloads ("<id> (1).age"): the exact name wins,
    # else the newest renamed copy. rveil finds the id inside either name.
    stem=${want%.age}
    for dir in "$PWD" "$HOME/Downloads"; do
        [ -f "$dir/$want" ] && { file="$dir/$want"; break; }
        # ls -t is the portable way to get the newest; the names are rveil's.
        # shellcheck disable=SC2012
        newest=$(ls -t "$dir/$stem"*.age 2>/dev/null | head -n 1 || true)
        [ -n "$newest" ] && { file=$newest; break; }
    done
    [ -n "$file" ] || die "Couldn't find $want here or in ~/Downloads. Download it first, or run this from its folder."

    case $(uname -s) in
        Darwin) os=darwin ;;
        Linux)  os=linux ;;
        *)      die "Unsupported system: $(uname -s)" ;;
    esac
    case $(uname -m) in
        arm64|aarch64) arch=arm64 ;;
        x86_64|amd64)  arch=amd64 ;;
        *)             die "Unsupported processor: $(uname -m)" ;;
    esac
    expected=$(rveil_sha256 "$os-$arch") || die "No rveil build for $os-$arch"

    # Global, so the EXIT trap still sees it after main returns.
    tmp=$(mktemp -d "${TMPDIR:-/tmp}/rveil-open.XXXXXX")
    trap 'rm -rf "$tmp"' EXIT
    printf '▸ Fetching rveil %s\n' "$VERSION" >&2
    curl -fsSL -o "$tmp/rveil" "$BASE_URL/rveil-$os-$arch" || die "Download of rveil failed."
    if command -v shasum >/dev/null; then
        got=$(shasum -a 256 "$tmp/rveil" | cut -d' ' -f1)
    else
        got=$(sha256sum "$tmp/rveil" | cut -d' ' -f1)
    fi
    [ "$got" = "$expected" ] || die "The downloaded rveil doesn't match its known checksum; stopping."
    chmod +x "$tmp/rveil"

    # stdin is this script's own pipe from curl, so the passphrase gets one
    # of its own.
    printf '%s\n' "$pass" | "$tmp/rveil" open -k - -C "$(dirname "$file")" "$file"
}

main "$@"
