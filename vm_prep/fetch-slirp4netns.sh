#!/bin/sh
# Fetch the upstream, checksum-pinned static slirp4netns release binary.
# Usage: vm_prep/fetch-slirp4netns.sh [REPO_ROOT]
set -eu

REPO="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
REPO="$(cd "$REPO" && pwd)"
. "$REPO/deps.lock"

EXT="${ZAIGR_EXTERNAL_SOURCES:-$HOME/.zaigr/external-sources}"
VERSION_FILE="$REPO/cmd/zaigr/vm_data/slirp4netns.version"
OUTPUT="$REPO/cmd/zaigr/vm_data/slirp4netns"
URL="https://github.com/rootless-containers/slirp4netns/releases/download/v${SLIRP4NETNS_VERSION}/slirp4netns-x86_64"
CACHE_DIR="$EXT/slirp4netns/upstream-v${SLIRP4NETNS_VERSION}-${SLIRP4NETNS_SHA256}"
CACHED="$CACHE_DIR/slirp4netns-x86_64"

for tool in curl sha256sum readelf ldd grep; do
    command -v "$tool" >/dev/null 2>&1 || {
        printf 'ERROR: %s not found in PATH\n' "$tool" >&2
        exit 1
    }
done

mkdir -p "$CACHE_DIR" "$(dirname "$OUTPUT")"
verify_sha256() {
    file="$1"
    printf '%s  %s\n' "$SLIRP4NETNS_SHA256" "$file" | sha256sum -c -
}

if [ -s "$CACHED" ]; then
    if ! verify_sha256 "$CACHED" >/dev/null; then
        printf 'ERROR: cached upstream slirp4netns v%s failed its pinned SHA-256\n' \
            "$SLIRP4NETNS_VERSION" >&2
        exit 1
    fi
else
    DOWNLOAD="$CACHE_DIR/.slirp4netns-x86_64.download-$$"
    trap 'rm -f "$DOWNLOAD"' EXIT HUP INT TERM
    printf ':: Downloading upstream slirp4netns v%s\n' "$SLIRP4NETNS_VERSION"
    if ! curl --fail --location --retry 2 --connect-timeout 10 --max-time 120 \
        --silent --show-error --output "$DOWNLOAD" "$URL"; then
        printf 'ERROR: failed to download %s\n' "$URL" >&2
        exit 1
    fi
    if ! verify_sha256 "$DOWNLOAD"; then
        printf 'ERROR: upstream slirp4netns v%s did not match its pinned SHA-256\n' \
            "$SLIRP4NETNS_VERSION" >&2
        exit 1
    fi
    chmod 0755 "$DOWNLOAD"
    mv "$DOWNLOAD" "$CACHED"
    trap - EXIT HUP INT TERM
fi
chmod 0755 "$CACHED"

if ! readelf -h "$CACHED" | grep -q 'Machine:.*X86-64'; then
    printf 'ERROR: upstream slirp4netns binary is not x86-64\n' >&2
    exit 1
fi
if readelf -l "$CACHED" | grep -q INTERP; then
    printf 'ERROR: upstream slirp4netns binary has a dynamic ELF interpreter\n' >&2
    exit 1
fi
if readelf -d "$CACHED" 2>&1 | grep -q NEEDED; then
    printf 'ERROR: upstream slirp4netns binary has dynamic dependencies\n' >&2
    exit 1
fi
LDD_OUTPUT="$(ldd "$CACHED" 2>&1 || true)"
case "$LDD_OUTPUT" in
    *'not a dynamic executable'*) ;;
    *)
        printf 'ERROR: ldd did not confirm static linkage: %s\n' "$LDD_OUTPUT" >&2
        exit 1
        ;;
esac

VERSION_OUTPUT="$("$CACHED" --version 2>&1)"
case "$VERSION_OUTPUT" in
    *"slirp4netns version $SLIRP4NETNS_VERSION"*) ;;
    *)
        printf 'ERROR: unexpected upstream slirp4netns version output: %s\n' \
            "$VERSION_OUTPUT" >&2
        exit 1
        ;;
esac
"$CACHED" --help >"$CACHE_DIR/help.txt" 2>&1
if ! grep -q -- '--disable-dns' "$CACHE_DIR/help.txt"; then
    printf 'ERROR: upstream slirp4netns does not support --disable-dns\n' >&2
    exit 1
fi

OUTPUT_TMP="$OUTPUT.tmp-$$"
VERSION_TMP="$VERSION_FILE.tmp-$$"
trap 'rm -f "$OUTPUT_TMP" "$VERSION_TMP"' EXIT HUP INT TERM
cp "$CACHED" "$OUTPUT_TMP"
chmod 0755 "$OUTPUT_TMP"
verify_sha256 "$OUTPUT_TMP" >/dev/null
printf '%s\n' "$SLIRP4NETNS_VERSION" >"$VERSION_TMP"
mv "$OUTPUT_TMP" "$OUTPUT"
mv "$VERSION_TMP" "$VERSION_FILE"
trap - EXIT HUP INT TERM

printf ':: Upstream slirp4netns v%s ready: %s\n' "$SLIRP4NETNS_VERSION" "$OUTPUT"
printf ':: SHA-256: %s\n' "$SLIRP4NETNS_SHA256"
