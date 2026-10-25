#!/bin/sh
# Print the base image versions computed from the current sources.
# Usage: vm_prep/base-image-version.sh [REPO_ROOT]
set -eu

REPO="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
BB="$REPO/vm_prep/base-image-building-blocks"
MINICONFIG="$REPO/cmd/zaigr/vm_data/miniconfig"
. "$REPO/deps.lock"

if [ -z "${DEBIAN_SUITE:-}" ]; then
    echo "ERROR: DEBIAN_SUITE is missing from $REPO/deps.lock" >&2
    exit 1
fi

MINICONFIG_VERSION="$(sha256sum "$MINICONFIG" | cut -c1-7)"
BUILDING_BLOCKS_VERSION="$(
    (
        printf 'DEBIAN_SUITE=%s\n' "$DEBIAN_SUITE"
        cd "$BB"
        find . -type f -print | LC_ALL=C sort | while IFS= read -r file; do
            printf '%s\n' "$file"
            cat "$file"
            printf '\n'
        done
    ) | sha256sum | cut -c1-7
)"

echo "miniconfig:$MINICONFIG_VERSION"
echo "building-blocks:$BUILDING_BLOCKS_VERSION"
echo "base-image:$MINICONFIG_VERSION-$BUILDING_BLOCKS_VERSION"
