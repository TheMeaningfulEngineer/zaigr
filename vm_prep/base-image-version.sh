#!/bin/sh
# Print the base image versions computed from the current sources.
# Usage: vm_prep/base-image-version.sh [REPO_ROOT]
set -eu

REPO="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
BB="$REPO/vm_prep/base-image-building-blocks"
MINICONFIG="$REPO/cmd/zaigr/vm_data/miniconfig"

MINICONFIG_VERSION="$(sha256sum "$MINICONFIG" | cut -c1-7)"
BUILDING_BLOCKS_VERSION="$(
    (
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
