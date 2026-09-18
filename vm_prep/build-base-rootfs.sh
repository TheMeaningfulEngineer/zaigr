#!/bin/sh
# Build the base image rootfs if the building blocks have changed.
# Usage: vm_prep/build-base-rootfs.sh [REPO_ROOT]
set -eu

REPO="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
BB="$REPO/vm_prep/base-image-building-blocks"
ROOTFS_ZST="$REPO/cmd/zaigr/vm_data/base-rootfs.img.zst"

# Get the base image version from the single source of truth. This combines
# kernel miniconfig and rootfs building blocks because both define image compatibility.
BASE_VERSION=$("$REPO/vm_prep/base-image-version.sh" "$REPO" | grep '^base-image:' | cut -d: -f2)
echo ":: Base image version: $BASE_VERSION"

VERSION_FILE="$REPO/cmd/zaigr/vm_data/base-rootfs.version"

# Check if existing rootfs already matches
if [ -f "$ROOTFS_ZST" ] && [ -f "$VERSION_FILE" ]; then
    if [ "$(cat "$VERSION_FILE")" = "$BASE_VERSION" ]; then
        echo ":: base-rootfs.img.zst already up to date ($BASE_VERSION), skipping"
        exit 0
    fi
    echo ":: base-rootfs.img.zst is stale, rebuilding"
    rm -f "$ROOTFS_ZST"
fi

"$BB/build.sh" "$REPO" "$BASE_VERSION"
echo "$BASE_VERSION" > "$VERSION_FILE"
