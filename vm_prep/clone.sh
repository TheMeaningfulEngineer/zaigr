#!/bin/sh
# Clone the kernel source tree (shallow, single branch).
# Idempotent — skips if kernel-src/ already exists.
# Usage: vm_prep/clone.sh [REPO_ROOT]
set -eu

REPO="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
REPO="$(cd "$REPO" && pwd)"
. "$REPO/deps.lock"
ZAIGR_EXTERNAL_SOURCES="${ZAIGR_EXTERNAL_SOURCES:-$HOME/.zaigr/external-sources}"
mkdir -p "$ZAIGR_EXTERNAL_SOURCES"
KERNEL_SRC="$ZAIGR_EXTERNAL_SOURCES/kernel-src-v${KERNEL_VERSION}-${KERNEL_COMMIT}"

if [ -d "$KERNEL_SRC" ]; then
    if [ "$(git -C "$KERNEL_SRC" remote get-url origin 2>/dev/null || true)" != "$KERNEL_URL" ]; then
        echo "ERROR: $KERNEL_SRC has an unexpected origin" >&2
        exit 1
    fi
    if [ -n "$(git -C "$KERNEL_SRC" status --porcelain --untracked-files=no)" ]; then
        echo "ERROR: tracked kernel source changes in $KERNEL_SRC; refusing to overwrite" >&2
        exit 1
    fi
    if [ "$(git -C "$KERNEL_SRC" rev-parse HEAD)" = "$KERNEL_COMMIT" ]; then
        echo ":: kernel source already at $KERNEL_VERSION, skipping clone"
        exit 0
    fi
    echo "ERROR: $KERNEL_SRC is not pinned to $KERNEL_COMMIT; refusing to overwrite" >&2
    exit 1
fi

command -v git >/dev/null 2>&1 || { echo "ERROR: git not found" >&2; exit 1; }

echo ":: Cloning kernel $KERNEL_VERSION ..."
git clone --depth 1 --branch "$KERNEL_TAG" "$KERNEL_URL" "$KERNEL_SRC"
if [ "$(git -C "$KERNEL_SRC" rev-parse HEAD)" != "$KERNEL_COMMIT" ]; then
    echo "ERROR: kernel tag $KERNEL_TAG resolved to an unexpected commit" >&2
    exit 1
fi
