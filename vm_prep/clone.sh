#!/bin/sh
# Clone the kernel source tree (shallow, single branch).
# Idempotent — skips if kernel-src/ already exists.
# Usage: vm_prep/clone.sh [REPO_ROOT]
set -eu

REPO="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
ZAIGR_EXTERNAL_SOURCES="${ZAIGR_EXTERNAL_SOURCES:-$HOME/.zaigr/external-sources}"
mkdir -p "$ZAIGR_EXTERNAL_SOURCES"
KERNEL_SRC="$ZAIGR_EXTERNAL_SOURCES/kernel-src"

if [ -d "$KERNEL_SRC" ]; then
    echo ":: kernel-src already exists, skipping clone"
    exit 0
fi

command -v git >/dev/null 2>&1 || { echo "ERROR: git not found" >&2; exit 1; }

echo ":: Cloning kernel v6.12 ..."
git clone --depth 1 --branch v6.12 \
    https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git \
    "$KERNEL_SRC"
