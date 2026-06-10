#!/bin/sh
# Build the minimal bzImage from kernel-src/ + cmd/zaigr/vm_data/miniconfig.
# Usage: vm_prep/build-kernel.sh [REPO_ROOT]
#
# The miniconfig hash is injected as CONFIG_LOCALVERSION so that uname -r
# shows which miniconfig produced the kernel (e.g. 6.12.0-zaigr-a1b2c3d).
# If a bzImage exists but its version doesn't match the current hash, it
# gets rebuilt automatically.
#
# Uses O= (out-of-tree build) to place build artifacts on tmpfs when the
# source tree is on a 9p mount. 9p without cache=mmap does not support
# mmap MAP_SHARED, which the kernel's sorttable linker step requires.
set -eu

REPO="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
ZAIGR_EXTERNAL_SOURCES="${ZAIGR_EXTERNAL_SOURCES:-$HOME/.zaigr/external-sources}"
KERNEL_SRC="$ZAIGR_EXTERNAL_SOURCES/kernel-src"
MINICONFIG="$REPO/cmd/zaigr/vm_data/miniconfig"
BZIMAGE="$REPO/cmd/zaigr/vm_data/bzImage"

# Get kernel version from the single source of truth
MC_VERSION="zaigr-$("$REPO/vm_prep/base-image-version.sh" "$REPO" | grep '^miniconfig:' | cut -d: -f2)"
echo ":: Miniconfig version: $MC_VERSION"

# Check if existing bzImage already matches
if [ -f "$BZIMAGE" ]; then
    if strings "$BZIMAGE" | grep -q "$MC_VERSION"; then
        echo ":: bzImage already up to date ($MC_VERSION), skipping build"
        exit 0
    fi
    echo ":: bzImage exists but doesn't match miniconfig, rebuilding"
    rm -f "$BZIMAGE"
fi

if [ ! -d "$KERNEL_SRC" ]; then
    echo ":: Cloning kernel source ..."
    "$REPO/vm_prep/clone.sh" "$REPO"
fi
test -f "$MINICONFIG" || { echo "ERROR: $MINICONFIG not found" >&2; exit 1; }

for tool in make gcc flex bison bc strings; do
    command -v "$tool" >/dev/null 2>&1 || { echo "ERROR: $tool not found" >&2; exit 1; }
done

kernel_make() {
    env \
        -u VERSION \
        -u BUILD \
        -u COMMIT \
        -u BUILD_TIME \
        -u PATCHLEVEL \
        -u SUBLEVEL \
        -u EXTRAVERSION \
        -u LOCALVERSION \
        -u KBUILD_BUILD_VERSION \
        -u MAKEFLAGS \
        make -C "$KERNEL_SRC" "$@"
}

# Build a temp miniconfig with the version injected
BUILD_MINICONFIG=$(mktemp)
trap 'rm -f "$BUILD_MINICONFIG"' EXIT
cat "$MINICONFIG" > "$BUILD_MINICONFIG"
echo "CONFIG_LOCALVERSION=\"-${MC_VERSION}\"" >> "$BUILD_MINICONFIG"

# Detect whether the source tree supports mmap MAP_SHARED (needed by
# the kernel's sorttable linker step). 9p mounts without cache=mmap
# do not support this, so we build out-of-tree on tmpfs instead.
BUILD_DIR="$KERNEL_SRC"
OUTDIR_FLAG=""
_test_file=$(mktemp "$KERNEL_SRC/.mmap_test.XXXXXX")
if ! python3 -c "
import mmap
with open('$_test_file', 'r+b') as f:
    f.write(b'x' * 4096)
    f.flush()
    mmap.mmap(f.fileno(), 4096, mmap.MAP_SHARED, mmap.PROT_READ|mmap.PROT_WRITE).close()
" 2>/dev/null; then
    BUILD_DIR=$(mktemp -d /tmp/kernel-build.XXXXXX)
    OUTDIR_FLAG="O=$BUILD_DIR"
    echo ":: 9p detected without mmap support, building out-of-tree in $BUILD_DIR"
fi
rm -f "$_test_file"

echo ":: Building kernel ..."
export ARCH=x86_64

# Clean in-tree build artifacts when using out-of-tree build
if [ -n "$OUTDIR_FLAG" ]; then
    echo ":: Cleaning source tree (mrproper) for out-of-tree build ..."
    kernel_make mrproper
fi

echo ":: Configuring kernel (allnoconfig + miniconfig) ..."
if ! kernel_make $OUTDIR_FLAG KCONFIG_ALLCONFIG="$BUILD_MINICONFIG" allnoconfig; then
    echo "ERROR: 'make allnoconfig' failed. Check that kernel-src is a valid kernel tree." >&2
    exit 1
fi

echo ":: Compiling bzImage ($(nproc) jobs) ..."
if ! kernel_make $OUTDIR_FLAG -j"$(nproc)" bzImage; then
    echo "ERROR: Kernel build failed. Check output above for missing dependencies." >&2
    echo "       Common fixes: apt-get install build-essential flex bison bc libelf-dev libssl-dev" >&2
    exit 1
fi

# Copy result to vm_data (the only location that matters — go:embed reads from here)
OUT_BZIMAGE="$BUILD_DIR/arch/x86/boot/bzImage"
cp "$OUT_BZIMAGE" "$BZIMAGE"
if [ "$BUILD_DIR" != "$KERNEL_SRC" ]; then
    rm -rf "$BUILD_DIR"
fi

echo ":: bzImage ready: $BZIMAGE ($MC_VERSION)"
