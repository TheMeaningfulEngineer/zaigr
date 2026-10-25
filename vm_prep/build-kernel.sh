#!/bin/sh
# Build the minimal bzImage from kernel-src/ + cmd/zaigr/vm_data/miniconfig.
# Usage: vm_prep/build-kernel.sh [REPO_ROOT]
#
# The miniconfig hash is injected as CONFIG_LOCALVERSION so uname -r identifies
# the config. A sidecar build key also tracks the selected kernel source pin.
#
# Uses O= (out-of-tree build) to place build artifacts on tmpfs when the
# source tree is on a 9p mount. 9p without cache=mmap does not support
# mmap MAP_SHARED, which the kernel's sorttable linker step requires.
set -eu

REPO="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
REPO="$(cd "$REPO" && pwd)"
. "$REPO/deps.lock"
ZAIGR_EXTERNAL_SOURCES="${ZAIGR_EXTERNAL_SOURCES:-$HOME/.zaigr/external-sources}"
KERNEL_SRC="$ZAIGR_EXTERNAL_SOURCES/kernel-src-v${KERNEL_VERSION}-${KERNEL_COMMIT}"
MINICONFIG="$REPO/cmd/zaigr/vm_data/miniconfig"
BZIMAGE="$REPO/cmd/zaigr/vm_data/bzImage"

test -f "$MINICONFIG" || { echo "ERROR: $MINICONFIG not found" >&2; exit 1; }
command -v gcc >/dev/null 2>&1 || { echo "ERROR: gcc not found" >&2; exit 1; }
MC_VERSION="zaigr-$("$REPO/vm_prep/base-image-version.sh" "$REPO" | grep '^miniconfig:' | cut -d: -f2)"
VERSION_SCRIPT_HASH="$(sha256sum "$REPO/vm_prep/base-image-version.sh" | cut -d' ' -f1)"
BUILD_KEY_INPUT="$KERNEL_VERSION:$KERNEL_COMMIT:$(sha256sum "$MINICONFIG" | cut -d' ' -f1):$VERSION_SCRIPT_HASH:$(sha256sum "$0" | cut -d' ' -f1):$(gcc --version | head -1)"
BUILD_KEY="$(printf '%s' "$BUILD_KEY_INPUT" | sha256sum | cut -d' ' -f1)"
BUILD_KEY_FILE="$BZIMAGE.build-key"
echo ":: Kernel build key: $BUILD_KEY"

if [ -s "$BZIMAGE" ] && grep -Fxq "build_key=$BUILD_KEY" "$BUILD_KEY_FILE" 2>/dev/null; then
    EXPECTED_SHA="$(sed -n 's/^artifact_sha256=//p' "$BUILD_KEY_FILE")"
    ACTUAL_SHA="$(sha256sum "$BZIMAGE" | cut -d' ' -f1)"
    if [ -n "$EXPECTED_SHA" ] && [ "$EXPECTED_SHA" = "$ACTUAL_SHA" ]; then
        echo ":: bzImage already up to date ($MC_VERSION, kernel $KERNEL_VERSION), skipping build"
        exit 0
    fi
fi

if [ ! -d "$KERNEL_SRC" ]; then
    echo ":: Cloning kernel source ..."
    "$REPO/vm_prep/clone.sh" "$REPO"
fi
if [ "$(git -C "$KERNEL_SRC" remote get-url origin 2>/dev/null || true)" != "$KERNEL_URL" ]; then
    echo "ERROR: kernel source has an unexpected origin" >&2
    exit 1
fi
if [ "$(git -C "$KERNEL_SRC" rev-parse HEAD)" != "$KERNEL_COMMIT" ]; then
    echo "ERROR: kernel source is not pinned to $KERNEL_COMMIT; run clone.sh" >&2
    exit 1
fi
if [ -n "$(git -C "$KERNEL_SRC" status --porcelain --untracked-files=no)" ]; then
    echo "ERROR: tracked kernel source changes in $KERNEL_SRC; refusing to build" >&2
    exit 1
fi
for tool in make gcc flex bison bc; do
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
ARTIFACT_SHA="$(sha256sum "$BZIMAGE" | cut -d' ' -f1)"
printf 'build_key=%s\nartifact_sha256=%s\n' "$BUILD_KEY" "$ARTIFACT_SHA" > "$BUILD_KEY_FILE.tmp-$$"
mv "$BUILD_KEY_FILE.tmp-$$" "$BUILD_KEY_FILE"
if [ "$BUILD_DIR" != "$KERNEL_SRC" ]; then
    rm -rf "$BUILD_DIR"
fi

echo ":: bzImage ready: $BZIMAGE ($MC_VERSION)"
