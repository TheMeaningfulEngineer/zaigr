#!/bin/sh
# Build a static musl virtiofsd binary for embedding in zaigr.
# Usage: vm_prep/build-virtiofsd.sh [REPO_ROOT]
#
# Produces cmd/zaigr/vm_data/virtiofsd — a static x86_64 musl binary.
# Requires: git, rustc/cargo (x86_64-unknown-linux-musl target), x86_64-linux-musl-gcc,
#           gperf (any host version), make, ar, readelf, sha256sum.
#
# Native dependencies (libcap-ng, libseccomp) are built from source for musl
# and stored under $ZAIGR_EXTERNAL_SOURCES/virtiofsd-native-deps/. They are
# rebuilt when the pinned versions or this script change.
#
# Version pin: cmd/zaigr/vm_data/virtiofsd.version (currently 1.13.2).
# Source commit pin: 720245d0857e9837484488ff69c2f8c577466851 (v1.13.2 tag target commit;
#   tag object fd21b60ec99703bbfea23a8eb39ff2065f358e78).
# libcap-ng version: 0.8.5 (from deb.debian.org/debian/pool/main/libc/libcap-ng/).
# libseccomp version: 2.6.0 (from github.com/seccomp/libseccomp/releases).
#
# Build cache key (stored in $ZAIGR_EXTERNAL_SOURCES/virtiofsd-build-state/):
#   virtiofsd source commit + Cargo.lock hash + this script hash +
#   target (x86_64-unknown-linux-musl) + rustc version + native dep recipe hash.
# MUST NOT use `strings` to detect version in an existing binary.
set -eu

REPO="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
ZAIGR_EXTERNAL_SOURCES="${ZAIGR_EXTERNAL_SOURCES:-$HOME/.zaigr/external-sources}"

# Resolve all paths before changing directories.
REPO="$(cd "$REPO" && pwd)"
mkdir -p "$ZAIGR_EXTERNAL_SOURCES"
ZAIGR_EXTERNAL_SOURCES="$(cd "$ZAIGR_EXTERNAL_SOURCES" && pwd)"
VIRTIOFSD_SRC="$ZAIGR_EXTERNAL_SOURCES/virtiofsd-src"
NATIVE_DEPS="$ZAIGR_EXTERNAL_SOURCES/virtiofsd-native-deps"
BUILD_STATE="$ZAIGR_EXTERNAL_SOURCES/virtiofsd-build-state"
OUTPUT="$REPO/cmd/zaigr/vm_data/virtiofsd"
VERSION_FILE="$REPO/cmd/zaigr/vm_data/virtiofsd.version"

if [ ! -f "$VERSION_FILE" ]; then
    printf 'ERROR: %s not found\n' "$VERSION_FILE" >&2
    exit 1
fi
VERSION="$(cat "$VERSION_FILE")"
if [ "$VERSION" != "1.13.2" ] || [ "$(wc -c < "$VERSION_FILE")" -ne 7 ]; then
    printf 'ERROR: expected exactly 1.13.2 and newline in %s\n' "$VERSION_FILE" >&2
    exit 1
fi
# Pinned upstream commit for v1.13.2 (the commit the annotated tag points to;
# the tag object itself is fd21b60ec99703bbfea23a8eb39ff2065f358e78):
PINNED_COMMIT="720245d0857e9837484488ff69c2f8c577466851"

LIBCAP_NG_VERSION="0.8.5"
LIBSECCOMP_VERSION="2.6.0"
LIBCAP_NG_SHA256="e4be07fdd234f10b866433f224d183626003c65634ed0552b02e654a380244c2"
LIBSECCOMP_SHA256="83b6085232d1588c379dc9b9cae47bb37407cf262e6e74993c61ba72d2a784dc"
TARGET="x86_64-unknown-linux-musl"

printf ':: virtiofsd version: %s\n' "$VERSION"

# If RUSTUP_HOME is unset and the known location exists, set it. Do not
# overwrite an explicit caller setting and do not install tools.
if [ -z "${RUSTUP_HOME:-}" ] && [ -d "/usr/local/rustup" ]; then
    RUSTUP_HOME=/usr/local/rustup
    export RUSTUP_HOME
fi

# Fail early for missing tools.
for tool in git cargo rustc rustup x86_64-linux-musl-gcc pkg-config make strip readelf ar sha256sum curl tar gperf; do
    command -v "$tool" >/dev/null 2>&1 || { printf 'ERROR: %s not found in PATH\n' "$tool" >&2; exit 1; }
done
rustup target list --installed 2>/dev/null | grep -qx "$TARGET" || \
    { printf 'ERROR: Rust target %s is not installed; install it with rustup target add %s\n' "$TARGET" "$TARGET" >&2; exit 1; }

# Check that gperf is available (needed to build libseccomp from source).
command -v gperf >/dev/null 2>&1 || { printf 'ERROR: gperf not found in PATH\n' >&2; exit 1; }

# --- Native dependency recipe hash (for cache invalidation) ---
# Hash this script itself plus the pinned dependency versions.
SCRIPT_HASH="$(sha256sum "$0" | cut -d' ' -f1)"
RECIPE_INPUT="${LIBCAP_NG_VERSION}:${LIBCAP_NG_SHA256}:${LIBSECCOMP_VERSION}:${LIBSECCOMP_SHA256}:${SCRIPT_HASH}:$(x86_64-linux-musl-gcc --version | head -1):$(sha256sum /usr/include/linux/audit.h /usr/include/linux/seccomp.h | sha256sum | cut -d' ' -f1)"
RECIPE_HASH="$(printf '%s' "$RECIPE_INPUT" | sha256sum | cut -d' ' -f1)"
# Native source, object files, and installed libraries are isolated by the
# complete recipe. A compiler/header change must never reuse old .o/.lo files.
NATIVE_DEPS="$NATIVE_DEPS/$RECIPE_HASH"

# --- Step 1: Clone/verify virtiofsd source ---
printf ':: Checking virtiofsd source...\n'
mkdir -p "$(dirname "$VIRTIOFSD_SRC")"
if [ -d "$VIRTIOFSD_SRC" ]; then
    # Verify it's a valid git repo with the expected remote.
    if [ "$(git -C "$VIRTIOFSD_SRC" remote get-url origin 2>/dev/null)" != "https://gitlab.com/virtio-fs/virtiofsd.git" ]; then
        printf 'ERROR: %s exists but has unexpected origin; remove it manually\n' "$VIRTIOFSD_SRC" >&2
        exit 1
    fi
    # Check for local modifications.
    if [ -n "$(git -C "$VIRTIOFSD_SRC" status --porcelain --untracked-files=normal)" ]; then
        printf 'ERROR: virtiofsd source at %s has local modifications; refusing to overwrite\n' "$VIRTIOFSD_SRC" >&2
        exit 1
    fi
    # Fetch if the pinned commit is not present.
    if ! git -C "$VIRTIOFSD_SRC" cat-file -e "${PINNED_COMMIT}^{commit}" 2>/dev/null; then
        printf ':: Fetching virtiofsd tag v%s...\n' "$VERSION"
        git -C "$VIRTIOFSD_SRC" fetch --depth=1 origin "refs/tags/v${VERSION}" 2>&1
    fi
else
    printf ':: Cloning virtiofsd v%s...\n' "$VERSION"
    git clone --depth=1 --branch "v${VERSION}" \
        "https://gitlab.com/virtio-fs/virtiofsd.git" "$VIRTIOFSD_SRC" 2>&1
fi

# Verify the tag resolves to the pinned commit.
ACTUAL_COMMIT="$(git -C "$VIRTIOFSD_SRC" rev-list -n1 "v${VERSION}" 2>/dev/null)"
if [ "$ACTUAL_COMMIT" != "$PINNED_COMMIT" ]; then
    printf 'ERROR: tag v%s resolves to %s, expected %s\n' \
        "$VERSION" "$ACTUAL_COMMIT" "$PINNED_COMMIT" >&2
    exit 1
fi
printf ':: Source commit verified: %s\n' "$PINNED_COMMIT"

# Check out the pinned commit.
git -C "$VIRTIOFSD_SRC" checkout "$PINNED_COMMIT" --quiet 2>&1

# --- Step 2: Build cache key ---
CARGO_LOCK_HASH="$(sha256sum "$VIRTIOFSD_SRC/Cargo.lock" | cut -d' ' -f1)"
RUSTC_VERSION="$(rustc --version | tr ' ' '-')"
CACHE_KEY="${PINNED_COMMIT}:${CARGO_LOCK_HASH}:${SCRIPT_HASH}:${TARGET}:${RUSTC_VERSION}:$(x86_64-linux-musl-gcc --version | head -1):${RECIPE_HASH}"
CACHE_KEY_HASH="$(printf '%s' "$CACHE_KEY" | sha256sum | cut -d' ' -f1)"

CACHE_DIR="$BUILD_STATE/build-${CACHE_KEY_HASH}"
CACHE_KEY_FILE="$CACHE_DIR/cache-key.txt"
NATIVE_DEPS_READY="$NATIVE_DEPS/ready-${RECIPE_HASH}"

printf ':: Build cache key: %s\n' "$CACHE_KEY_HASH"

# --- Step 3: Build native dependencies (libcap-ng + libseccomp) for musl ---
if [ ! -f "$NATIVE_DEPS_READY" ] || [ ! -s "$NATIVE_DEPS/dist/lib/libcap-ng.a" ] || [ ! -s "$NATIVE_DEPS/dist/lib/libseccomp.a" ]; then
    printf ':: Building native musl dependencies...\n'
    mkdir -p "$NATIVE_DEPS/src" "$NATIVE_DEPS/dist/lib" "$NATIVE_DEPS/dist/include"

    # Create a minimal kernel headers directory for musl builds.
    # Uses the host's linux-libc-dev headers for asm/unistd.h etc.
    # These are C API headers only; no glibc runtime is pulled in.
    KERNEL_HEADERS="$NATIVE_DEPS/kernel-headers"
    mkdir -p "$KERNEL_HEADERS"
    if [ ! -L "$KERNEL_HEADERS/asm" ]; then
        ln -s /usr/include/x86_64-linux-gnu/asm "$KERNEL_HEADERS/asm"
    fi
    if [ ! -L "$KERNEL_HEADERS/linux" ]; then
        ln -s /usr/include/linux "$KERNEL_HEADERS/linux"
    fi
    if [ ! -L "$KERNEL_HEADERS/asm-generic" ]; then
        ln -s /usr/include/asm-generic "$KERNEL_HEADERS/asm-generic"
    fi

    # ---- libcap-ng 0.8.5 ----
    # Downloaded from deb.debian.org as a release tarball with pre-generated configure.
    CAPNG_TAR="$NATIVE_DEPS/src/libcap-ng-debian-${LIBCAP_NG_VERSION}.tar.gz"
    CAPNG_SRC="$NATIVE_DEPS/src/libcap-ng-${LIBCAP_NG_VERSION}"
    CAPNG_BUILD="$NATIVE_DEPS/src/libcap-ng-build"
    if [ ! -f "$CAPNG_TAR" ]; then
        printf ':: Downloading libcap-ng %s...\n' "$LIBCAP_NG_VERSION"
        curl -L --retry 3 --max-time 120 -o "$CAPNG_TAR" \
            "https://deb.debian.org/debian/pool/main/libc/libcap-ng/libcap-ng_${LIBCAP_NG_VERSION}.orig.tar.gz"
    fi
    printf '%s  %s\n' "$LIBCAP_NG_SHA256" "$CAPNG_TAR" | sha256sum -c - >/dev/null
    if [ ! -d "$CAPNG_SRC" ]; then
        tar xzf "$CAPNG_TAR" -C "$NATIVE_DEPS/src/"
    fi

    # libcap-ng uses stdio_ext.h (glibc-only). Provide musl-compatible stubs.
    # The library functionality is preserved; __fsetlocking is a locking hint
    # that musl handles internally. Stubs are not patching functionality.
    mkdir -p "$CAPNG_BUILD"
    cat > "$CAPNG_BUILD/stdio_ext.h" << 'STUB_EOF'
/* Stub stdio_ext.h for musl builds - __fsetlocking is a no-op hint */
#ifndef _STDIO_EXT_H
#define _STDIO_EXT_H
#define FSETLOCKING_QUERY    0
#define FSETLOCKING_INTERNAL 1
#define FSETLOCKING_BYCALLER 2
static inline int __fsetlocking(void *f, int type) { (void)f; (void)type; return FSETLOCKING_BYCALLER; }
#endif
STUB_EOF

    # Minimal config.h with features available in musl.
    cat > "$CAPNG_BUILD/config.h" << 'CONFIG_EOF'
/* config.h for libcap-ng 0.8.5 static musl build */
#define PACKAGE_NAME "libcap-ng"
#define PACKAGE_VERSION "0.8.5"
#define PACKAGE_STRING "libcap-ng 0.8.5"
#define _GNU_SOURCE 1
#define HAVE_SYSCALL_H 1
#define HAVE_LINUX_SECUREBITS_H 1
#define HAVE_LINUX_MAGIC_H 1
#define HAVE_SYS_XATTR_H 1
CONFIG_EOF

    for src in cap-ng.c lookup_table.c libdrop_ambient.c; do
        x86_64-linux-musl-gcc \
            -I "$CAPNG_BUILD" \
            -I "$CAPNG_SRC/src" \
            -I "$KERNEL_HEADERS" \
            -O2 -fPIC \
            -c "$CAPNG_SRC/src/$src" \
            -o "$CAPNG_BUILD/$(basename "$src" .c).o"
    done
    ar rcs "$NATIVE_DEPS/dist/lib/libcap-ng.a" \
        "$CAPNG_BUILD/cap-ng.o" \
        "$CAPNG_BUILD/lookup_table.o" \
        "$CAPNG_BUILD/libdrop_ambient.o"
    cp "$CAPNG_SRC/src/cap-ng.h" "$NATIVE_DEPS/dist/include/"
    printf ':: libcap-ng.a built\n'

    # ---- libseccomp 2.6.0 ----
    # Downloaded as release tarball (has pre-generated configure script and
    # pre-generated syscalls.perf.c so gperf is only needed to satisfy configure).
    SECCOMP_TAR="$NATIVE_DEPS/src/libseccomp-${LIBSECCOMP_VERSION}.tar.gz"
    SECCOMP_SRC="$NATIVE_DEPS/src/libseccomp-${LIBSECCOMP_VERSION}"
    if [ ! -f "$SECCOMP_TAR" ]; then
        printf ':: Downloading libseccomp %s...\n' "$LIBSECCOMP_VERSION"
        curl -L --retry 3 --max-time 120 -o "$SECCOMP_TAR" \
            "https://github.com/seccomp/libseccomp/releases/download/v${LIBSECCOMP_VERSION}/libseccomp-${LIBSECCOMP_VERSION}.tar.gz"
    fi
    printf '%s  %s\n' "$LIBSECCOMP_SHA256" "$SECCOMP_TAR" | sha256sum -c - >/dev/null
    if [ ! -d "$SECCOMP_SRC" ]; then
        tar xzf "$SECCOMP_TAR" -C "$NATIVE_DEPS/src/"
    fi

    cd "$SECCOMP_SRC"
    # libseccomp's configure requires gperf but the release tarball has
    # syscalls.perf.c pre-generated; gperf is not invoked during the actual build.
    ./configure \
        CC=x86_64-linux-musl-gcc \
        CPPFLAGS="-I $KERNEL_HEADERS" \
        --host=x86_64-linux-musl \
        --prefix="$NATIVE_DEPS/dist" \
        --enable-static \
        --disable-shared \
        2>&1
    make -C src libseccomp.la 2>&1
    make -C include install 2>&1
    make -C src install-libLTLIBRARIES 2>&1
    cd "$REPO"

    # Record that native deps are ready for this recipe.
    rm -f "$NATIVE_DEPS/ready-"*
    touch "$NATIVE_DEPS_READY"
    printf ':: Native musl dependencies built and installed\n'
else
    printf ':: Native musl dependencies cached (recipe %s)\n' "$(printf '%s' "$RECIPE_HASH" | cut -c1-12)"
fi

# The build cache reuses Cargo outputs, but every invocation validates and
# republishes the artifact. A cache key is never sufficient proof of linkage.

# --- Step 5: Build virtiofsd ---
printf ':: Building virtiofsd v%s for %s...\n' "$VERSION" "$TARGET"

mkdir -p "$CACHE_DIR"

cd "$VIRTIOFSD_SRC"

export CC=x86_64-linux-musl-gcc
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-linux-musl-gcc
export LIBCAPNG_LIB_PATH="$NATIVE_DEPS/dist/lib"
export LIBCAPNG_LINK_TYPE=static
export LIBSECCOMP_LIB_PATH="$NATIVE_DEPS/dist/lib"
export LIBSECCOMP_LINK_TYPE=static
# Provide include path for native dependency headers.
export CFLAGS="-I $NATIVE_DEPS/dist/include -I $NATIVE_DEPS/kernel-headers"

CARGO_TARGET_DIR="$CACHE_DIR/target" \
    cargo build --release --locked --target "$TARGET" 2>&1

BUILT="$CACHE_DIR/target/$TARGET/release/virtiofsd"
if [ ! -f "$BUILT" ]; then
    printf 'ERROR: expected output not found at %s\n' "$BUILT" >&2
    exit 1
fi

cd "$REPO"

# --- Step 6: Validate and publish ---
STRIPPED="$CACHE_DIR/virtiofsd.stripped"
cp "$BUILT" "$STRIPPED"
strip "$STRIPPED"

# Check version string.
ACTUAL_VERSION="$("$STRIPPED" --version 2>&1 | head -1 | grep -o '[0-9]*\.[0-9]*\.[0-9]*' | head -1)"
if [ "$ACTUAL_VERSION" != "$VERSION" ]; then
    printf 'ERROR: binary reports version %s, expected %s\n' "$ACTUAL_VERSION" "$VERSION" >&2
    rm -f "$STRIPPED"
    exit 1
fi

# Check ELF architecture.
ARCH="$(readelf -h "$STRIPPED" | grep 'Machine:' | grep -o 'X86-64')"
if [ "$ARCH" != "X86-64" ]; then
    printf 'ERROR: binary is not x86-64 (got: %s)\n' "$(readelf -h "$STRIPPED" | grep Machine)" >&2
    rm -f "$STRIPPED"
    exit 1
fi

# Verify no INTERP segment (no dynamic linker required).
if readelf -l "$STRIPPED" | grep -q "INTERP"; then
    printf 'ERROR: binary has an INTERP segment (not statically linked)\n' >&2
    readelf -l "$STRIPPED" | grep -E "Type|INTERP" >&2
    rm -f "$STRIPPED"
    exit 1
fi

# Verify no NEEDED entries (no shared library dependencies).
if readelf -d "$STRIPPED" 2>/dev/null | grep -q "(NEEDED)"; then
    printf 'ERROR: binary has NEEDED dynamic library entries\n' >&2
    readelf -d "$STRIPPED" | grep "NEEDED" >&2
    rm -f "$STRIPPED"
    exit 1
fi

# Record artifact hash and cache key.
ARTIFACT_SHA256="$(sha256sum "$STRIPPED" | cut -d' ' -f1)"
cat > "$CACHE_DIR/build-record.txt" << RECORD_EOF
version=$VERSION
source_commit=$PINNED_COMMIT
cache_key=$CACHE_KEY
artifact_sha256=$ARTIFACT_SHA256
rustc_version=$RUSTC_VERSION
libcap_ng_version=$LIBCAP_NG_VERSION
libseccomp_version=$LIBSECCOMP_VERSION
target=$TARGET
RECORD_EOF

printf '%s' "$CACHE_KEY" > "$CACHE_KEY_FILE"

# Atomic rename to output path. A failed build cannot replace the last valid artifact.
mkdir -p "$(dirname "$OUTPUT")"
mv "$STRIPPED" "${OUTPUT}.tmp-$$"
mv "${OUTPUT}.tmp-$$" "$OUTPUT"

printf ':: virtiofsd v%s built: %s\n' "$VERSION" "$OUTPUT"
printf ':: SHA-256: %s\n' "$ARTIFACT_SHA256"
printf ':: Build record: %s\n' "$CACHE_DIR/build-record.txt"
