#!/bin/sh
# Build the base image rootfs. Called by vm_prep/build-base-rootfs.sh
# after it determines a rebuild is needed.
# Usage: build.sh REPO_ROOT BASE_VERSION
# Requires: mmdebstrap, fakeroot, zstd, curl.
set -eu

REPO="$1"
BASE_VERSION="$2"
. "$REPO/deps.lock"
if [ -z "${DEBIAN_SUITE:-}" ]; then
    echo "ERROR: DEBIAN_SUITE is missing from $REPO/deps.lock" >&2
    exit 1
fi
BB="$(cd "$(dirname "$0")" && pwd)"
ROOTFS_TAR="$REPO/.cache/base-rootfs.tar"
ROOTFS_IMG="$REPO/.cache/base-rootfs.img"
ROOTFS_ZST="$REPO/cmd/zaigr/vm_data/base-rootfs.img.zst"
MERGED_USR_HOOKS="/usr/share/mmdebstrap/hooks/merged-usr"
FILE_MIRROR_HOOKS="/usr/share/mmdebstrap/hooks/file-mirror-automount"

for tool in mmdebstrap fakeroot zstd curl; do
    command -v "$tool" >/dev/null 2>&1 || { echo "ERROR: $tool not found" >&2; exit 1; }
done

test -d "$MERGED_USR_HOOKS" || { echo "ERROR: mmdebstrap merged-/usr hooks not found: $MERGED_USR_HOOKS" >&2; exit 1; }
test -d "$FILE_MIRROR_HOOKS" || { echo "ERROR: mmdebstrap file mirror hooks not found: $FILE_MIRROR_HOOKS" >&2; exit 1; }

mkdir -p "$(dirname "$ROOTFS_ZST")" "$(dirname "$ROOTFS_IMG")"

ROOTFS_DIR=$(mktemp -d)
trap 'rm -rf "$ROOTFS_DIR" "$ROOTFS_TAR" "$ROOTFS_IMG"' EXIT

# Generate a random root password — only the hash enters the image
ROOT_PW=$(openssl rand -hex 16)

echo ":: Building base image rootfs (mmdebstrap) ..."

# Minimal packages — just enough to boot systemd, run a shell, and network.
# systemd-sysv is intentionally omitted because QEMU boots systemd explicitly.
PACKAGES="bash,bash-completion,coreutils,mount,procps,iproute2,conntrack,util-linux,e2fsprogs,systemd"
PACKAGES="$PACKAGES,ca-certificates,curl,openssh-server"

mmdebstrap \
    --mode=unshare \
    --variant=minbase \
    --aptopt='Apt::Install-Recommends "false"' \
    --skip=cleanup/apt/lists \
    --hook-dir="$MERGED_USR_HOOKS" \
    --hook-dir="$FILE_MIRROR_HOOKS" \
    --include="$PACKAGES" \
    --customize-hook='test "$(readlink "$1/bin")" = usr/bin' \
    --customize-hook='test "$(readlink "$1/sbin")" = usr/sbin' \
    --customize-hook='test "$(readlink "$1/lib")" = usr/lib' \
    --customize-hook='chroot "$1" test -x /usr/lib/systemd/systemd' \
    --customize-hook='for pkg in dbus udev systemd-sysv; do if chroot "$1" dpkg-query -W -f="\${Status}" "$pkg" 2>/dev/null | grep -q "install ok installed"; then echo "ERROR: prohibited package installed: $pkg" >&2; exit 1; fi; done' \
    --customize-hook='chroot "$1" groupadd -f kvm' \
    --customize-hook='chroot "$1" useradd -m -s /bin/bash -G kvm user' \
    --customize-hook='mkdir -p "$1/home/user/workspace"' \
    --customize-hook='chroot "$1" chown user:user /home/user/workspace' \
    --customize-hook='printf "export PATH=\"\$HOME/.local/bin:\$PATH\"\ncd ~/workspace 2>/dev/null\n" >> "$1/home/user/.bashrc"' \
    --customize-hook='chroot "$1" passwd -l user' \
    --customize-hook="echo 'root:$ROOT_PW' | chroot \"\$1\" chpasswd" \
    --customize-hook='rm -rf "$1"/var/cache/apt/archives/*.deb' \
    --customize-hook='rm -rf "$1"/usr/share/doc/*' \
    --customize-hook='rm -rf "$1"/usr/share/man/*' \
    --customize-hook='rm -rf "$1"/usr/share/locale/*' \
    "$DEBIAN_SUITE" "$ROOTFS_TAR" http://deb.debian.org/debian

echo ":: Unpacking and finalizing rootfs ..."

fakeroot sh -c "
    tar -xf \"$ROOTFS_TAR\" -C \"$ROOTFS_DIR\"

    for overlay_dir in \"$BB\"/*; do
        [ -d \"\$overlay_dir\" ] || continue
        overlay_name=\$(basename \"\$overlay_dir\")
        mkdir -p \"$ROOTFS_DIR/\$overlay_name\"
        cp -r \"\$overlay_dir/.\" \"$ROOTFS_DIR/\$overlay_name/\"
    done

    chown root:root \"$ROOTFS_DIR/usr/local/lib/zaigr/run-preset-isolated\"
    chmod 0700 \"$ROOTFS_DIR/usr/local/lib/zaigr/run-preset-isolated\"

    mkdir -p \"$ROOTFS_DIR/etc/systemd/system/sockets.target.wants\"
    mkdir -p \"$ROOTFS_DIR/etc/systemd/system\"

    ln -sfn /dev/null \"$ROOTFS_DIR/etc/systemd/system/ssh.service\"
    ln -sfn /dev/null \"$ROOTFS_DIR/etc/systemd/system/ssh.socket\"
    ln -sfn /etc/systemd/system/ssh-vsock.socket \"$ROOTFS_DIR/etc/systemd/system/sockets.target.wants/ssh-vsock.socket\"

    echo \"base-image:$BASE_VERSION\" > \"$ROOTFS_DIR/etc/base-image-version\"
    chmod 644 \"$ROOTFS_DIR/etc/base-image-version\"

    SIZE_KB=\$(du -sk \"$ROOTFS_DIR\" | awk '{print \$1}')
    SIZE_KB=\$(( SIZE_KB * 120 / 100 ))
    echo \":: Packing rootfs.img (ext4, \${SIZE_KB}K) ...\"
    /sbin/mkfs.ext4 -q -O ^orphan_file -d \"$ROOTFS_DIR\" \"$ROOTFS_IMG\" \"\${SIZE_KB}K\"
"

echo ":: Compressing with zstd ..."
zstd -1 --rm -f -o "$ROOTFS_ZST" "$ROOTFS_IMG"

SIZE=$(ls -lh "$ROOTFS_ZST" | awk '{print $5}')
echo ":: base-rootfs.img.zst ready ($SIZE, version: $BASE_VERSION)"
echo ":: Guest SSH is available only through zaigr's vsock control channel"
