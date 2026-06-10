#!/bin/sh
# Build the base image rootfs. Called by vm_prep/build-base-rootfs.sh
# after it determines a rebuild is needed.
# Usage: build.sh REPO_ROOT BASE_VERSION
# Requires: mmdebstrap, fakeroot, zstd, curl.
set -eu

REPO="$1"
BASE_VERSION="$2"
BB="$(cd "$(dirname "$0")" && pwd)"
ROOTFS_TAR="$REPO/.cache/base-rootfs.tar"
ROOTFS_IMG="$REPO/.cache/base-rootfs.img"
ROOTFS_ZST="$REPO/cmd/zaigr/vm_data/base-rootfs.img.zst"
ZAIGR_INSIDE_SCRIPT="$BB/zaigr-inside"
ALLOWED_HOSTS="$BB/allowed-hosts.txt"

OPENSNITCH_VER="1.8.0"
OPENSNITCH_DEB="opensnitch_${OPENSNITCH_VER}-1_amd64.deb"
OPENSNITCH_URL="https://github.com/evilsocket/opensnitch/releases/download/v$OPENSNITCH_VER/$OPENSNITCH_DEB"

for tool in mmdebstrap fakeroot zstd curl; do
    command -v "$tool" >/dev/null 2>&1 || { echo "ERROR: $tool not found" >&2; exit 1; }
done

test -f "$ZAIGR_INSIDE_SCRIPT" || { echo "ERROR: $ZAIGR_INSIDE_SCRIPT not found" >&2; exit 1; }
test -f "$ALLOWED_HOSTS" || { echo "ERROR: $ALLOWED_HOSTS not found" >&2; exit 1; }

mkdir -p "$(dirname "$ROOTFS_ZST")" "$(dirname "$ROOTFS_IMG")"

# Download OpenSnitch .deb
OPENSNITCH_DEB_PATH="$REPO/.cache/$OPENSNITCH_DEB"
if [ ! -f "$OPENSNITCH_DEB_PATH" ]; then
    echo ":: Downloading OpenSnitch $OPENSNITCH_VER ..."
    curl -fsSL -o "$OPENSNITCH_DEB_PATH" "$OPENSNITCH_URL"
fi

# Generate a random root password — only the hash enters the image
ROOT_PW=$(openssl rand -hex 16)

echo ":: Building base image rootfs (mmdebstrap) ..."

# Minimal packages — just enough to boot systemd, run a shell, and network.
# systemd-sysv is intentionally omitted because QEMU boots systemd explicitly.
PACKAGES="bash,bash-completion,coreutils,mount,procps,iproute2,util-linux,e2fsprogs,systemd"
PACKAGES="$PACKAGES,ca-certificates,curl,libnetfilter-queue1,libpcap0.8t64,openssh-server"

mmdebstrap \
    --mode=unshare \
    --variant=minbase \
    --aptopt='Apt::Install-Recommends "false"' \
    --skip=cleanup/apt/lists \
    --include="$PACKAGES" \
    --customize-hook='chroot "$1" test -x /usr/lib/systemd/systemd' \
    --customize-hook='for pkg in dbus udev systemd-sysv; do if chroot "$1" dpkg-query -W -f="\${Status}" "$pkg" 2>/dev/null | grep -q "install ok installed"; then echo "ERROR: prohibited package installed: $pkg" >&2; exit 1; fi; done' \
    --customize-hook='chroot "$1" groupadd -f kvm' \
    --customize-hook='chroot "$1" useradd -m -s /bin/bash -G kvm user' \
    --customize-hook='mkdir -p "$1/home/user/workspace"' \
    --customize-hook='chroot "$1" chown user:user /home/user/workspace' \
    --customize-hook='printf "export PATH=\"\$HOME/.local/bin:\$PATH\"\ncd ~/workspace 2>/dev/null\n" >> "$1/home/user/.bashrc"' \
    --customize-hook='chroot "$1" passwd -d user' \
    --customize-hook="echo 'root:$ROOT_PW' | chroot \"\$1\" chpasswd" \
    --customize-hook='rm -rf "$1"/var/cache/apt/archives/*.deb' \
    --customize-hook='rm -rf "$1"/usr/share/doc/*' \
    --customize-hook='rm -rf "$1"/usr/share/man/*' \
    --customize-hook='rm -rf "$1"/usr/share/locale/*' \
    trixie "$ROOTFS_TAR" http://deb.debian.org/debian

echo ":: Unpacking and installing OpenSnitch ..."

ROOTFS_DIR=$(mktemp -d)
trap 'rm -rf "$ROOTFS_DIR" "$ROOTFS_TAR" "$ROOTFS_IMG"' EXIT

fakeroot sh -c "
    tar -xf \"$ROOTFS_TAR\" -C \"$ROOTFS_DIR\"

    for overlay_dir in \"$BB\"/*; do
        [ -d \"\$overlay_dir\" ] || continue
        overlay_name=\$(basename \"\$overlay_dir\")
        mkdir -p \"$ROOTFS_DIR/\$overlay_name\"
        cp -r \"\$overlay_dir/.\" \"$ROOTFS_DIR/\$overlay_name/\"
    done

    ln -sfn usr/lib/x86_64-linux-gnu \"$ROOTFS_DIR/lib/x86_64-linux-gnu\"

    dpkg-deb -x \"$OPENSNITCH_DEB_PATH\" \"$ROOTFS_DIR\"

    mkdir -p \"$ROOTFS_DIR/etc/opensnitchd/rules\"
    mkdir -p \"$ROOTFS_DIR/etc/opensnitchd/lists/domains\"
    mkdir -p \"$ROOTFS_DIR/etc/systemd/system/multi-user.target.wants\"

    cat > \"$ROOTFS_DIR/etc/opensnitchd/default-config.json\" <<'CONF'
{
  \"DefaultAction\": \"deny\",
  \"DefaultDuration\": \"always\",
  \"InterceptUnknown\": true,
  \"ProcMonitorMethod\": \"proc\",
  \"LogLevel\": 1,
  \"Server\": {
    \"Address\": \"\",
    \"LogFile\": \"/var/log/opensnitchd.log\"
  },
  \"Stats\": {
    \"MaxEvents\": 150,
    \"MaxStats\": 50
  }
}
CONF

    cp \"$ALLOWED_HOSTS\" \"$ROOTFS_DIR/etc/opensnitchd/lists/domains/allowed.txt\"

    echo '{\"name\":\"000-allow-loopback\",\"enabled\":true,\"action\":\"allow\",\"duration\":\"always\",\"operator\":{\"type\":\"simple\",\"operand\":\"dest.ip\",\"data\":\"127.0.0.1\"}}' \
        > \"$ROOTFS_DIR/etc/opensnitchd/rules/000-allow-loopback.json\"

    echo '{\"name\":\"010-allow-dns\",\"enabled\":true,\"action\":\"allow\",\"duration\":\"always\",\"operator\":{\"type\":\"simple\",\"operand\":\"dest.port\",\"data\":\"53\"}}' \
        > \"$ROOTFS_DIR/etc/opensnitchd/rules/010-allow-dns.json\"

    echo '{\"name\":\"100-allow-whitelisted-domains\",\"enabled\":true,\"action\":\"allow\",\"duration\":\"always\",\"operator\":{\"type\":\"lists\",\"operand\":\"lists.domains_regexp\",\"data\":\"/etc/opensnitchd/lists/domains/\"}}' \
        > \"$ROOTFS_DIR/etc/opensnitchd/rules/100-allow-whitelisted-domains.json\"

    ln -sfn /usr/lib/systemd/system/ssh.service \"$ROOTFS_DIR/etc/systemd/system/multi-user.target.wants/ssh.service\"

    mkdir -p \"$ROOTFS_DIR/usr/local/sbin\"
    cp \"$ZAIGR_INSIDE_SCRIPT\" \"$ROOTFS_DIR/usr/local/sbin/zaigr-inside\"
    chown root:root \"$ROOTFS_DIR/usr/local/sbin/zaigr-inside\"
    chmod 750 \"$ROOTFS_DIR/usr/local/sbin/zaigr-inside\"

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
echo ":: Root password set (use 'zaigr ssh --root' for access)"
