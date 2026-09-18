package main

import (
	"fmt"
	"os"
)

func ensureHostUserBase(ram, cpu string) (globalBaseManifest, bool, error) {
	lock, err := acquireGlobalBaseMutationLock()
	if err != nil {
		return globalBaseManifest{}, false, fmt.Errorf("lock global base image: %w", err)
	}
	defer releaseGlobalBaseMutationLock(lock)
	return ensureHostUserBaseLocked(ram, cpu)
}

// The caller holds the global mutation lock, including while publishing the base.
func ensureHostUserBaseLocked(ram, cpu string) (globalBaseManifest, bool, error) {
	manifest, customized, err := readGlobalBaseManifest()
	if err != nil {
		return manifest, customized, err
	}
	uid := os.Getuid()
	if uid == 0 || (!customized && uid == 1000) || (customized && manifest.UserUID == uid) {
		return manifest, customized, nil
	}
	// Legacy customized images have no recorded account identity. Preserve them:
	// changing arbitrary custom ACLs, capabilities, or service accounts is unsafe.
	if customized && manifest.UserUID == 0 {
		return manifest, customized, nil
	}
	if uid != os.Geteuid() || uint64(uid) >= 4294967295 {
		return manifest, customized, fmt.Errorf("base image preparation requires running as your normal host account, without sudo")
	}
	if customized && len(manifest.Applied) != 0 {
		return manifest, customized, fmt.Errorf("the customized base image belongs to another host account and was not changed")
	}
	ramValue, cpuValue, err := resolveGlobalBuildResources(ram, cpu)
	if err != nil {
		return manifest, customized, err
	}
	if err := cleanupGlobalBaseStaging(); err != nil {
		return manifest, customized, err
	}
	fmt.Fprintln(os.Stderr, ":: Warning: Preparing the base image for your account automatically; this may take a little longer.")
	if err := buildAndPublishGlobalBase(globalBaseManifest{}, false, nil, nil, nil, ramValue, cpuValue, uid); err != nil {
		return manifest, customized, err
	}
	return readGlobalBaseManifest()
}

// Only run this in the factory-derived global builder's private staging VM.
// Arbitrary customized-image ACL/capability migration is deliberately unsupported.
const migrateUserUIDScript = `#!/bin/bash
set -euo pipefail

target_uid=${ZAIGR_MIGRATE_UID:?Set ZAIGR_MIGRATE_UID explicitly}
case "$target_uid" in
    ''|*[!0-9]*) printf 'Invalid target UID\n' >&2; exit 1 ;;
esac
if [ "$target_uid" -le 0 ] || [ "$target_uid" -ge 4294967295 ]; then
    printf 'Refusing reserved target UID\n' >&2
    exit 1
fi
[ "$(id -u)" = 0 ] || { printf 'Migration must run as guest root\n' >&2; exit 1; }
old_uid=$(id -u user)
if [ "$old_uid" = "$target_uid" ]; then
    exit 0
fi
if account=$(getent passwd "$target_uid"); then
    printf 'Target UID is already assigned: %s\n' "$account" >&2
    exit 1
fi
if pgrep -u "$old_uid" >/dev/null || pgrep -U "$old_uid" >/dev/null; then
    printf 'Guest user has running processes; refusing migration\n' >&2
    exit 1
fi

# usermod walks the home directory itself; find -xdev alone cannot protect shares.
cd /
for share in /home/user/workspace /home/user/.zaigr-agent-state; do
    if mountpoint -q "$share"; then
        umount "$share"
    fi
done
orphan=$(find / -xdev -uid "$target_uid" -print -quit)
if [ -n "$orphan" ]; then
    printf 'Target UID already owns guest-disk files: %s\n' "$orphan" >&2
    exit 1
fi

# Keep the username, home path, primary group, and supplementary groups.
usermod -u "$target_uid" user
find / -xdev -uid "$old_uid" -exec chown -h "$target_uid" {} +
`
