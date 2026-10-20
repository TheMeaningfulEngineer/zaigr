package main

import (
	"context"
	"fmt"
)

// applyHostNetworkGuestTransition removes OpenSnitch from this boot's systemd
// dependency graph only after the host policy is active and SSH is ready. The
// drop-ins live under /run, so the legacy guest firewall dependencies return
// on the next boot unless that boot also selects the host backend.
func applyHostNetworkGuestTransition(ctx context.Context, port string) error {
	rootKey := rootSSHKeyPath()
	const script = `set -eu
# Fresh images have no guest firewall unit or dependency chain to transition.
if ! systemctl cat opensnitch.service >/dev/null 2>&1; then
  exit 0
fi
target=/etc/systemd/system/ssh.service.d/10-zaigr-runtime.conf
test -f "$target" && test ! -L "$target"
install -d -m 0755 /run/zaigr-host-network
replacement=/run/zaigr-host-network/ssh-runtime.conf
cat > "$replacement" <<'EOF'
[Unit]
After=zaigr-runtime-ready.service
EOF
chmod 0644 "$replacement"
mount --bind "$replacement" "$target"
systemctl daemon-reload
requires=$(systemctl show -p Requires ssh.service)
case "$requires" in
  *zaigr-runtime-ready.service*) echo 'SSH still requires guest firewall readiness after host transition' >&2; exit 1 ;;
esac
systemctl stop opensnitch.service
systemctl is-active --quiet ssh.service
if systemctl is-active --quiet opensnitch.service; then
  echo 'OpenSnitch remained active after host-backend transition' >&2
  exit 1
fi
`
	if err := sshRunControlScriptContext(ctx, port, rootKey, script); err != nil {
		return fmt.Errorf("disable guest OpenSnitch after host policy activation: %w", err)
	}
	return nil
}

func hostTransitionError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("host-enforced network transition failed: %w", err)
}
