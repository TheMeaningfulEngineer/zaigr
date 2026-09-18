package main

import (
	"errors"
	"fmt"
	"os/exec"
	"path"
	"strings"
	"time"
)

const temporaryRootAllowAllFirewallRuleName = "000-zaigr-root-allow-all-temporary"
const temporaryCaptureAllowAllFirewallRuleName = "000-zaigr-capture-allow-all-temporary"

func withTemporaryRootAllowAllFirewallRule(sshPort string, rootKeyPath string, action func() error) (err error) {
	if action == nil {
		return fmt.Errorf("temporary root firewall action is nil")
	}

	rulePath, err := installTemporaryRootAllowAllFirewallRule(sshPort, rootKeyPath)
	if err != nil {
		return fmt.Errorf("install temporary root allow-all firewall rule: %w", err)
	}

	defer func() {
		if cleanupErr := removeTemporaryRootAllowAllFirewallRule(sshPort, rootKeyPath, rulePath); cleanupErr != nil {
			if err != nil {
				err = fmt.Errorf("temporary root allow-all firewall rule action failed: %w; cleanup of temporary rule also failed: %v", err, cleanupErr)
			} else {
				err = fmt.Errorf("cleanup temporary root allow-all firewall rule: %w", cleanupErr)
			}
		}
	}()

	err = action()
	return
}

func installTemporaryRootAllowAllFirewallRule(sshPort string, rootKeyPath string) (string, error) {
	createdAt := time.Now().UTC()
	now := createdAt.Format(time.RFC3339Nano)
	ruleID := fmt.Sprintf("%d", createdAt.UnixNano())
	ruleName := temporaryRootAllowAllFirewallRuleName + "-" + ruleID
	rulePath := "/etc/opensnitchd/rules/" + ruleName + ".json"
	expiryUnit := "zaigr-root-allow-all-expiry-" + ruleID

	ruleJSON := strings.TrimSpace(fmt.Sprintf(`{
  "created": "%s",
  "updated": "%s",
  "name": "%s",
  "enabled": true,
  "precedence": true,
  "action": "allow",
  "duration": "until restart",
  "operator": {
    "type": "simple",
    "sensitive": false,
    "operand": "user.id",
    "data": "0"
  }
}`, now, now, ruleName))

	script := fmt.Sprintf(`set -eu
umask 077
rules_dir=/etc/opensnitchd/rules
mkdir -p "$rules_dir"
system_state="$(systemctl is-system-running 2>/dev/null || true)"
case "$system_state" in
  running|degraded|starting)
    systemd-run --quiet --collect --unit=%s --on-active=31m \
      /bin/sh -c 'rm -f "$1"' _ %s
    ;;
esac
cat <<'__ZAIGR_ROOT_RULE__' > %s
%s
__ZAIGR_ROOT_RULE__
`, expiryUnit, singleQuotedArg(rulePath), singleQuotedArg(rulePath), ruleJSON)

	if err := sshRunScript(sshPort, rootKeyPath, script); err != nil {
		return "", err
	}

	return rulePath, nil
}

func removeTemporaryRootAllowAllFirewallRule(sshPort string, rootKeyPath string, rulePath string) error {
	expiryUnit, err := temporaryFirewallExpiryUnit(rulePath, temporaryRootAllowAllFirewallRuleName, "zaigr-root-allow-all-expiry-")
	if err != nil {
		return err
	}
	script := fmt.Sprintf(`set -eu
systemctl stop %s.timer %s.service >/dev/null 2>&1 || true
systemctl reset-failed %s.timer %s.service >/dev/null 2>&1 || true
rm -f %s
`, expiryUnit, expiryUnit, expiryUnit, expiryUnit, singleQuotedArg(rulePath))
	return sshRunScript(sshPort, rootKeyPath, script)
}

func withTemporaryCaptureAllowAllFirewallRule(sshPort string, rootKeyPath string, token string, action func() error) (err error) {
	if action == nil {
		return fmt.Errorf("temporary capture firewall action is nil")
	}
	if token == "" {
		return fmt.Errorf("temporary capture firewall token is empty")
	}

	rulePath, err := installTemporaryCaptureAllowAllFirewallRule(sshPort, rootKeyPath, token)
	if err != nil {
		return fmt.Errorf("install temporary capture allow-all firewall rule: %w", err)
	}

	defer func() {
		if cleanupErr := removeTemporaryCaptureAllowAllFirewallRule(sshPort, rootKeyPath, rulePath); cleanupErr != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) && exitErr.ExitCode() == 255 && setupCaptureFinishedAfterVMShutdown() {
				err = nil
				return
			}
			if err != nil {
				err = fmt.Errorf("temporary capture allow-all firewall action failed: %w; cleanup of temporary rule also failed: %v", err, cleanupErr)
			} else {
				err = fmt.Errorf("cleanup temporary capture allow-all firewall rule: %w", cleanupErr)
			}
		}
	}()

	err = action()
	return
}

func setupCaptureFinishedAfterVMShutdown() bool {
	store := currentProjectStore()
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, active, metadataErr := store.readSetupCaptureMetadata()
		running, stale := detectRunningProjectVMWithMetadataInStore(store)
		if metadataErr == nil && !active && (running == nil || stale) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func installTemporaryCaptureAllowAllFirewallRule(sshPort string, rootKeyPath string, token string) (string, error) {
	createdAt := time.Now().UTC()
	now := createdAt.Format(time.RFC3339Nano)
	ruleID := fmt.Sprintf("%d", createdAt.UnixNano())
	ruleName := temporaryCaptureAllowAllFirewallRuleName + "-" + ruleID
	rulePath := "/etc/opensnitchd/rules/" + ruleName + ".json"
	expiryUnit := "zaigr-capture-allow-all-expiry-" + ruleID

	ruleJSON := strings.TrimSpace(fmt.Sprintf(`{
  "created": "%s",
  "updated": "%s",
  "name": "%s",
  "enabled": true,
  "precedence": true,
  "action": "allow",
  "duration": "until restart",
  "operator": {
    "type": "simple",
    "sensitive": false,
    "operand": "process.env.ZAIGR_SETUP_CAPTURE_TOKEN",
    "data": "%s"
  }
}`, now, now, ruleName, token))

	script := fmt.Sprintf(`set -eu
umask 077
rules_dir=/etc/opensnitchd/rules
mkdir -p "$rules_dir"
systemctl stop 'zaigr-capture-allow-all-expiry-*.timer' 'zaigr-capture-allow-all-expiry-*.service' >/dev/null 2>&1 || true
rm -f "$rules_dir"/000-zaigr-capture-allow-all-*.json
system_state="$(systemctl is-system-running 2>/dev/null || true)"
case "$system_state" in
  running|degraded|starting)
    systemd-run --quiet --collect --unit=%s --on-active=24h \
      /bin/sh -c 'rm -f "$1"' _ %s
    ;;
esac
cat <<'__ZAIGR_CAPTURE_RULE__' > %s
%s
__ZAIGR_CAPTURE_RULE__
`, expiryUnit, singleQuotedArg(rulePath), singleQuotedArg(rulePath), ruleJSON)

	if err := sshRunScript(sshPort, rootKeyPath, script); err != nil {
		return "", err
	}

	return rulePath, nil
}

func removeTemporaryCaptureAllowAllFirewallRule(sshPort string, rootKeyPath string, rulePath string) error {
	expiryUnit, err := temporaryFirewallExpiryUnit(rulePath, temporaryCaptureAllowAllFirewallRuleName, "zaigr-capture-allow-all-expiry-")
	if err != nil {
		return err
	}
	script := fmt.Sprintf(`set -eu
systemctl stop %s.timer %s.service >/dev/null 2>&1 || true
systemctl reset-failed %s.timer %s.service >/dev/null 2>&1 || true
rm -f %s
`, expiryUnit, expiryUnit, expiryUnit, expiryUnit, singleQuotedArg(rulePath))
	return sshRunScript(sshPort, rootKeyPath, script)
}

func removeAllTemporaryCaptureAllowAllFirewallRules(sshPort string, rootKeyPath string) error {
	script := `set -eu
systemctl stop 'zaigr-capture-allow-all-expiry-*.timer' 'zaigr-capture-allow-all-expiry-*.service' >/dev/null 2>&1 || true
systemctl reset-failed 'zaigr-capture-allow-all-expiry-*.timer' 'zaigr-capture-allow-all-expiry-*.service' >/dev/null 2>&1 || true
rm -f /etc/opensnitchd/rules/000-zaigr-capture-allow-all-*.json
`
	return sshRunScript(sshPort, rootKeyPath, script)
}

func temporaryFirewallExpiryUnit(rulePath string, rulePrefix string, unitPrefix string) (string, error) {
	ruleName := strings.TrimSuffix(path.Base(rulePath), ".json")
	id, ok := strings.CutPrefix(ruleName, rulePrefix+"-")
	if !ok || id == "" || strings.IndexFunc(id, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return "", fmt.Errorf("invalid temporary firewall rule path: %s", rulePath)
	}
	return unitPrefix + id, nil
}
