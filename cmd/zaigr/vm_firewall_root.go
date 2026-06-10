package main

import (
	"fmt"
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
	now := time.Now().UTC().Format(time.RFC3339Nano)
	ruleName := temporaryRootAllowAllFirewallRuleName
	rulePath := "/etc/opensnitchd/rules/" + ruleName + ".json"

	ruleJSON := strings.TrimSpace(fmt.Sprintf(`{
  "created": "%s",
  "updated": "%s",
  "name": "%s",
  "enabled": true,
  "precedence": true,
  "action": "allow",
  "duration": "always",
  "operator": {
    "type": "simple",
    "sensitive": false,
    "operand": "user.id",
    "data": "0"
  }
}`, now, now, ruleName))

	script := fmt.Sprintf(`set -eu
rules_dir=/etc/opensnitchd/rules
mkdir -p "$rules_dir"
rm -f "$rules_dir"/000-zaigr-root-allow-all-*.json
cat <<'__ZAIGR_ROOT_RULE__' > "$rules_dir"/%s.json
%s
__ZAIGR_ROOT_RULE__
`, temporaryRootAllowAllFirewallRuleName, ruleJSON)

	if err := sshRunScript(sshPort, rootKeyPath, script); err != nil {
		return "", err
	}

	return rulePath, nil
}

func removeTemporaryRootAllowAllFirewallRule(sshPort string, rootKeyPath string, rulePath string) error {
	script := fmt.Sprintf(`set -eu
rules_dir=/etc/opensnitchd/rules
rm -f "$rules_dir"/000-zaigr-root-allow-all-*.json
rm -f %s
`, singleQuotedArg(rulePath))
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

func installTemporaryCaptureAllowAllFirewallRule(sshPort string, rootKeyPath string, token string) (string, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	ruleName := temporaryCaptureAllowAllFirewallRuleName
	rulePath := "/etc/opensnitchd/rules/" + ruleName + ".json"

	ruleJSON := strings.TrimSpace(fmt.Sprintf(`{
  "created": "%s",
  "updated": "%s",
  "name": "%s",
  "enabled": true,
  "precedence": true,
  "action": "allow",
  "duration": "always",
  "operator": {
    "type": "simple",
    "sensitive": false,
    "operand": "process.env.ZAIGR_SETUP_CAPTURE_TOKEN",
    "data": "%s"
  }
}`, now, now, ruleName, token))

	script := fmt.Sprintf(`set -eu
rules_dir=/etc/opensnitchd/rules
mkdir -p "$rules_dir"
rm -f "$rules_dir"/000-zaigr-capture-allow-all-*.json
cat <<'__ZAIGR_CAPTURE_RULE__' > "$rules_dir"/%s.json
%s
__ZAIGR_CAPTURE_RULE__
`, temporaryCaptureAllowAllFirewallRuleName, ruleJSON)

	if err := sshRunScript(sshPort, rootKeyPath, script); err != nil {
		return "", err
	}

	return rulePath, nil
}

func removeTemporaryCaptureAllowAllFirewallRule(sshPort string, rootKeyPath string, rulePath string) error {
	script := fmt.Sprintf(`set -eu
rules_dir=/etc/opensnitchd/rules
rm -f "$rules_dir"/000-zaigr-capture-allow-all-*.json
rm -f %s
`, singleQuotedArg(rulePath))
	return sshRunScript(sshPort, rootKeyPath, script)
}
