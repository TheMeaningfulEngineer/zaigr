package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestInstallTemporaryRootAllowAllFirewallRuleCleansStaleRulesAndIsIdempotent(t *testing.T) {
	rulesDir := t.TempDir()
	installFakeSSHForRootFirewallTest(t, rulesDir)

	writeTestRuleFile(t, rulesDir, "000-zaigr-root-allow-all-stale.json")
	writeTestRuleFile(t, rulesDir, "000-zaigr-root-allow-all-older.json")
	writeTestRuleFile(t, rulesDir, "100-allow-whitelisted-domains.json")

	firstRulePath, err := installTemporaryRootAllowAllFirewallRule("10022", "/tmp/root.key")
	if err != nil {
		t.Fatal(err)
	}

	firstRules := rootAllowAllRuleFiles(t, rulesDir)
	if len(firstRules) != 1 {
		t.Fatalf("root allow-all rules after first install:\n%s\nwant exactly one rule", strings.Join(firstRules, "\n"))
	}
	if firstRules[0] != filepath.Base(firstRulePath) {
		t.Fatalf("root allow-all rule after first install = %q, want %q", firstRules[0], filepath.Base(firstRulePath))
	}

	secondRulePath, err := installTemporaryRootAllowAllFirewallRule("10022", "/tmp/root.key")
	if err != nil {
		t.Fatal(err)
	}

	secondRules := rootAllowAllRuleFiles(t, rulesDir)
	if len(secondRules) != 1 {
		t.Fatalf("root allow-all rules after second install:\n%s\nwant exactly one rule", strings.Join(secondRules, "\n"))
	}
	if secondRules[0] != filepath.Base(secondRulePath) {
		t.Fatalf("root allow-all rule after second install = %q, want %q", secondRules[0], filepath.Base(secondRulePath))
	}
	if _, err := os.Stat(filepath.Join(rulesDir, "100-allow-whitelisted-domains.json")); err != nil {
		t.Fatalf("non-root firewall rule should remain: %v", err)
	}

	rule := readTestRule(t, filepath.Join(rulesDir, secondRules[0]))
	operator := rule["operator"].(map[string]any)
	if operator["operand"] != "user.id" || operator["data"] != "0" {
		t.Fatalf("temporary root rule operator = %#v, want user.id 0", operator)
	}
}

func TestWithTemporaryCaptureAllowAllFirewallRuleIsScopedToCaptureToken(t *testing.T) {
	rulesDir := t.TempDir()
	installFakeSSHForRootFirewallTest(t, rulesDir)

	actionRan := false
	err := withTemporaryCaptureAllowAllFirewallRule("10022", "/tmp/root.key", "capture-token", func() error {
		actionRan = true
		rules := captureAllowAllRuleFiles(t, rulesDir)
		if len(rules) != 1 {
			t.Fatalf("capture allow-all rules during capture action:\n%s\nwant exactly one temporary rule", strings.Join(rules, "\n"))
		}

		rule := readTestRule(t, filepath.Join(rulesDir, rules[0]))
		operator := rule["operator"].(map[string]any)
		if operator["operand"] != "process.env.ZAIGR_SETUP_CAPTURE_TOKEN" || operator["data"] != "capture-token" {
			t.Fatalf("temporary capture rule operator = %#v, want capture env token", operator)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !actionRan {
		t.Fatal("capture action did not run")
	}

	rules := captureAllowAllRuleFiles(t, rulesDir)
	if len(rules) != 0 {
		t.Fatalf("capture allow-all rules after cleanup:\n%s\nwant none", strings.Join(rules, "\n"))
	}
}

func TestWithTemporaryRootAllowAllFirewallRuleCleansUpRootRules(t *testing.T) {
	rulesDir := t.TempDir()
	installFakeSSHForRootFirewallTest(t, rulesDir)

	writeTestRuleFile(t, rulesDir, "000-zaigr-root-allow-all-stale.json")

	actionRan := false
	err := withTemporaryRootAllowAllFirewallRule("10022", "/tmp/root.key", func() error {
		actionRan = true
		rules := rootAllowAllRuleFiles(t, rulesDir)
		if len(rules) != 1 {
			t.Fatalf("root allow-all rules during root action:\n%s\nwant exactly one temporary rule", strings.Join(rules, "\n"))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !actionRan {
		t.Fatal("root action did not run")
	}

	rules := rootAllowAllRuleFiles(t, rulesDir)
	if len(rules) != 0 {
		t.Fatalf("root allow-all rules after cleanup:\n%s\nwant none", strings.Join(rules, "\n"))
	}
}

func installFakeSSHForRootFirewallTest(t *testing.T, rulesDir string) {
	t.Helper()

	tempDir := t.TempDir()
	binDir := filepath.Join(tempDir, "bin")
	captureDir := filepath.Join(tempDir, "ssh-calls")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(captureDir, 0755); err != nil {
		t.Fatal(err)
	}

	fakeSSH := filepath.Join(binDir, "ssh")
	if err := os.WriteFile(fakeSSH, []byte(`#!/bin/sh
set -eu

index_file="$ZAIGR_TEST_SSH_CAPTURE_DIR/next"
if [ -f "$index_file" ]; then
  index="$(cat "$index_file")"
else
  index=0
fi
next=$((index + 1))
printf '%s\n' "$next" > "$index_file"

script="$ZAIGR_TEST_SSH_CAPTURE_DIR/script-$index.sh"
rewritten="$ZAIGR_TEST_SSH_CAPTURE_DIR/script-$index.local.sh"
cat > "$script"
sed "s#/etc/opensnitchd/rules#$ZAIGR_TEST_RULES_DIR#g" "$script" > "$rewritten"
bash -eu "$rewritten"
`), 0755); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("ZAIGR_TEST_RULES_DIR", rulesDir)
	t.Setenv("ZAIGR_TEST_SSH_CAPTURE_DIR", captureDir)
}

func writeTestRuleFile(t *testing.T, rulesDir string, name string) {
	t.Helper()

	if err := os.WriteFile(filepath.Join(rulesDir, name), []byte("{}\n"), 0644); err != nil {
		t.Fatal(err)
	}
}

func rootAllowAllRuleFiles(t *testing.T, rulesDir string) []string {
	t.Helper()

	return globTestRuleFiles(t, rulesDir, "000-zaigr-root-allow-all-*.json")
}

func captureAllowAllRuleFiles(t *testing.T, rulesDir string) []string {
	t.Helper()

	return globTestRuleFiles(t, rulesDir, "000-zaigr-capture-allow-all-*.json")
}

func globTestRuleFiles(t *testing.T, rulesDir string, pattern string) []string {
	t.Helper()

	paths, err := filepath.Glob(filepath.Join(rulesDir, pattern))
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(paths))
	for _, path := range paths {
		names = append(names, filepath.Base(path))
	}
	sort.Strings(names)
	return names
}

func readTestRule(t *testing.T, path string) map[string]any {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rule map[string]any
	if err := json.Unmarshal(data, &rule); err != nil {
		t.Fatal(err)
	}
	return rule
}
