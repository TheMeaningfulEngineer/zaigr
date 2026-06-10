package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureBuiltinSetupDefinitionRefreshesExistingCopy(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	setupPath := filepath.Join(home, ".zaigr", "setups", "release-tools", "setup.script")
	if err := os.MkdirAll(filepath.Dir(setupPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(setupPath, []byte("#!/bin/sh\necho stale-release-tools\n"), 0644); err != nil {
		t.Fatal(err)
	}
	staleExtraPath := filepath.Join(filepath.Dir(setupPath), "99-stale.script")
	if err := os.WriteFile(staleExtraPath, []byte("#!/bin/sh\necho extra-stale\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := ensureBuiltinSetupDefinition("release-tools"); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(setupPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, "stale-release-tools") {
		t.Fatalf("builtin setup was not refreshed:\n%s", text)
	}
	if !strings.Contains(text, "\n    podman \\") {
		t.Fatalf("refreshed release-tools setup does not install podman:\n%s", text)
	}
	if _, err := os.Stat(staleExtraPath); !os.IsNotExist(err) {
		t.Fatalf("stale builtin setup file still exists: %v", err)
	}
}

func TestLoadSetupDefinitionsRefreshesStaleBuiltinSetupDefinition(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	setupPath := filepath.Join(home, ".zaigr", "setups", "release-tools", "setup.script")
	if err := os.MkdirAll(filepath.Dir(setupPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(setupPath, []byte("#!/bin/sh\necho stale-release-tools\n"), 0644); err != nil {
		t.Fatal(err)
	}

	definitions, err := loadSetupDefinitions([]string{"release-tools"})
	if err != nil {
		t.Fatal(err)
	}
	if len(definitions) != 1 {
		t.Fatalf("got %d setup definitions, want 1", len(definitions))
	}
	if definitions[0].Name != "release-tools" {
		t.Fatalf("got setup definition %q, want release-tools", definitions[0].Name)
	}

	payload, err := buildSetupPayload(definitions[0])
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	if strings.Contains(text, "stale-release-tools") {
		t.Fatalf("loaded setup payload was not refreshed:\n%s", text)
	}
	if !strings.Contains(text, "\n    podman \\") {
		t.Fatalf("loaded release-tools setup payload does not install podman:\n%s", text)
	}
}
