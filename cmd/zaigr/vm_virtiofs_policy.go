package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// Set from the CLI command scope, never from a project's files or environment.
// Global base-image operations must not inherit the current directory's choice.
var projectSandboxContext bool

func (store projectStore) virtiofsSandboxPath() string {
	return filepath.Join(store.Path, "virtiofs-sandbox")
}

func (store projectStore) virtiofsSandbox() (string, error) {
	if store.Path == "" {
		return "namespace", nil
	}
	data, err := os.ReadFile(store.virtiofsSandboxPath())
	if os.IsNotExist(err) {
		return "namespace", nil
	}
	if err != nil {
		return "", fmt.Errorf("read project virtiofs sandbox setting: %w", err)
	}
	mode := strings.TrimSpace(string(data))
	if mode != "namespace" && mode != "none" {
		return "", fmt.Errorf("invalid project virtiofs-sandbox setting %q; expected namespace or none", mode)
	}
	return mode, nil
}

func (store projectStore) writeVirtiofsSandbox(mode string) error {
	return writeFileAtomically(store.virtiofsSandboxPath(), []byte(mode+"\n"), 0600)
}

func preserveVirtiofsSandbox(source, destination projectStore) error {
	mode, err := source.virtiofsSandbox()
	if err != nil {
		return err
	}
	return destination.writeVirtiofsSandbox(mode)
}

func virtiofsPreferenceStore(spec vmLaunchSpec) projectStore {
	if !projectSandboxContext {
		return projectStore{}
	}
	// Rebuilds can launch from a staging store; preferences belong to the
	// source project whose durable logs receive the result.
	if filepath.Dir(spec.LogRoot) == projectStoreRoot() && !strings.HasPrefix(filepath.Base(spec.LogRoot), ".") {
		return projectStore{Path: spec.LogRoot}
	}
	// Automatic base preparation during project initialization uses a global
	// runtime directory, but must honor this project's choice too.
	store := currentProjectStore()
	if _, err := os.Stat(store.configPath()); err == nil {
		return store
	}
	// Standalone global operations have no project preference to persist.
	return projectStore{}
}

func selectVirtiofsSandbox(store projectStore) (string, error) {
	mode, err := store.virtiofsSandbox()
	if err != nil {
		return "", err
	}
	if mode == "none" {
		return "", virtiofsNamespaceRequiredError("the saved project setting is virtiofs-sandbox=none")
	}
	host := detectCheckHost()
	check := checkVirtiofsMode(host, "namespace")
	if check.passed {
		return "namespace", nil
	}
	return "", fmt.Errorf("virtiofs namespace sandbox is required; no VM started\nHost check failed: could not start the required filesystem sandbox.\nRun 'zaigr misc check' for the full host report.\n\n%s", hostNamespaceGuidance(host))
}

func virtiofsNamespaceRequiredError(reason string) error {
	return fmt.Errorf("%s; host-enforced VM networking requires the namespace file-sharing sandbox. Run 'zaigr project vm set-config --virtiofs-sandbox namespace' after resolving the host restriction with 'zaigr misc check'", reason)
}

// hostNamespaceGuidance is shared by the network and virtiofs probes so the
// remediation text stays consistent across misc check and operation failures.
func hostNamespaceGuidance(host checkHost) string {
	if host.container {
		return `Container setup
───────────────

Ask the host administrator to allow nested user, mount, PID and network
namespaces and sandbox mounts in the container settings.

Verify:
  zaigr misc check`
	}
	if host.family("ubuntu") && host.policy["AppArmor user-namespace restriction"] == "1" {
		return `Ubuntu setup
────────────

Generate and review:
  zaigr misc apparmor-profile > zaigr-virtiofsd.profile

Install:
  sudo install -m 0644 zaigr-virtiofsd.profile /etc/apparmor.d/zaigr-virtiofsd
  sudo apparmor_parser -r /etc/apparmor.d/zaigr-virtiofsd

Verify:
  zaigr misc check

What this permission allows:
  Zaigr and the file server can use user namespaces for network and
  filesystem sandbox setup. Ubuntu's system-wide restriction stays enabled.

  Permission follows executable paths, not verified code identities.
  Subprocesses inherit the profile, and same-user code can replace either
  executable at its path. Protect both paths from other local users and
  regenerate the policy when either path changes.

Ubuntu documentation:
  https://documentation.ubuntu.com/release-notes/24.04/#unprivileged-user-namespace-restrictions`
	}
	return fmt.Sprintf("Setup for %s\n\nRun zaigr misc check to identify the host restriction and required change.", host.name)
}

func newAppArmorProfileCommand() *cobra.Command {
	return &cobra.Command{
		Use: "apparmor-profile", Short: "Print an Ubuntu AppArmor user-namespace profile for Zaigr and its bundled daemon", Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			daemon, err := ensureVirtiofsdWithWriter(false, io.Discard)
			if err != nil {
				return err
			}
			executable, err := os.Executable()
			if err != nil {
				return fmt.Errorf("resolve Zaigr executable path: %w", err)
			}
			executable, err = filepath.EvalSymlinks(executable)
			if err != nil {
				return fmt.Errorf("resolve Zaigr executable path: %w", err)
			}
			executable, err = filepath.Abs(executable)
			if err != nil {
				return fmt.Errorf("make Zaigr executable path absolute: %w", err)
			}
			daemon, err = filepath.EvalSymlinks(daemon)
			if err != nil {
				return fmt.Errorf("resolve cached virtiofs daemon path: %w", err)
			}
			daemon, err = filepath.Abs(daemon)
			if err != nil {
				return fmt.Errorf("make cached virtiofs daemon path absolute: %w", err)
			}
			paths := []string{executable, daemon}
			for _, path := range paths {
				// Never turn a literal executable path into a broader AppArmor glob.
				if strings.ContainsAny(path, "\n\r\"\\*?[]{}@^!|,;:$&") {
					return fmt.Errorf("executable path contains AppArmor pattern characters; a host administrator must write the profile for %q", path)
				}
			}
			fmt.Printf("# Review before loading. These path-scoped rules are not verified code identities.\n# Processes and subprocesses under either profile can use user namespaces.\n# Same-user code may replace files at these paths; regenerate when either path changes.\nabi <abi/4.0>,\nprofile zaigr %q flags=(unconfined) {\n  userns,\n}\nprofile zaigr-virtiofsd %q flags=(unconfined) {\n  userns,\n}\n", executable, daemon)
			return nil
		},
	}
}
