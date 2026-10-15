package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

const unsafeVirtiofsWarning = `WARNING: Without the file-sharing sandbox, a file-server exploit could
compromise your host user account.

An attacker in the VM could then read or change files outside the shared
directories, steal credentials, or run commands as you.`

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
		fmt.Fprintln(os.Stderr, unsafeVirtiofsWarning)
		return mode, nil
	}
	host := detectCheckHost()
	check := checkVirtiofsMode(host, "namespace")
	if check.passed {
		return "namespace", nil
	}
	fmt.Fprint(os.Stderr, ":: File-sharing isolation is unavailable on this host.\n\n")
	// Probe only an empty private export, without a VM, before offering an
	// alternative that might also be unsupported on this host.
	if fallback := checkVirtiofsMode(host, "none"); !fallback.passed {
		return "", fmt.Errorf("unsandboxed virtiofs is also unavailable; no VM started:\n%s", fallback.detail)
	}
	fmt.Fprintln(os.Stderr, unsafeVirtiofsWarning)
	if store.Path != "" {
		fmt.Fprintln(os.Stderr, "\nIf you choose unsafe, Zaigr will remember it for this project, including\nfuture starts and rebuilds. Other projects keep their own settings.")
	} else {
		fmt.Fprintln(os.Stderr, "\nThis is a global image operation. Your choice applies only to this\noperation and will not be saved as a project setting.")
	}
	for {
		fmt.Fprint(os.Stderr, "\n  cancel  Stop here and keep the current settings (default).\n  info    Show more information and setup instructions.\n  unsafe  Continue with the risk described above.\n\n")
		fmt.Fprint(os.Stderr, "Your choice [cancel/info/unsafe] (default: cancel): ")
		var answer string
		if _, err := fmt.Scanln(&answer); err != nil {
			return "", fmt.Errorf("cancelled: virtiofs namespace sandbox unavailable; no unsafe preference was saved")
		}
		if strings.EqualFold(answer, "info") {
			fmt.Fprintf(os.Stderr, "\n%s\n\nFull diagnostics: zaigr misc check\n", virtiofsSandboxSetup(host))
			continue
		}
		if !strings.EqualFold(answer, "unsafe") {
			return "", fmt.Errorf("cancelled: virtiofs namespace sandbox unavailable; no unsafe preference was saved")
		}
		break
	}
	if store.Path != "" {
		if err := store.writeVirtiofsSandbox("none"); err != nil {
			return "", err
		}
		fmt.Fprintln(os.Stderr, "\n:: Saved for this project: file-sharing sandbox disabled.\n\nTo enable it again, stop the project VM and run:\n  zaigr project vm set-config --virtiofs-sandbox namespace")
	}
	return "none", nil
}

func virtiofsSandboxSetup(host checkHost) string {
	if host.family("ubuntu") && host.policy["AppArmor user-namespace restriction"] == "1" {
		return `Ubuntu setup
────────────

Generate and review:
  zaigr misc apparmor-profile > zaigr-virtiofsd.profile

Install:
  sudo install -m 0644 zaigr-virtiofsd.profile /etc/apparmor.d/zaigr-virtiofsd
  sudo apparmor_parser -r /etc/apparmor.d/zaigr-virtiofsd

Verify:
  zaigr misc check`
	}
	if host.container {
		return `Container setup
───────────────

Ask the host administrator to allow nested user, mount, PID and network
namespaces and sandbox mounts in the container settings.

Verify:
  zaigr misc check`
	}
	return fmt.Sprintf("Setup for %s\n\nRun zaigr misc check to identify the host restriction and required change.", host.name)
}

func virtiofsSandboxGuidance(host checkHost) string {
	setup := virtiofsSandboxSetup(host)
	if host.family("ubuntu") && host.policy["AppArmor user-namespace restriction"] == "1" {
		return setup + `

If AppArmor is blocking sandbox creation, this rule may allow it.
Review the generated policy before installing it. Verify as your normal user.

What this permission allows:
  The file server can use kernel features needed to create its sandbox.
  Ubuntu's system-wide restriction stays enabled.

  The permission applies to the executable's path. Your account can
  replace that file, so other code running as you could replace it and
  gain the same permission. Regenerate the policy after a daemon upgrade.

Ubuntu documentation:
  https://documentation.ubuntu.com/release-notes/24.04/#unprivileged-user-namespace-restrictions`
	}
	return setup
}

func newAppArmorProfileCommand() *cobra.Command {
	return &cobra.Command{
		Use: "apparmor-profile", Short: "Print an Ubuntu AppArmor user-namespace exception for the bundled daemon", Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			daemon, err := ensureVirtiofsdWithWriter(false, io.Discard)
			if err != nil {
				return err
			}
			// Never turn a literal executable path into a broader AppArmor glob.
			if strings.ContainsAny(daemon, "\n\r\"\\*?[]{}@") {
				return fmt.Errorf("daemon path contains AppArmor pattern characters; a host administrator must write the profile for %q", daemon)
			}
			fmt.Printf("# Review before loading: this permits user namespaces for the executable path below.\n# The cached executable is user-writable; the path is not a verified code identity.\n# Regenerate after a daemon upgrade.\nabi <abi/4.0>,\nprofile zaigr-virtiofsd %q flags=(unconfined) {\n  userns,\n}\n", daemon)
			return nil
		},
	}
}
