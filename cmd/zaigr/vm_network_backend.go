package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	vmNetworkBackendUser = "qemu-user"
	vmNetworkBackendHost = "host"
)

// selectVMNetworkBackend keeps old on-disk backend values readable while new
// launches use only the host-owned firewall. A legacy VM must be stopped
// before it can be replaced by the host-enforced network boundary.
func selectVMNetworkBackend(requested, running string) (string, error) {
	requested = strings.TrimSpace(requested)
	running = strings.TrimSpace(running)
	if running == "legacy" {
		running = vmNetworkBackendUser
	}
	if requested != "" && requested != vmNetworkBackendHost {
		return "", fmt.Errorf("unsupported network backend %q; zaigr now uses host-enforced networking", requested)
	}
	if running != "" && running != vmNetworkBackendUser && running != vmNetworkBackendHost {
		return "", fmt.Errorf("running VM has unknown network backend %q", running)
	}
	if running == vmNetworkBackendUser {
		return "", fmt.Errorf("running VM uses the legacy guest firewall; stop it with 'zaigr project vm stop' before using host-enforced networking")
	}
	return vmNetworkBackendHost, nil
}

func requestedProjectVMNetworkBackend(requested string) (string, error) {
	running, stale := detectRunningProjectVM()
	if stale || running == nil {
		return selectVMNetworkBackend(requested, "")
	}
	record, err := readVMSupervisorRecord(currentProjectStore())
	if err != nil {
		return "", fmt.Errorf("read running VM network backend: %w", err)
	}
	stored := record.NetworkBackend
	if stored == "" {
		stored = vmNetworkBackendUser
	}
	return selectVMNetworkBackend(requested, stored)
}

// validateHostNetworkExport prevents a VM-visible export from exposing zaigr's
// host policy, project metadata, or live runtime controls. The
// one intentional exception is the current project's own agent-state export:
// it must resolve to exactly <storeRoot>/agent-state. That directory is a
// normal guest-facing data export; all sibling project/control paths remain
// protected by globalRoot.
func validateHostNetworkExport(workspace, agentState, storeRoot, globalRoot, runtimeRoot string) error {
	store, err := canonicalPathWithMissingSuffix(storeRoot)
	if err != nil {
		return fmt.Errorf("resolve project store path: %w", err)
	}
	global, err := canonicalPathWithMissingSuffix(globalRoot)
	if err != nil {
		return fmt.Errorf("resolve zaigr data path: %w", err)
	}
	runtime, err := canonicalPathWithMissingSuffix(runtimeRoot)
	if err != nil {
		return fmt.Errorf("resolve host runtime path: %w", err)
	}

	workspacePath, err := canonicalPathWithMissingSuffix(workspace)
	if err != nil {
		return fmt.Errorf("resolve workspace export path: %w", err)
	}
	for _, protected := range []struct {
		name string
		path string
	}{
		{name: "project store", path: store},
		{name: "zaigr private data", path: global},
		{name: "host runtime", path: runtime},
	} {
		if pathsOverlap(workspacePath, protected.path) {
			return fmt.Errorf("workspace export %q overlaps Zaigr's protected %s path %q; use a narrower project workspace that does not contain this data path, then retry", workspacePath, protected.name, protected.path)
		}
	}

	if strings.TrimSpace(agentState) == "" {
		return fmt.Errorf("agent-state export path is empty")
	}
	agentPath, err := canonicalPathWithMissingSuffix(agentState)
	if err != nil {
		return fmt.Errorf("resolve agent-state export path: %w", err)
	}
	approvedAgentPath := filepath.Join(store, "agent-state")
	if agentPath != approvedAgentPath {
		return fmt.Errorf("agent-state export must resolve to the current project's private agent-state directory")
	}
	if pathsOverlap(agentPath, runtime) {
		return fmt.Errorf("agent-state export overlaps protected host runtime path")
	}

	// Reject a symlink at the export leaf even if a platform resolves it back
	// to the expected path. The guest mount must name the host-owned directory
	// directly; no symlink target is chmodded or otherwise mutated here.
	if info, statErr := os.Lstat(agentState); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("agent-state export path must not be a symlink")
	} else if statErr != nil && !os.IsNotExist(statErr) {
		return fmt.Errorf("inspect agent-state export path: %w", statErr)
	}
	return nil
}

// canonicalPathWithMissingSuffix resolves all existing symlink components,
// including the deepest existing ancestor of a not-yet-created export path.
func canonicalPathWithMissingSuffix(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("path is empty")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	absolute = filepath.Clean(absolute)
	current := absolute
	var suffix []string
	for {
		resolved, resolveErr := filepath.EvalSymlinks(current)
		if resolveErr == nil {
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			return filepath.Clean(resolved), nil
		}
		if !os.IsNotExist(resolveErr) {
			return "", resolveErr
		}
		if info, statErr := os.Lstat(current); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("cannot resolve dangling symlink %q", current)
		} else if statErr != nil && !os.IsNotExist(statErr) {
			return "", statErr
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", resolveErr
		}
		suffix = append(suffix, filepath.Base(current))
		current = parent
	}
}

func pathsOverlap(a, b string) bool {
	return pathContains(a, b) || pathContains(b, a)
}

func pathContains(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}
