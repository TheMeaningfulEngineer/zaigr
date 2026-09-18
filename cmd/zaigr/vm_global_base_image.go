package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	globalBaseManifestSchema = 1
	globalBaseBuildDisk      = defaultDiskSize
	projectBackingFileName   = "base-backing.json"
)

type globalBaseManifest struct {
	Schema         int                 `json:"schema"`
	RuntimeVersion string              `json:"runtime_version"`
	Revision       string              `json:"revision"`
	SourceImage    string              `json:"source_image"`
	UserUID        int                 `json:"user_uid,omitempty"`
	Applied        []appliedSetup      `json:"applied_setups,omitempty"`
	Firewall       []string            `json:"firewall_entries,omitempty"`
	SetupFirewall  map[string][]string `json:"setup_firewall,omitempty"`
	CreatedAt      string              `json:"created_at"`
}

type projectBackingPin struct {
	Schema         int    `json:"schema"`
	Kind           string `json:"kind"`
	RuntimeVersion string `json:"runtime_version"`
	Revision       string `json:"revision,omitempty"`
	Disk           string `json:"disk"`
	Path           string `json:"path"`
}

type baseImageSelection struct {
	BackingPath string
	Pin         projectBackingPin
	Applied     []appliedSetup
	Firewall    []string
}

func globalBaseRoot() string         { return filepath.Join(zaigDir(), "base-images", "custom") }
func globalBaseManifestPath() string { return filepath.Join(globalBaseRoot(), "current.json") }
func globalBaseLockPath() string     { return filepath.Join(globalBaseRoot(), "mutation.lock") }
func globalBaseStagingRoot() string  { return filepath.Join(globalBaseRoot(), "staging") }
func globalBaseRevisionRoot(revision string) string {
	return filepath.Join(globalBaseRoot(), "revisions", revision)
}

func (store projectStore) backingPinPath() string {
	return filepath.Join(store.Path, projectBackingFileName)
}

func (store projectStore) writeBackingPin(pin projectBackingPin) error {
	body, err := json.MarshalIndent(pin, "", "  ")
	if err != nil {
		return fmt.Errorf("serialize project backing pin: %w", err)
	}
	return writeFileAtomically(store.backingPinPath(), append(body, '\n'), 0644)
}

func (store projectStore) readBackingPin() (projectBackingPin, bool, error) {
	body, err := os.ReadFile(store.backingPinPath())
	if os.IsNotExist(err) {
		return projectBackingPin{}, false, nil
	}
	if err != nil {
		return projectBackingPin{}, false, fmt.Errorf("read project backing pin: %w", err)
	}
	var pin projectBackingPin
	if err := json.Unmarshal(body, &pin); err != nil {
		return projectBackingPin{}, false, fmt.Errorf("parse project backing pin: %w", err)
	}
	if pin.Schema != 1 || pin.Path == "" || pin.RuntimeVersion == "" || pin.Disk == "" {
		return projectBackingPin{}, false, fmt.Errorf("invalid project backing pin; project data was not changed")
	}
	return pin, true, nil
}

func readGlobalBaseManifest() (globalBaseManifest, bool, error) {
	body, err := os.ReadFile(globalBaseManifestPath())
	if os.IsNotExist(err) {
		return globalBaseManifest{}, false, nil
	}
	if err != nil {
		return globalBaseManifest{}, false, fmt.Errorf("read global base image manifest: %w; run 'zaigr global base-image reset' to recover", err)
	}
	var manifest globalBaseManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return globalBaseManifest{}, false, fmt.Errorf("parse global base image manifest: %w; run 'zaigr global base-image reset' to recover", err)
	}
	if manifest.Schema != globalBaseManifestSchema || manifest.RuntimeVersion == "" || manifest.Revision == "" || manifest.SourceImage == "" {
		return globalBaseManifest{}, false, fmt.Errorf("invalid global base image manifest; run 'zaigr global base-image reset' to recover")
	}
	if manifest.UserUID < 0 || uint64(manifest.UserUID) >= 4294967295 {
		return globalBaseManifest{}, false, fmt.Errorf("invalid guest user UID in global base image manifest; run 'zaigr global base-image reset' to recover")
	}
	if manifest.Revision != filepath.Base(manifest.Revision) || strings.ContainsAny(manifest.Revision, `/\\`) || manifest.Revision == "." || manifest.Revision == ".." {
		return globalBaseManifest{}, false, fmt.Errorf("invalid global base image revision; run 'zaigr global base-image reset' to recover")
	}
	seen := make(map[string]struct{}, len(manifest.Applied))
	for _, record := range manifest.Applied {
		if !isValidResourceName(record.Name) || record.Version == "" || record.ProjectLocal || record.Inherited {
			return globalBaseManifest{}, false, fmt.Errorf("invalid applied setup in global base image manifest; run 'zaigr global base-image reset' to recover")
		}
		if _, ok := seen[record.Name]; ok {
			return globalBaseManifest{}, false, fmt.Errorf("duplicate applied setup %s in global base image manifest; run 'zaigr global base-image reset' to recover", record.Name)
		}
		seen[record.Name] = struct{}{}
	}
	manifestFirewall := make(map[string]struct{}, len(manifest.Firewall))
	for _, entry := range manifest.Firewall {
		if !isValidFirewallDomain(entry) {
			return globalBaseManifest{}, false, fmt.Errorf("invalid firewall entry in global base image manifest; run 'zaigr global base-image reset' to recover")
		}
		if _, ok := manifestFirewall[entry]; ok {
			return globalBaseManifest{}, false, fmt.Errorf("duplicate firewall entry in global base image manifest; run 'zaigr global base-image reset' to recover")
		}
		manifestFirewall[entry] = struct{}{}
	}
	groupFirewall := make(map[string]struct{})
	for name, entries := range manifest.SetupFirewall {
		if _, ok := seen[name]; !ok {
			return globalBaseManifest{}, false, fmt.Errorf("unknown setup firewall group in global base image manifest; run 'zaigr global base-image reset' to recover")
		}
		for _, entry := range entries {
			if !isValidFirewallDomain(entry) {
				return globalBaseManifest{}, false, fmt.Errorf("invalid setup firewall entry in global base image manifest; run 'zaigr global base-image reset' to recover")
			}
			groupFirewall[entry] = struct{}{}
		}
	}
	if len(groupFirewall) != len(manifestFirewall) {
		return globalBaseManifest{}, false, fmt.Errorf("inconsistent firewall metadata in global base image manifest; run 'zaigr global base-image reset' to recover")
	}
	for entry := range groupFirewall {
		if _, ok := manifestFirewall[entry]; !ok {
			return globalBaseManifest{}, false, fmt.Errorf("inconsistent firewall metadata in global base image manifest; run 'zaigr global base-image reset' to recover")
		}
	}
	if !filepath.IsAbs(manifest.SourceImage) || !pathWithin(globalBaseRevisionRoot(manifest.Revision), manifest.SourceImage) {
		return globalBaseManifest{}, false, fmt.Errorf("invalid global base image path in manifest; run 'zaigr global base-image reset' to recover")
	}
	if manifest.RuntimeVersion != baseRootfsVersion() {
		// This is a disposable preparation of the bundled factory image, not
		// a user customization. Select the new factory runtime and let first
		// use prepare it again. Keep the old revision for pinned projects.
		if manifest.UserUID != 0 && len(manifest.Applied) == 0 {
			return globalBaseManifest{}, false, nil
		}
		return manifest, true, fmt.Errorf("custom global base image runtime %s is incompatible with bundled runtime %s; run 'zaigr global base-image reset' and reapply setups", manifest.RuntimeVersion, baseRootfsVersion())
	}
	info, err := os.Stat(manifest.SourceImage)
	if err != nil || !info.Mode().IsRegular() {
		return manifest, true, fmt.Errorf("custom global base image is unavailable at %s; run 'zaigr global base-image reset' to recover", manifest.SourceImage)
	}
	qemuImg := findTool("qemu-img", "/usr/bin/qemu-img")
	if out, err := exec.Command(qemuImg, "check", "-f", "qcow2", "--output=json", manifest.SourceImage).CombinedOutput(); err != nil {
		return manifest, true, fmt.Errorf("custom global base image is damaged: %s; run 'zaigr global base-image reset' to recover", strings.TrimSpace(string(out)))
	}
	return manifest, true, nil
}

func pathWithin(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func resolveCurrentBaseSelection(disk, ram, cpu string) (baseImageSelection, error) {
	manifest, customized, err := ensureHostUserBase(ram, cpu)
	if err != nil {
		return baseImageSelection{}, err
	}
	if !customized {
		path, err := ensureSharedBaseImage(disk)
		if err != nil {
			return baseImageSelection{}, err
		}
		return baseImageSelection{BackingPath: path, Pin: projectBackingPin{
			Schema: 1, Kind: "factory", RuntimeVersion: baseRootfsVersion(), Disk: disk, Path: path,
		}}, nil
	}
	path, err := ensureCustomBaseVariant(manifest, disk)
	if err != nil {
		return baseImageSelection{}, err
	}
	applied := append([]appliedSetup(nil), manifest.Applied...)
	for i := range applied {
		applied[i].Inherited = true
		applied[i].ProjectLocal = false
	}
	return baseImageSelection{
		BackingPath: path,
		Pin:         projectBackingPin{Schema: 1, Kind: "custom", RuntimeVersion: manifest.RuntimeVersion, Revision: manifest.Revision, Disk: disk, Path: path},
		Applied:     applied,
		Firewall:    append([]string(nil), manifest.Firewall...),
	}, nil
}

func ensureCustomBaseVariant(manifest globalBaseManifest, disk string) (string, error) {
	diskID := contentVersion([]byte(disk))[:12]
	path := filepath.Join(globalBaseRevisionRoot(manifest.Revision), "sizes", diskID, "base.qcow2")
	if ready, err := customBaseImageReady(path); ready || err != nil {
		return path, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return "", err
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return "", fmt.Errorf("open custom base variant lock: %w", err)
	}
	defer func() { _ = lock.Close() }()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return "", fmt.Errorf("lock custom base variant: %w", err)
	}
	defer func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) }()
	if ready, err := customBaseImageReady(path); ready || err != nil {
		return path, err
	}
	wip, err := os.CreateTemp(filepath.Dir(path), ".base.qcow2.wip-*")
	if err != nil {
		return "", err
	}
	wipPath := wip.Name()
	_ = wip.Close()
	_ = os.Remove(wipPath)
	defer func() { _ = os.Remove(wipPath) }()
	if err := expandCustomBaseImage(manifest.SourceImage, wipPath, disk); err != nil {
		return "", fmt.Errorf("prepare customized base image at disk size %s: %w", disk, err)
	}
	if err := os.Chmod(wipPath, 0444); err != nil {
		return "", err
	}
	if err := os.Rename(wipPath, path); err != nil {
		return "", err
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return "", err
	}
	return path, nil
}

func customBaseImageReady(path string) (bool, error) {
	ready, err := sharedBaseImageReady(path)
	if !ready || err != nil {
		return ready, err
	}
	qemuImg := findTool("qemu-img", "/usr/bin/qemu-img")
	if out, err := exec.Command(qemuImg, "check", "-f", "qcow2", "--output=json", path).CombinedOutput(); err != nil {
		return false, fmt.Errorf("customized base image variant is damaged at %s: %s; run 'zaigr global base-image reset' to recover", path, strings.TrimSpace(string(out)))
	}
	return true, nil
}

func expandCustomBaseImage(source, output, disk string) error {
	raw := output + ".raw"
	defer func() { _ = os.Remove(raw) }()
	qemuImg := findTool("qemu-img", "/usr/bin/qemu-img")
	if out, err := exec.Command(qemuImg, "convert", "-f", "qcow2", "-O", "raw", source, raw).CombinedOutput(); err != nil {
		return fmt.Errorf("extract compact custom image: %s", strings.TrimSpace(string(out)))
	}
	target, err := diskSizeBytes(disk)
	if err != nil {
		return err
	}
	info, err := os.Stat(raw)
	if err != nil {
		return err
	}
	if target < info.Size() {
		return fmt.Errorf("installed filesystem requires at least %d bytes; %s is too small", info.Size(), disk)
	}
	if err := os.Truncate(raw, target); err != nil {
		return fmt.Errorf("resize custom image file: %w", err)
	}
	if err := checkExt4(raw); err != nil {
		return err
	}
	resize2fs := findTool("resize2fs", "/sbin/resize2fs")
	if out, err := exec.Command(resize2fs, raw).CombinedOutput(); err != nil {
		return fmt.Errorf("expand custom filesystem: %s", strings.TrimSpace(string(out)))
	}
	return convertRawToQcow2(raw, output)
}

func diskSizeBytes(value string) (int64, error) {
	probe, err := os.CreateTemp("", "zaigr-disk-size-*")
	if err != nil {
		return 0, err
	}
	path := probe.Name()
	if err := probe.Close(); err != nil {
		_ = os.Remove(path)
		return 0, err
	}
	defer func() { _ = os.Remove(path) }()
	if out, err := exec.Command("truncate", "-s", value, path).CombinedOutput(); err != nil {
		return 0, fmt.Errorf("invalid disk size %s: %s", value, strings.TrimSpace(string(out)))
	}
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	if info.Size() <= 0 {
		return 0, fmt.Errorf("invalid disk size: %s", value)
	}
	return info.Size(), nil
}

func checkExt4(path string) error {
	e2fsck := findTool("e2fsck", "/sbin/e2fsck")
	out, err := exec.Command(e2fsck, "-f", "-y", path).CombinedOutput()
	if err == nil {
		return nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return nil
	}
	return fmt.Errorf("check custom filesystem: %s", strings.TrimSpace(string(out)))
}

func acquireGlobalBaseMutationLock() (*os.File, error) {
	if err := os.MkdirAll(globalBaseRoot(), 0755); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(globalBaseLockPath(), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		_ = lock.Close()
		return nil, err
	}
	return lock, nil
}

func releaseGlobalBaseMutationLock(lock *os.File) {
	if lock == nil {
		return
	}
	_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	_ = lock.Close()
}

func cmdGlobalBaseImageStatus() error {
	manifest, customized, err := readGlobalBaseManifest()
	if err != nil {
		// Runtime mismatches retain enough metadata to make status inspectable.
		if customized && manifest.Revision != "" {
			fmt.Printf("mode: customized (unusable)\nruntime: %s\nbundled runtime: %s\nrevision: %s\n", manifest.RuntimeVersion, baseRootfsVersion(), manifest.Revision)
			for _, record := range manifest.Applied {
				fmt.Printf("setup: %s  %s\n", record.Name, record.Version)
			}
		}
		return err
	}
	if !customized || (manifest.UserUID != 0 && len(manifest.Applied) == 0) {
		fmt.Printf("mode: factory\nruntime: %s\nsetups: (none)\n", baseRootfsVersion())
		return nil
	}
	fmt.Printf("mode: customized\nruntime: %s\nrevision: %s\n", manifest.RuntimeVersion, manifest.Revision)
	if len(manifest.Applied) == 0 {
		fmt.Println("setups: (none)")
	}
	for _, record := range manifest.Applied {
		fmt.Printf("setup: %s  %s\n", record.Name, record.Version)
	}
	return nil
}

func cmdGlobalBaseImageReset() error {
	lock, err := acquireGlobalBaseMutationLock()
	if err != nil {
		return fmt.Errorf("lock global base image: %w", err)
	}
	defer releaseGlobalBaseMutationLock(lock)
	if err := os.Remove(globalBaseManifestPath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("reset global base image: %w", err)
	}
	if err := syncDirectory(globalBaseRoot()); err != nil {
		return err
	}
	fmt.Printf(":: Global base image reset to bundled factory runtime %s\n", baseRootfsVersion())
	return nil
}

func cmdGlobalBaseImageSetupRun(names []string, ram, cpu string, force bool) error {
	if len(names) == 0 {
		return fmt.Errorf("at least one setup name is required")
	}
	seen := make(map[string]struct{}, len(names))
	definitions := make([]setupDefinition, 0, len(names))
	for _, name := range names {
		if _, ok := seen[name]; ok {
			return fmt.Errorf("setup name repeated more than once: %s", name)
		}
		seen[name] = struct{}{}
		definition, err := loadGlobalSetupDefinition(name)
		if err != nil {
			return err
		}
		definitions = append(definitions, definition)
	}
	ramValue, cpuValue, err := resolveGlobalBuildResources(ram, cpu)
	if err != nil {
		return err
	}
	lock, err := acquireGlobalBaseMutationLock()
	if err != nil {
		return fmt.Errorf("lock global base image: %w", err)
	}
	defer releaseGlobalBaseMutationLock(lock)
	if err := cleanupGlobalBaseStaging(); err != nil {
		return err
	}
	manifest, customized, err := ensureHostUserBaseLocked(ramValue, cpuValue)
	if err != nil {
		return err
	}
	applied := []appliedSetup(nil)
	firewall := []string(nil)
	if customized {
		applied = append(applied, manifest.Applied...)
		firewall = append(firewall, manifest.Firewall...)
	}
	if !force {
		filtered := definitions[:0]
		for _, def := range definitions {
			found := false
			for _, record := range applied {
				if record.Name == def.Name && record.Version == def.Version {
					found = true
					break
				}
			}
			if found {
				fmt.Printf(":: Skipping setup already applied at the current version: %s\n", def.Name)
				continue
			}
			filtered = append(filtered, def)
		}
		definitions = filtered
	}
	if len(definitions) == 0 {
		return nil
	}
	if err := confirmSetupAptCommands(definitions, "global base image setup"); err != nil {
		return err
	}
	return buildAndPublishGlobalBase(manifest, customized, definitions, applied, firewall, ramValue, cpuValue, 0)
}

func cleanupGlobalBaseStaging() error {
	entries, err := os.ReadDir(globalBaseStagingRoot())
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read global base image staging: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "build-") {
			continue
		}
		if err := os.RemoveAll(filepath.Join(globalBaseStagingRoot(), entry.Name())); err != nil {
			return fmt.Errorf("remove stale global base image staging %s: %w", entry.Name(), err)
		}
	}
	return nil
}

func resolveGlobalBuildResources(ramFlag, cpuFlag string) (string, string, error) {
	ram := ramFlag
	if ram == "" {
		ram = os.Getenv("ZAIGR_VM_RAM")
	}
	if ram == "" {
		ram = "4096"
	}
	cpu := cpuFlag
	if cpu == "" {
		cpu = os.Getenv("ZAIGR_VM_CPU")
	}
	if cpu == "" {
		cpu = defaultVMCPUs
	}
	if n, err := strconv.Atoi(ram); err != nil || n <= 0 {
		return "", "", fmt.Errorf("RAM must be a positive number of MB: %s", ram)
	}
	if n, err := strconv.Atoi(cpu); err != nil || n <= 0 {
		return "", "", fmt.Errorf("CPU count must be a positive integer: %s", cpu)
	}
	return ram, cpu, nil
}

func buildAndPublishGlobalBase(previous globalBaseManifest, customized bool, definitions []setupDefinition, applied []appliedSetup, firewall []string, ram, cpu string, userUID int) error {
	setupFirewall := make(map[string][]string, len(previous.SetupFirewall)+len(definitions))
	for name, entries := range previous.SetupFirewall {
		setupFirewall[name] = append([]string(nil), entries...)
	}
	prospectiveApplied := append([]appliedSetup(nil), applied...)
	for _, def := range definitions {
		prospectiveApplied = upsertAppliedSetup(prospectiveApplied, appliedSetup{Name: def.Name, Version: def.Version})
		setupFirewall[def.Name] = append([]string(nil), def.FirewallRules...)
	}
	prospectiveFirewall := make([]string, 0)
	for _, record := range prospectiveApplied {
		prospectiveFirewall = appendUniqueFirewallEntries(prospectiveFirewall, setupFirewall[record.Name])
	}
	if err := os.MkdirAll(globalBaseStagingRoot(), 0755); err != nil {
		return err
	}
	staging, err := os.MkdirTemp(globalBaseStagingRoot(), "build-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(staging) }()
	workspace := filepath.Join(staging, "workspace")
	agentState := filepath.Join(staging, "agent-state")
	runtimeStore := projectStore{Hash: "global-base-build", Path: filepath.Join(staging, "runtime-store")}
	for _, dir := range []string{workspace, agentState, runtimeStore.Path} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	working := filepath.Join(staging, "working.qcow2")
	var backing string
	if customized {
		backing, err = ensureCustomBaseVariant(previous, globalBaseBuildDisk)
		if err != nil {
			return err
		}
	} else {
		backing, err = ensureSharedBaseImage(globalBaseBuildDisk)
		if err != nil {
			return err
		}
	}
	if err := createQcow2Overlay(backing, working); err != nil {
		return err
	}
	scripts := make([]string, 0, len(definitions))
	for i, def := range definitions {
		payload, err := buildSetupPayload(def)
		if err != nil {
			return err
		}
		path := filepath.Join(staging, fmt.Sprintf("%03d-%s.script", i, def.Name))
		if err := os.WriteFile(path, payload, 0600); err != nil {
			return err
		}
		scripts = append(scripts, path)
	}
	staleFirewall := differenceFirewallEntries(firewall, prospectiveFirewall)
	if len(staleFirewall) > 0 {
		groups := []setupFirewallGroup{{Name: "global base setups", Entries: prospectiveFirewall}}
		path := filepath.Join(staging, fmt.Sprintf("%03d-firewall-reconcile.script", len(scripts)))
		if err := os.WriteFile(path, []byte("set -e\n"+firewallSyncCommands(groups, staleFirewall)), 0600); err != nil {
			return err
		}
		scripts = append(scripts, path)
	}
	if userUID != 0 {
		path := filepath.Join(staging, "base-prepare.script")
		payload := fmt.Sprintf("export ZAIGR_MIGRATE_UID=%d\n", userUID) + migrateUserUIDScript
		if err := os.WriteFile(path, []byte(payload), 0600); err != nil {
			return err
		}
		scripts = append(scripts, path)
	}
	port, err := allocateEphemeralSSHPort()
	if err != nil {
		return err
	}
	if err := applyStepsViaSSHInContext(working, scripts, ram, cpu, port, true, agentState, workspace, runtimeStore); err != nil {
		name := guestSetupExecutionStep(err)
		if userUID != 0 && name == "base-prepare.script" {
			return fmt.Errorf("automatic base image preparation failed; global base image was not changed: %w", err)
		}
		for i, path := range scripts {
			if filepath.Base(path) == name {
				if i >= len(definitions) {
					return fmt.Errorf("failed to reconcile global base image firewall: %w", err)
				}
				return fmt.Errorf("failed to run global setup %s: %w", definitions[i].Name, err)
			}
		}
		return err
	}
	revision := fmt.Sprintf("%d-%s", time.Now().UTC().UnixNano(), contentVersion([]byte(strings.Join(func() []string {
		out := make([]string, len(definitions))
		for i, d := range definitions {
			out[i] = d.Identity()
		}
		return out
	}(), "\n")))[:12])
	revisionRoot := globalBaseRevisionRoot(revision)
	if err := os.MkdirAll(revisionRoot, 0755); err != nil {
		return err
	}
	publishedSource := filepath.Join(revisionRoot, "source.qcow2")
	if err := compactCustomBaseImage(working, publishedSource); err != nil {
		return err
	}
	if err := os.Chmod(publishedSource, 0444); err != nil {
		return err
	}
	if err := syncDirectory(revisionRoot); err != nil {
		return err
	}
	applied = prospectiveApplied
	firewall = prospectiveFirewall
	next := globalBaseManifest{Schema: globalBaseManifestSchema, RuntimeVersion: baseRootfsVersion(), Revision: revision, SourceImage: publishedSource, Applied: applied, Firewall: firewall, SetupFirewall: setupFirewall, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	next.UserUID = previous.UserUID
	if userUID != 0 {
		next.UserUID = userUID
	}
	body, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomically(globalBaseManifestPath(), append(body, '\n'), 0644); err != nil {
		return fmt.Errorf("publish global base image selection: %w", err)
	}
	if userUID == 0 {
		fmt.Printf(":: Published customized global base image revision %s\n", revision)
	}
	return nil
}

func differenceFirewallEntries(previous, current []string) []string {
	wanted := make(map[string]struct{}, len(current))
	for _, entry := range current {
		wanted[entry] = struct{}{}
	}
	stale := make([]string, 0)
	for _, entry := range previous {
		if _, ok := wanted[entry]; !ok {
			stale = append(stale, entry)
		}
	}
	return stale
}

func compactCustomBaseImage(source, output string) error {
	raw := output + ".raw-wip"
	defer func() { _ = os.Remove(raw) }()
	qemuImg := findTool("qemu-img", "/usr/bin/qemu-img")
	if out, err := exec.Command(qemuImg, "convert", "-f", "qcow2", "-O", "raw", source, raw).CombinedOutput(); err != nil {
		return fmt.Errorf("flatten customized image: %s", strings.TrimSpace(string(out)))
	}
	if err := checkExt4(raw); err != nil {
		return err
	}
	resize2fs := findTool("resize2fs", "/sbin/resize2fs")
	if out, err := exec.Command(resize2fs, "-M", raw).CombinedOutput(); err != nil {
		return fmt.Errorf("minimize customized filesystem: %s", strings.TrimSpace(string(out)))
	}
	if err := checkExt4(raw); err != nil {
		return err
	}
	dumpe2fs := findTool("dumpe2fs", "/sbin/dumpe2fs")
	out, err := exec.Command(dumpe2fs, "-h", raw).CombinedOutput()
	if err != nil {
		return fmt.Errorf("inspect minimized filesystem: %s", strings.TrimSpace(string(out)))
	}
	var blocks, blockSize int64
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		switch strings.TrimSuffix(fields[0], ":") + " " + strings.TrimSuffix(fields[1], ":") {
		case "Block count":
			blocks, _ = strconv.ParseInt(fields[len(fields)-1], 10, 64)
		case "Block size":
			blockSize, _ = strconv.ParseInt(fields[len(fields)-1], 10, 64)
		}
	}
	if blocks <= 0 || blockSize <= 0 {
		return fmt.Errorf("could not determine minimized filesystem size")
	}
	if err := os.Truncate(raw, blocks*blockSize); err != nil {
		return fmt.Errorf("truncate compact image: %w", err)
	}
	return convertRawToQcow2(raw, output)
}
