package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	projectImageFormatVersion = "direct-base-v1"
	projectImageFileName      = "project.qcow2"
	projectImageFormatFile    = "image-format"
	appliedSetupsFileName     = "applied-setups.json"
	setupFailureMarkerFile    = "setup-failed-once"
	setupExecutionIntentFile  = "setup-execution-intent.json"
)

type appliedSetup struct {
	Name                string `json:"name"`
	Version             string `json:"version"`
	ProjectLocal        bool   `json:"project_local,omitempty"`
	Inherited           bool   `json:"inherited,omitempty"`
	MissingAcknowledged bool   `json:"missing_acknowledged,omitempty"`
}

type directSetupExecutionIntent struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	ProjectLocal bool   `json:"project_local,omitempty"`
}

func (store projectStore) imageFormatPath() string {
	return filepath.Join(store.Path, projectImageFormatFile)
}

func (store projectStore) authoritativeImagePath() string {
	return filepath.Join(store.Path, projectImageFileName)
}

func (store projectStore) appliedSetupsPath() string {
	return filepath.Join(store.Path, appliedSetupsFileName)
}

func (store projectStore) setupFailureMarkerPath() string {
	return filepath.Join(store.Path, setupFailureMarkerFile)
}

func (store projectStore) setupExecutionIntentPath() string {
	return filepath.Join(store.agentStateDir(), setupExecutionIntentFile)
}

func (store projectStore) readSetupExecutionIntent() (directSetupExecutionIntent, bool, error) {
	body, err := os.ReadFile(store.setupExecutionIntentPath())
	if err != nil {
		if os.IsNotExist(err) {
			return directSetupExecutionIntent{}, false, nil
		}
		return directSetupExecutionIntent{}, false, fmt.Errorf("read setup execution intent: %w", err)
	}
	var intent directSetupExecutionIntent
	if err := json.Unmarshal(body, &intent); err != nil {
		return directSetupExecutionIntent{}, false, fmt.Errorf("parse setup execution intent: %w", err)
	}
	if intent.Name == "" || intent.Version == "" {
		return directSetupExecutionIntent{}, false, fmt.Errorf("invalid setup execution intent")
	}
	return intent, true, nil
}

func (store projectStore) setupExecutionIntentPersisted(expected directSetupExecutionIntent) (bool, error) {
	actual, ok, err := store.readSetupExecutionIntent()
	if err != nil {
		if _, statErr := os.Stat(store.setupExecutionIntentPath()); statErr == nil {
			return true, err
		}
		return false, err
	}
	if !ok {
		return false, nil
	}
	if actual != expected {
		return true, fmt.Errorf(
			"setup execution intent is for %s (%s), expected %s (%s)",
			actual.Name,
			actual.Version,
			expected.Name,
			expected.Version,
		)
	}
	return true, nil
}

func (store projectStore) removeSetupExecutionIntent() error {
	if err := os.Remove(store.setupExecutionIntentPath()); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("remove setup execution intent: %w", err)
	}
	return syncDirectory(filepath.Dir(store.setupExecutionIntentPath()))
}

func setupExecutionIntentPrelude(intent directSetupExecutionIntent) (string, error) {
	body, err := json.Marshal(intent)
	if err != nil {
		return "", err
	}
	encoded := base64.StdEncoding.EncodeToString(append(body, '\n'))
	return fmt.Sprintf(`intent_dir=/home/user/.zaigr-agent-state
intent_path="$intent_dir/%s"
intent_tmp="$intent_path.tmp.$$"
(
  umask 077
  printf '%%s' '%s' | base64 -d > "$intent_tmp"
  sync "$intent_tmp"
  mv "$intent_tmp" "$intent_path"
  sync "$intent_dir"
)
`, setupExecutionIntentFile, encoded), nil
}

func (store projectStore) usesCurrentImageFormat() (bool, error) {
	data, err := os.ReadFile(store.imageFormatPath())
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("read project image format: %w", err)
	}
	return strings.TrimSpace(string(data)) == projectImageFormatVersion, nil
}

func (store projectStore) writeCurrentImageFormat() error {
	return writeFileAtomically(store.imageFormatPath(), []byte(projectImageFormatVersion+"\n"), 0644)
}

func (store projectStore) requireCurrentImageFormat(command string) error {
	current, err := store.usesCurrentImageFormat()
	if err != nil {
		return err
	}
	if current {
		return nil
	}
	return fmt.Errorf("%s cannot use this incompatible legacy project store; run 'zaigr project rebuild' to replay recoverable applied setups, 'zaigr project clean' to discard it, or 'zaigr project delete'", command)
}

func (store projectStore) readAppliedSetups() ([]appliedSetup, error) {
	data, err := os.ReadFile(store.appliedSetupsPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read applied setups: %w", err)
	}
	var records []appliedSetup
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("parse applied setups: %w", err)
	}
	seen := make(map[string]struct{}, len(records))
	for _, record := range records {
		if record.Name == "" || record.Version == "" {
			return nil, fmt.Errorf("invalid applied setup record")
		}
		identity := fmt.Sprintf("%t:%s", record.ProjectLocal, record.Name)
		if _, exists := seen[identity]; exists {
			return nil, fmt.Errorf("duplicate applied setup record: %s", displaySetupName(record.Name, record.ProjectLocal))
		}
		seen[identity] = struct{}{}
	}
	return records, nil
}

func (store projectStore) writeAppliedSetups(records []appliedSetup) error {
	if len(records) == 0 {
		if err := os.Remove(store.appliedSetupsPath()); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove applied setup state: %w", err)
		}
		return nil
	}
	copyRecords := append([]appliedSetup(nil), records...)
	sort.Slice(copyRecords, func(i, j int) bool {
		if copyRecords[i].Name != copyRecords[j].Name {
			return copyRecords[i].Name < copyRecords[j].Name
		}
		return !copyRecords[i].ProjectLocal && copyRecords[j].ProjectLocal
	})
	body, err := json.MarshalIndent(copyRecords, "", "  ")
	if err != nil {
		return fmt.Errorf("serialize applied setups: %w", err)
	}
	return writeFileAtomically(store.appliedSetupsPath(), append(body, '\n'), 0644)
}

func upsertAppliedSetup(records []appliedSetup, replacement appliedSetup) []appliedSetup {
	updated := make([]appliedSetup, 0, len(records)+1)
	replaced := false
	for _, record := range records {
		if record.Name == replacement.Name && record.ProjectLocal == replacement.ProjectLocal {
			if !replaced {
				updated = append(updated, replacement)
				replaced = true
			}
			continue
		}
		updated = append(updated, record)
	}
	if !replaced {
		updated = append(updated, replacement)
	}
	return updated
}

func removeAppliedSetupIdentity(records []appliedSetup, identity appliedSetup) []appliedSetup {
	updated := make([]appliedSetup, 0, len(records))
	for _, record := range records {
		if record.Name == identity.Name && record.Version == identity.Version && record.ProjectLocal == identity.ProjectLocal {
			continue
		}
		updated = append(updated, record)
	}
	return updated
}

func (store projectStore) hasSetupFailureMarker() (bool, error) {
	_, err := os.Stat(store.setupFailureMarkerPath())
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, fmt.Errorf("stat setup failure marker: %w", err)
}

func (store projectStore) markSetupFailure() error {
	return writeFileAtomically(store.setupFailureMarkerPath(), []byte("1\n"), 0644)
}

func (store projectStore) clearSetupFailureMarker() error {
	if err := os.Remove(store.setupFailureMarkerPath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove setup failure marker: %w", err)
	}
	return nil
}

func writeFileAtomically(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".metadata-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func sharedBaseImagePath(disk string) string {
	return sharedBaseImagePathForVersionAndDisk(baseRootfsVersion(), disk)
}

func sharedBaseImagePathForVersionAndDisk(version string, disk string) string {
	diskID := contentVersion([]byte(disk))[:12]
	return filepath.Join(zaigDir(), "base-images", version, diskID, "base.qcow2")
}

func ensureSharedBaseImage(disk string) (string, error) {
	path := sharedBaseImagePath(disk)
	if ready, err := sharedBaseImageReady(path); ready || err != nil {
		return path, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return "", fmt.Errorf("create shared base directory: %w", err)
	}
	lockPath := path + ".lock"
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return "", fmt.Errorf("open shared base image lock: %w", err)
	}
	defer func() {
		if err := lock.Close(); err != nil {
			logWarn("failed to close shared base image lock", "error", err)
		}
	}()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return "", fmt.Errorf("lock shared base image: %w", err)
	}
	defer func() {
		if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); err != nil {
			logWarn("failed to unlock shared base image", "error", err)
		}
	}()
	if ready, err := sharedBaseImageReady(path); ready || err != nil {
		return path, err
	}
	staleWIPs, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".base.qcow2.wip-*"))
	if err != nil {
		return "", fmt.Errorf("find stale shared base staging files: %w", err)
	}
	for _, staleWIP := range staleWIPs {
		if err := os.Remove(staleWIP); err != nil && !os.IsNotExist(err) {
			return "", fmt.Errorf("remove stale shared base staging file: %w", err)
		}
	}

	wipFile, err := os.CreateTemp(filepath.Dir(path), ".base.qcow2.wip-*")
	if err != nil {
		return "", fmt.Errorf("create shared base staging path: %w", err)
	}
	wip := wipFile.Name()
	if err := wipFile.Close(); err != nil {
		return "", err
	}
	_ = os.Remove(wip)
	defer func() { _ = os.Remove(wip) }()
	if err := buildImageFromEmbeddedBase(wip, disk); err != nil {
		return "", fmt.Errorf("build shared base image: %w", err)
	}
	if err := os.Chmod(wip, 0444); err != nil {
		return "", fmt.Errorf("make shared base image immutable: %w", err)
	}
	if err := os.Rename(wip, path); err != nil {
		return "", fmt.Errorf("publish shared base image: %w", err)
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return "", fmt.Errorf("sync shared base publication: %w", err)
	}
	return path, nil
}

func sharedBaseImageReady(path string) (bool, error) {
	if info, err := os.Stat(path); err == nil {
		if !info.Mode().IsRegular() {
			return false, fmt.Errorf("shared base image is not a regular file: %s", path)
		}
		return true, nil
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("stat shared base image: %w", err)
	}
	return false, nil
}

func createProjectOverlayFromCurrent(path, disk, ram, cpu string) (baseImageSelection, error) {
	selection, err := resolveCurrentBaseSelection(disk, ram, cpu)
	if err != nil {
		return baseImageSelection{}, err
	}
	if err := createQcow2Overlay(selection.BackingPath, path); err != nil {
		return baseImageSelection{}, err
	}
	return selection, nil
}

func compactToDirectProjectOverlay(sourcePath, outputPath string) error {
	store := currentProjectStore()
	pin, ok, err := store.readBackingPin()
	if err != nil {
		return err
	}
	var basePath string
	if ok {
		basePath = pin.Path
	} else {
		version, recorded, err := store.readBaseImageVersion()
		if err != nil {
			return err
		}
		if !recorded || version == "" {
			return fmt.Errorf("project base image version is not recorded")
		}
		disk, _ := resolveDisk("")
		basePath = sharedBaseImagePathForVersionAndDisk(version, disk)
	}
	if _, err := os.Stat(basePath); err != nil {
		return fmt.Errorf("project shared base image is unavailable: %w", err)
	}
	absBase, err := filepath.Abs(basePath)
	if err != nil {
		return err
	}
	qemuImg := findTool("qemu-img", "/usr/bin/qemu-img")
	out, err := exec.Command(qemuImg, "convert", "-f", "qcow2", "-O", "qcow2", sourcePath, outputPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("flatten project overlay: %s", strings.TrimSpace(string(out)))
	}
	out, err = exec.Command(qemuImg, "rebase", "-f", "qcow2", "-b", absBase, "-F", "qcow2", outputPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("rebase compacted project overlay: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func applySetupDirectlyToRunningVM(port string, def setupDefinition, payload []byte) error {
	rootKeyPath, _, err := ensureRootSSHKey()
	if err != nil {
		return fmt.Errorf("prepare root SSH key: %w", err)
	}
	store := currentProjectStore()
	intent := directSetupExecutionIntent{Name: def.Name, Version: def.Version, ProjectLocal: def.ProjectLocal}
	executionStarted := false
	executionDeadline := time.Now().Add(setupExecutionTimeout)
	run := func() error {
		started, runErr := sshRunSetupScriptUntil(port, rootKeyPath, "set -e\n"+string(payload), executionDeadline, &intent)
		executionStarted = started
		persisted, intentErr := store.setupExecutionIntentPersisted(intent)
		if persisted {
			executionStarted = true
		}
		if intentErr != nil {
			return errors.Join(runErr, intentErr)
		}
		return runErr
	}
	err = withTemporaryRootAllowAllFirewallRule(port, rootKeyPath, run)
	if err == nil {
		err = sshSync(port, rootKeyPath)
	}
	if err != nil {
		if executionStarted {
			if stateErr := recordDirectSetupFailure(def); stateErr != nil {
				return fmt.Errorf("setup failed: %w (record failure: %v)", err, stateErr)
			}
		}
		return fmt.Errorf("setup failed: %w", err)
	}
	if err := recordSuccessfulDirectSetup(def); err != nil {
		failureErr := recordDirectSetupFailure(def)
		if failureErr != nil {
			return fmt.Errorf("record applied setup: %w (record failure: %v)", err, failureErr)
		}
		return fmt.Errorf("record applied setup: %w", err)
	}
	fmt.Printf(":: Setup applied to running project VM: %s (%s)\n", displaySetupName(def.Name, def.ProjectLocal), def.Version)
	return nil
}

func applySetupDirectlyToStoppedProject(def setupDefinition, payload []byte, ram string, cpus string) error {
	stagingDir, err := os.MkdirTemp(currentProjectStore().Path, directSetupStagingPrefix+"*")
	if err != nil {
		return fmt.Errorf("create setup staging directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(stagingDir) }()
	scriptPath := filepath.Join(stagingDir, def.Name+".script")
	if err := os.WriteFile(scriptPath, payload, 0600); err != nil {
		return fmt.Errorf("stage setup script: %w", err)
	}
	ram, ramSource := resolveRAM(ram)
	if ramSource == "default" {
		ram = "4096"
	}
	cpus, _ = resolveCPUs(cpus)
	port, err := allocateEphemeralSSHPort()
	if err != nil {
		return err
	}
	intent := directSetupExecutionIntent{Name: def.Name, Version: def.Version, ProjectLocal: def.ProjectLocal}
	err = applyStepsViaSSHWithIntent(currentProjectStore().authoritativeImagePath(), []string{scriptPath}, ram, cpus, port, true, &intent)
	if err != nil {
		if isGuestSetupExecutionError(err) {
			if stateErr := recordDirectSetupFailure(def); stateErr != nil {
				return fmt.Errorf("setup failed: %w (record failure: %v)", err, stateErr)
			}
		}
		return err
	}
	if err := recordSuccessfulDirectSetup(def); err != nil {
		failureErr := recordDirectSetupFailure(def)
		if failureErr != nil {
			return fmt.Errorf("record applied setup: %w (record failure: %v)", err, failureErr)
		}
		return fmt.Errorf("record applied setup: %w", err)
	}
	fmt.Printf(":: Setup applied to stopped project image: %s (%s)\n", displaySetupName(def.Name, def.ProjectLocal), def.Version)
	return nil
}

func recordSuccessfulDirectSetup(def setupDefinition) error {
	store := currentProjectStore()
	records, err := store.readAppliedSetups()
	if err != nil {
		return err
	}
	firewallEntries, err := store.firewallEntries()
	if err != nil {
		return err
	}
	firewallEntries = appendUniqueFirewallEntries(firewallEntries, def.FirewallRules)
	return updateProjectMetadataTransaction(
		store,
		[]string{store.firewallPath(), store.appliedSetupsPath(), store.setupExecutionIntentPath()},
		func() error {
			if err := store.writeFirewallEntries(firewallEntries); err != nil {
				return err
			}
			if err := store.writeAppliedSetups(
				upsertAppliedSetup(records, appliedSetup{Name: def.Name, Version: def.Version, ProjectLocal: def.ProjectLocal}),
			); err != nil {
				return err
			}
			return store.removeSetupExecutionIntent()
		},
	)
}

func recordDirectSetupFailure(def setupDefinition) error {
	return recordDirectSetupFailureForStore(
		currentProjectStore(),
		appliedSetup{Name: def.Name, Version: def.Version, ProjectLocal: def.ProjectLocal},
	)
}

func recordDirectSetupFailureForStore(store projectStore, identity appliedSetup) error {
	records, err := store.readAppliedSetups()
	if err != nil {
		return err
	}
	updated := removeAppliedSetupIdentity(records, identity)
	return updateProjectMetadataTransaction(
		store,
		[]string{store.appliedSetupsPath(), store.setupFailureMarkerPath(), store.setupExecutionIntentPath()},
		func() error {
			if err := store.writeAppliedSetups(updated); err != nil {
				return err
			}
			if err := store.markSetupFailure(); err != nil {
				return err
			}
			return store.removeSetupExecutionIntent()
		},
	)
}

func resolveInterruptedDirectSetup(store projectStore) error {
	intent, ok, err := store.readSetupExecutionIntent()
	if err != nil || !ok {
		return err
	}
	return recordDirectSetupFailureForStore(
		store,
		appliedSetup{Name: intent.Name, Version: intent.Version, ProjectLocal: intent.ProjectLocal},
	)
}
