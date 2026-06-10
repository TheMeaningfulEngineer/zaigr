package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const resourceVersionBytes = 6

const (
	setupStateCommitted      = "committed"
	setupStateAwaitingCommit = "awaiting-commit"
	setupStateFailed         = "failed"
)

func canonicalPath(path string) string {
	cleaned := path
	if abs, err := filepath.Abs(path); err == nil {
		cleaned = abs
	}
	cleaned = filepath.Clean(cleaned)
	if resolved, err := filepath.EvalSymlinks(cleaned); err == nil {
		cleaned = resolved
	}
	return cleaned
}

// storeDir returns the project-specific store directory under ~/.zaigr/store/<hash>.
// The hash is derived from the current working directory so each project gets its own store.
func storeDir() string {
	cwd, _ := os.Getwd()
	return storeDirForPath(cwd)
}

func storeDirForPath(path string) string {
	home, _ := os.UserHomeDir()
	h := sha256.Sum256([]byte(canonicalPath(path)))
	return filepath.Join(home, ".zaigr", "store", fmt.Sprintf("%x", h[:4])[:7])
}

func storeCommittedSetupsDir() string {
	return filepath.Join(storeDir(), setupStateCommitted)
}

func storeAwaitingCommitSetupsDir() string {
	return filepath.Join(storeDir(), setupStateAwaitingCommit)
}

func storeFailedSetupsDir() string {
	return filepath.Join(storeDir(), setupStateFailed)
}

func storeLegacyCommittedSetupsDir() string {
	return filepath.Join(storeDir(), "steps")
}

func storeLegacyAwaitingCommitSetupsDir() string {
	return filepath.Join(storeDir(), "pending")
}

func migrateLegacySetupStateDir(oldDir string, newDir string) error {
	if oldDir == newDir {
		return nil
	}
	if _, err := os.Stat(oldDir); os.IsNotExist(err) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(newDir), 0755); err != nil {
		return fmt.Errorf("create setup state dir parent: %w", err)
	}
	if _, err := os.Stat(newDir); os.IsNotExist(err) {
		if err := os.Rename(oldDir, newDir); err == nil {
			return nil
		}
	}
	if err := os.MkdirAll(newDir, 0755); err != nil {
		return fmt.Errorf("create setup state dir: %w", err)
	}
	entries, err := os.ReadDir(oldDir)
	if err != nil {
		return fmt.Errorf("read legacy setup state dir: %w", err)
	}
	for _, entry := range entries {
		oldPath := filepath.Join(oldDir, entry.Name())
		newPath := filepath.Join(newDir, entry.Name())
		if err := os.Rename(oldPath, newPath); err != nil && !os.IsExist(err) {
			return fmt.Errorf("migrate legacy setup state entry %s: %w", entry.Name(), err)
		}
	}
	_ = os.Remove(oldDir)
	return nil
}

func migrateLegacySetupStateDirs() error {
	logDebug("migrating legacy setup state directories")
	if err := migrateLegacySetupStateDir(storeLegacyCommittedSetupsDir(), storeCommittedSetupsDir()); err != nil {
		return err
	}
	if err := migrateLegacySetupStateDir(storeLegacyAwaitingCommitSetupsDir(), storeAwaitingCommitSetupsDir()); err != nil {
		return err
	}
	return nil
}

func storeSetupStateDir(state string) string {
	switch state {
	case setupStateCommitted:
		return storeCommittedSetupsDir()
	case setupStateAwaitingCommit:
		return storeAwaitingCommitSetupsDir()
	case setupStateFailed:
		return storeFailedSetupsDir()
	default:
		return ""
	}
}

func listStoredSetupsRaw(state string) ([]string, error) {
	if err := migrateLegacySetupStateDirs(); err != nil {
		return nil, err
	}
	dir := storeSetupStateDir(state)
	if dir == "" {
		return nil, fmt.Errorf("unknown setup state: %s", state)
	}
	logDebug("listing setup files", "state", state)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s dir: %w", state, err)
	}
	var scripts []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		scripts = append(scripts, filepath.Join(dir, e.Name()))
	}
	sort.Strings(scripts)
	return scripts, nil
}

func listStoredSetups(state string) ([]string, error) {
	if err := migrateLegacySetupStateDirs(); err != nil {
		return nil, err
	}
	dir := storeSetupStateDir(state)
	if dir == "" {
		return nil, fmt.Errorf("unknown setup state: %s", state)
	}
	migrateFailedApply(storeFailedSetupsDir())
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if state == setupStateCommitted {
			// One-time migration from legacy format.
			logDebug("migrating legacy provision script into committed setup state")
			migrateProvisionScript(storeCommittedSetupsDir())
		}
		return nil, nil
	}
	return listStoredSetupsRaw(state)
}

func storeCommittedSetups() ([]string, error) {
	return listStoredSetups(setupStateCommitted)
}

func storeAwaitingCommitSetups() ([]string, error) {
	return listStoredSetups(setupStateAwaitingCommit)
}

func storeFailedSetups() ([]string, error) {
	return listStoredSetups(setupStateFailed)
}

func validateCommittedProjectImage(committed []string) (string, bool, error) {
	if len(committed) == 0 {
		return "", false, nil
	}
	logDebug("hashing committed setup files", "count", len(committed))
	hash, err := hashSteps(committed)
	if err != nil {
		return "", false, err
	}
	imagePath := filepath.Join(storeDir(), fmt.Sprintf("image-%s.qcow2", hash))
	logDebug("checking committed image file", "image", filepath.Base(imagePath))
	if _, err := os.Stat(imagePath); err == nil {
		return imagePath, false, nil
	} else if !os.IsNotExist(err) {
		return "", false, fmt.Errorf("stat image %s: %w", filepath.Base(imagePath), err)
	}
	if _, err := os.Stat(imagePath + ".wip"); err == nil {
		return imagePath + ".wip", false, nil
	} else if !os.IsNotExist(err) {
		return "", false, fmt.Errorf("stat image wip %s: %w", filepath.Base(imagePath)+".wip", err)
	}
	return imagePath, true, nil
}

func migrateProvisionScript(stepsDir string) {
	store := storeDir()
	oldScript := filepath.Join(store, "provision.sh")
	oldScriptName := filepath.Join(store, "script-name")
	data, err := os.ReadFile(oldScript)
	if err != nil {
		return
	}
	if err := os.MkdirAll(stepsDir, 0755); err != nil {
		return
	}
	name := "provision"
	if nameData, err := os.ReadFile(oldScriptName); err == nil {
		name = strings.TrimSpace(string(nameData))
	}
	stepPath := filepath.Join(stepsDir, fmt.Sprintf("001-%s.sh", name))
	_ = os.WriteFile(stepPath, data, 0755)

	newHash, err := hashSteps([]string{stepPath})
	if err != nil {
		return
	}
	newPath := filepath.Join(store, fmt.Sprintf("image-%s.qcow2", newHash))
	if _, err := os.Stat(newPath); err == nil {
		return
	}
	rawMatches, _ := filepath.Glob(filepath.Join(store, "image-*.img"))
	if len(rawMatches) == 1 {
		convertRawToQcow2(rawMatches[0], newPath)
		os.Remove(rawMatches[0])
	}
}

func migrateFailedApply(failedDir string) {
	store := storeDir()
	oldScript := filepath.Join(store, "failed-apply.sh")
	oldName := filepath.Join(store, "failed-apply-name")
	data, err := os.ReadFile(oldScript)
	if err != nil {
		return
	}
	name := "failed-apply"
	if nameData, err := os.ReadFile(oldName); err == nil {
		name = strings.TrimSpace(string(nameData))
	}
	entries, err := os.ReadDir(failedDir)
	if err == nil && len(entries) > 0 {
		return
	}
	if err := os.MkdirAll(failedDir, 0755); err != nil {
		return
	}
	stepPath := filepath.Join(failedDir, fmt.Sprintf("001-%s.sh", name))
	_ = os.WriteFile(stepPath, data, 0755)
}

func storeScriptBaseNameFromPath(path string) string {
	base := filepath.Base(path)
	if len(base) > 4 && base[3] == '-' {
		base = base[4:]
	}
	return strings.TrimSuffix(base, filepath.Ext(base))
}

func contentVersion(content []byte) string {
	sum := sha256.Sum256(content)
	return fmt.Sprintf("%x", sum[:resourceVersionBytes])
}

func contentVersionFromPath(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return contentVersion(content), nil
}

func resourceVersionTimestamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("060102-1504")
}

func resourceDisplayVersion(hash string, t time.Time) string {
	return storedResourceVersionLabel(hash, resourceVersionTimestamp(t))
}

func storedResourceVersionLabel(hash, timestamp string) string {
	if hash == "" {
		return timestamp
	}
	if timestamp == "" {
		return hash
	}
	return hash + "-" + timestamp
}

func contentDisplayVersionFromPath(path string) (string, error) {
	hash, err := contentVersionFromPath(path)
	if err != nil {
		return "", err
	}
	timestamp, err := canonicalVersionTimeForHash(hash)
	if err != nil {
		return "", err
	}
	if timestamp.IsZero() {
		info, err := os.Stat(path)
		if err != nil {
			return "", err
		}
		timestamp = info.ModTime()
	}
	return resourceDisplayVersion(hash, timestamp), nil
}

func versionedResourceIdentity(name, version string) string {
	if name == "" {
		return ""
	}
	if version == "" {
		return name
	}
	return name + "@" + version
}

func storeSetupIdentityFromPath(path string) (string, error) {
	name := storeScriptBaseNameFromPath(path)
	if name == "" {
		return "", nil
	}
	version, err := contentVersionFromPath(path)
	if err != nil {
		return "", err
	}
	return versionedResourceIdentity(name, version), nil
}

func storeSaveScript(state string, content []byte, baseName string) (string, error) {
	if baseName == "" {
		baseName = "provision"
	}
	if err := migrateLegacySetupStateDirs(); err != nil {
		return "", err
	}
	if err := os.MkdirAll(storeSetupStateDir(state), 0755); err != nil {
		return "", fmt.Errorf("create %s dir: %w", state, err)
	}
	existing, err := listStoredSetupsRaw(state)
	if err != nil {
		return "", err
	}
	name := fmt.Sprintf("%03d-%s.sh", len(existing)+1, baseName)
	stepPath := filepath.Join(storeSetupStateDir(state), name)
	if err := os.WriteFile(stepPath, content, 0755); err != nil {
		return "", fmt.Errorf("write %s script: %w", state, err)
	}
	if err := stampScriptVersionTime(stepPath, content); err != nil {
		return "", err
	}
	return stepPath, nil
}

func storeSaveScriptFromPath(state string, sourcePath string) (string, error) {
	content, err := os.ReadFile(sourcePath)
	if err != nil {
		return "", err
	}
	return storeSaveScript(state, content, storeScriptBaseNameFromPath(sourcePath))
}

func storeMoveScripts(fromState string, toState string, scriptPaths []string) ([]string, error) {
	_ = fromState
	if err := migrateLegacySetupStateDirs(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(storeSetupStateDir(toState), 0755); err != nil {
		return nil, fmt.Errorf("create %s dir: %w", toState, err)
	}
	existing, err := listStoredSetupsRaw(toState)
	if err != nil {
		return nil, err
	}
	next := len(existing) + 1
	var moved []string
	for _, script := range scriptPaths {
		content, err := os.ReadFile(script)
		if err != nil {
			return moved, err
		}
		base := storeScriptBaseNameFromPath(script)
		target := filepath.Join(storeSetupStateDir(toState), fmt.Sprintf("%03d-%s.sh", next, base))
		if err := os.WriteFile(target, content, 0755); err != nil {
			return moved, err
		}
		if err := stampScriptVersionTime(target, content); err != nil {
			return moved, err
		}
		next++
		if err := os.Remove(script); err != nil {
			return moved, err
		}
		moved = append(moved, target)
	}
	return moved, nil
}

func storeRemoveAll(state string) {
	_ = migrateLegacySetupStateDirs()
	entries, err := os.ReadDir(storeSetupStateDir(state))
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		_ = os.Remove(filepath.Join(storeSetupStateDir(state), e.Name()))
	}
}

func storeRemove(scriptPath string) {
	_ = os.Remove(scriptPath)
}

func storeProjectHostname() string {
	return "zaigr-" + filepath.Base(storeDir())
}

func storeListScripts(dir string) ([]string, error) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var scripts []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		scripts = append(scripts, filepath.Join(dir, e.Name()))
	}
	sort.Strings(scripts)
	return scripts, nil
}

// hashSteps computes a 7-char hash of steps combined with the base image version.
func hashSteps(steps []string) (string, error) {
	return hashStepsWithExtra(steps, nil)
}

// hashStepsWithExtra is like hashSteps but appends extra bytes before hashing.
func hashStepsWithExtra(steps []string, extra []byte) (string, error) {
	var combined []byte
	for _, s := range steps {
		data, err := os.ReadFile(s)
		if err != nil {
			return "", fmt.Errorf("read step %s: %w", filepath.Base(s), err)
		}
		combined = append(combined, data...)
	}
	combined = append(combined, extra...)
	combined = append(combined, []byte(baseRootfsVersion())...)
	h := sha256.Sum256(combined)
	return fmt.Sprintf("%x", h[:4])[:7], nil
}

// storeFindIncrementalBase looks for the most recent existing image built from a
// prefix of the given steps. Returns the image path and the count of steps already
// committed in it. Returns ("", 0) if no incremental base exists.
func storeFindIncrementalBase(steps []string) (string, int) {
	return storeFindIncrementalBaseLimited(steps, len(steps)-1)
}

func storeFindIncrementalBaseLimited(steps []string, maxPrefixSteps int) (string, int) {
	if len(steps) == 0 {
		return "", 0
	}
	if maxPrefixSteps > len(steps)-1 {
		maxPrefixSteps = len(steps) - 1
	}
	if maxPrefixSteps < 0 {
		maxPrefixSteps = 0
	}
	for i := maxPrefixSteps; i >= 0; i-- {
		hash, err := hashSteps(steps[:i])
		if err != nil {
			continue
		}
		imgPath := filepath.Join(storeDir(), fmt.Sprintf("image-%s.qcow2", hash))
		if _, err := os.Stat(imgPath); err == nil {
			return imgPath, i
		}
	}
	return "", 0
}

// storeImageHash returns a 7-char hash of all committed setups combined with the base image version.
// Zero setups is valid — it represents the base image with no project-specific setups committed.
func storeImageHash() (string, error) {
	steps, err := storeCommittedSetups()
	if err != nil {
		return "", err
	}
	return hashSteps(steps)
}

// storeImagePath returns the versioned image path based on committed setups + base image version.
func storeImagePath() (string, error) {
	hash, err := storeImageHash()
	if err != nil {
		return "", err
	}
	return filepath.Join(storeDir(), fmt.Sprintf("image-%s.qcow2", hash)), nil
}

func storeImagePathForSteps(steps []string) (string, error) {
	hash, err := hashSteps(steps)
	if err != nil {
		return "", err
	}
	return filepath.Join(storeDir(), fmt.Sprintf("image-%s.qcow2", hash)), nil
}

func storeConfigPath() string {
	return filepath.Join(storeDir(), "config")
}

func storeFirewallPath() string {
	return filepath.Join(storeDir(), "firewall")
}

func storeFirewallEntries() ([]string, error) {
	data, err := os.ReadFile(storeFirewallPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read firewall metadata: %w", err)
	}

	seen := make(map[string]struct{})
	entries := make([]string, 0)
	for _, line := range strings.Split(string(data), "\n") {
		entry := strings.TrimSpace(line)
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		if _, ok := seen[entry]; ok {
			continue
		}
		seen[entry] = struct{}{}
		entries = append(entries, entry)
	}
	sort.Strings(entries)
	return entries, nil
}

func storeWriteFirewallEntries(entries []string) error {
	seen := make(map[string]struct{})
	normalized := make([]string, 0, len(entries))
	for _, value := range entries {
		entry := strings.TrimSpace(value)
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		if _, ok := seen[entry]; ok {
			continue
		}
		seen[entry] = struct{}{}
		normalized = append(normalized, entry)
	}
	sort.Strings(normalized)
	if len(normalized) == 0 {
		return os.WriteFile(storeFirewallPath(), []byte{}, 0644)
	}
	return os.WriteFile(storeFirewallPath(), []byte(strings.Join(normalized, "\n")+"\n"), 0644)
}

func storeAppendFirewallEntries(entries []string) error {
	current, err := storeFirewallEntries()
	if err != nil {
		return err
	}
	current = append(current, entries...)
	return storeWriteFirewallEntries(current)
}

func storeRuntimeDir() string {
	return filepath.Join(storeDir(), "runtime")
}

func storeCommittedFirewallSyncMarkerPath() string {
	return filepath.Join(storeRuntimeDir(), "committed-firewall-sync")
}

func storeAppliedGlobalFirewallPath() string {
	return filepath.Join(storeDir(), "global-firewall-applied")
}

func storeReadCommittedFirewallSyncMarker() (string, error) {
	data, err := os.ReadFile(storeCommittedFirewallSyncMarkerPath())
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func storeWriteCommittedFirewallSyncMarker(hash string) error {
	return os.WriteFile(storeCommittedFirewallSyncMarkerPath(), []byte(hash), 0644)
}

func storeAppliedGlobalFirewallEntries() ([]string, error) {
	return readFirewallListFile(storeAppliedGlobalFirewallPath(), "applied global firewall metadata")
}

func storeWriteAppliedGlobalFirewallEntries(entries []string) error {
	return writeFirewallListFile(storeAppliedGlobalFirewallPath(), entries, "applied global firewall metadata")
}

func storeEnsureRuntimeDir() error {
	return os.MkdirAll(storeRuntimeDir(), 0755)
}

func storeClearRuntimeState() error {
	if err := os.RemoveAll(storeRuntimeDir()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove runtime state: %w", err)
	}
	return nil
}

func storeSSHPortPath() string {
	return filepath.Join(storeRuntimeDir(), "ssh-port")
}

func storeSSHPort() (string, error) {
	data, err := os.ReadFile(storeSSHPortPath())
	if err != nil {
		return "", fmt.Errorf("no SSH port configured — run 'zaigr shell' first")
	}
	return strings.TrimSpace(string(data)), nil
}

func storeRAMPath() string {
	return filepath.Join(storeDir(), "ram")
}

func storeRAM() string {
	data, err := os.ReadFile(storeRAMPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func storeCPUsPath() string {
	return filepath.Join(storeDir(), "cpus")
}

func storeCPUs() string {
	data, err := os.ReadFile(storeCPUsPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func storeMonitorSockPath() string {
	return filepath.Join(storeRuntimeDir(), "vm.sock")
}

func storeSerialLogPath() string {
	return filepath.Join(storeDir(), "vm-serial.log")
}

func canonicalVersionTimeForHash(hash string) (time.Time, error) {
	if hash == "" {
		return time.Time{}, nil
	}

	var earliest time.Time
	for _, state := range []string{setupStateCommitted, setupStateAwaitingCommit, setupStateFailed} {
		paths, err := listStoredSetupsRaw(state)
		if err != nil {
			return time.Time{}, err
		}
		for _, path := range paths {
			candidateHash, err := contentVersionFromPath(path)
			if err != nil {
				return time.Time{}, err
			}
			if candidateHash != hash {
				continue
			}
			info, err := os.Stat(path)
			if err != nil {
				return time.Time{}, err
			}
			if earliest.IsZero() || info.ModTime().Before(earliest) {
				earliest = info.ModTime()
			}
		}
	}

	return earliest, nil
}

func stampScriptVersionTime(path string, content []byte) error {
	hash := contentVersion(content)
	timestamp, err := canonicalVersionTimeForHash(hash)
	if err != nil {
		return fmt.Errorf("resolve version timestamp for %s: %w", filepath.Base(path), err)
	}
	if timestamp.IsZero() {
		timestamp = time.Now().UTC()
	}
	if err := os.Chtimes(path, timestamp, timestamp); err != nil {
		return fmt.Errorf("stamp version timestamp for %s: %w", filepath.Base(path), err)
	}
	return nil
}

func storeDisk() string {
	data, err := os.ReadFile(storeConfigPath())
	if err != nil {
		return "unknown"
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "disk=") {
			return strings.TrimPrefix(line, "disk=")
		}
	}
	return "unknown"
}

type storedPresetSelection struct {
	Name    string
	Version string
	Time    string
}

func storePresetSelectionPath() string {
	return filepath.Join(storeDir(), "preset")
}

func storeWritePresetSelection(name, version string) error {
	if name == "" {
		return storeClearPresetSelection()
	}
	if err := os.MkdirAll(storeDir(), 0755); err != nil {
		return fmt.Errorf("create store dir: %w", err)
	}
	content := fmt.Sprintf(
		"name=%s\nversion=%s\ntime=%s\n",
		name,
		version,
		resourceVersionTimestamp(time.Now()),
	)
	if err := os.WriteFile(storePresetSelectionPath(), []byte(content), 0644); err != nil {
		return fmt.Errorf("write preset selection: %w", err)
	}
	return nil
}

func storeReadPresetSelection() (storedPresetSelection, bool, error) {
	data, err := os.ReadFile(storePresetSelectionPath())
	if err != nil {
		if os.IsNotExist(err) {
			return storedPresetSelection{}, false, nil
		}
		return storedPresetSelection{}, false, fmt.Errorf("read preset selection: %w", err)
	}
	return parseStoredPresetSelection(data)
}

func parseStoredPresetSelection(data []byte) (storedPresetSelection, bool, error) {
	var selection storedPresetSelection
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "name":
			selection.Name = value
		case "version":
			selection.Version = value
		case "time":
			selection.Time = value
		}
	}
	if selection.Name == "" {
		return storedPresetSelection{}, false, nil
	}
	return selection, true, nil
}

func storeClearPresetSelection() error {
	if err := os.Remove(storePresetSelectionPath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove preset selection: %w", err)
	}
	return nil
}
