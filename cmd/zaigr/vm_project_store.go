package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const unknownProjectPathLabel = "(unknown path)"

type projectStore struct {
	Hash string
	Path string
}

const baseImageVersionFileName = "base-image-version"

func currentProjectStore() projectStore {
	path := storeDir()
	return projectStore{
		Hash: filepath.Base(path),
		Path: path,
	}
}

func projectStoreRoot() string {
	return filepath.Join(zaigDir(), "store")
}

func listProjectStores() ([]projectStore, error) {
	entries, err := os.ReadDir(projectStoreRoot())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read project store root: %w", err)
	}

	stores := make([]projectStore, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		store := projectStore{
			Hash: entry.Name(),
			Path: filepath.Join(projectStoreRoot(), entry.Name()),
		}
		initialized, err := isProjectInitialized(store.Path)
		if err != nil {
			return nil, err
		}
		if initialized {
			stores = append(stores, store)
		}
	}
	sort.Slice(stores, func(i, j int) bool {
		return stores[i].Hash < stores[j].Hash
	})
	return stores, nil
}

func resolveProjectStoreHash(hash string) (projectStore, error) {
	if hash == "" || hash != filepath.Base(hash) || strings.ContainsAny(hash, `/\`) {
		return projectStore{}, fmt.Errorf("invalid project store hash: %s", hash)
	}
	store := projectStore{
		Hash: hash,
		Path: filepath.Join(projectStoreRoot(), hash),
	}
	initialized, err := isProjectInitialized(store.Path)
	if err != nil {
		return projectStore{}, err
	}
	if !initialized {
		return projectStore{}, fmt.Errorf("project store not found: %s", hash)
	}
	return store, nil
}

func resolveProjectStoreHashes(hashes []string) ([]projectStore, error) {
	stores := make([]projectStore, 0, len(hashes))
	for _, hash := range hashes {
		store, err := resolveProjectStoreHash(hash)
		if err != nil {
			return nil, err
		}
		stores = append(stores, store)
	}
	return stores, nil
}

func (store projectStore) setupStateDir(state string) string {
	switch state {
	case setupStateCommitted:
		return filepath.Join(store.Path, setupStateCommitted)
	case setupStateAwaitingCommit:
		return filepath.Join(store.Path, setupStateAwaitingCommit)
	case setupStateFailed:
		return filepath.Join(store.Path, setupStateFailed)
	default:
		return ""
	}
}

func (store projectStore) listSetups(state string) ([]string, error) {
	dir := store.setupStateDir(state)
	if dir == "" {
		return nil, fmt.Errorf("unknown setup state: %s", state)
	}
	return storeListScripts(dir)
}

func (store projectStore) committedSetups() ([]string, error) {
	return store.listSetups(setupStateCommitted)
}

func (store projectStore) awaitingCommitSetups() ([]string, error) {
	return store.listSetups(setupStateAwaitingCommit)
}

func (store projectStore) failedSetups() ([]string, error) {
	return store.listSetups(setupStateFailed)
}

func (store projectStore) imageHash() (string, error) {
	steps, err := store.committedSetups()
	if err != nil {
		return "", err
	}
	return hashSteps(steps)
}

func (store projectStore) imagePath() (string, error) {
	hash, err := store.imageHash()
	if err != nil {
		return "", err
	}
	return filepath.Join(store.Path, fmt.Sprintf("image-%s.qcow2", hash)), nil
}

func (store projectStore) baseImageVersionPath() string {
	return filepath.Join(store.Path, baseImageVersionFileName)
}

func (store projectStore) readBaseImageVersion() (string, bool, error) {
	data, err := os.ReadFile(store.baseImageVersionPath())
	if os.IsNotExist(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("read recorded base image version: %w", err)
	}
	return strings.TrimSpace(string(data)), true, nil
}

func (store projectStore) writeBaseImageVersion(version string) error {
	if err := os.MkdirAll(store.Path, 0755); err != nil {
		return fmt.Errorf("create project store: %w", err)
	}
	return os.WriteFile(store.baseImageVersionPath(), []byte(fmt.Sprintf("%s\n", version)), 0644)
}

func (store projectStore) validateCommittedProjectImage(committed []string) (string, bool, error) {
	if len(committed) == 0 {
		return "", false, nil
	}
	hash, err := hashSteps(committed)
	if err != nil {
		return "", false, err
	}
	imagePath := filepath.Join(store.Path, fmt.Sprintf("image-%s.qcow2", hash))
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

func (store projectStore) configPath() string {
	return filepath.Join(store.Path, "config")
}

func (store projectStore) firewallPath() string {
	return filepath.Join(store.Path, "firewall")
}

func (store projectStore) runtimeDir() string {
	return filepath.Join(store.Path, "runtime")
}

func (store projectStore) agentStateDir() string {
	return filepath.Join(store.Path, "agent-state")
}

func (store projectStore) ensureAgentStateDir() error {
	dir := store.agentStateDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create agent state dir: %w", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return fmt.Errorf("secure agent state dir: %w", err)
	}
	return nil
}

func (store projectStore) clearRuntimeState() error {
	if err := os.RemoveAll(store.runtimeDir()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove runtime state: %w", err)
	}
	return nil
}

func (store projectStore) sshPortPath() string {
	return filepath.Join(store.runtimeDir(), "ssh-port")
}

func (store projectStore) sshPort() (string, error) {
	data, err := os.ReadFile(store.sshPortPath())
	if err != nil {
		return "", fmt.Errorf("no SSH port configured")
	}
	return strings.TrimSpace(string(data)), nil
}

func (store projectStore) monitorSockPath() string {
	return filepath.Join(store.runtimeDir(), "vm.sock")
}

func (store projectStore) ram() string {
	return readTrimmedFile(filepath.Join(store.Path, "ram"))
}

func (store projectStore) cpus() string {
	return readTrimmedFile(filepath.Join(store.Path, "cpus"))
}

func (store projectStore) disk() string {
	data, err := os.ReadFile(store.configPath())
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

func (store projectStore) projectPathPath() string {
	return filepath.Join(store.Path, "project-path")
}

func (store projectStore) readProjectPath() (string, bool, error) {
	data, err := os.ReadFile(store.projectPathPath())
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("read project path: %w", err)
	}
	path := strings.TrimSpace(string(data))
	if path == "" {
		return "", false, nil
	}
	return path, true, nil
}

func (store projectStore) writeProjectPath(path string) error {
	if err := os.MkdirAll(store.Path, 0755); err != nil {
		return fmt.Errorf("create project store: %w", err)
	}
	return os.WriteFile(store.projectPathPath(), []byte(path+"\n"), 0644)
}

func storeWriteCurrentProjectPath() error {
	return currentProjectStore().writeProjectPath(canonicalPath("."))
}

func (store projectStore) firewallEntries() ([]string, error) {
	data, err := os.ReadFile(store.firewallPath())
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

func (store projectStore) presetSelectionPath() string {
	return filepath.Join(store.Path, "preset")
}

func (store projectStore) readPresetSelection() (storedPresetSelection, bool, error) {
	data, err := os.ReadFile(store.presetSelectionPath())
	if err != nil {
		if os.IsNotExist(err) {
			return storedPresetSelection{}, false, nil
		}
		return storedPresetSelection{}, false, fmt.Errorf("read preset selection: %w", err)
	}
	return parseStoredPresetSelection(data)
}

func readTrimmedFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
