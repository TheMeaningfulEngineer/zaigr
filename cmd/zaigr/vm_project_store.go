package main

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const unknownProjectPathLabel = "(unknown path)"

type projectStore struct {
	Hash string
	Path string
}

const baseImageVersionFileName = "base-image-version"

type storedPresetSelection struct {
	Name    string
	Version string
	Time    string
}

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
	// Global inspection must not recover or lock projects just to list them.
	entries, err := os.ReadDir(projectStoreRoot())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read project store root: %w", err)
	}

	stores := make([]projectStore, 0, len(entries))
	for _, entry := range entries {
		// Image replacement uses hidden staging directories alongside stores.
		// They are not project IDs, even while they contain staged metadata.
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		if strings.HasSuffix(entry.Name(), ".legacy-clean-transaction-old") {
			continue
		}
		store := projectStore{
			Hash: entry.Name(),
			Path: filepath.Join(projectStoreRoot(), entry.Name()),
		}
		initialized, err := isProjectInitialized(store.Path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: project %s: %v\n", store.Hash, err)
		}
		if initialized || err != nil {
			stores = append(stores, store)
		}
	}
	sort.Slice(stores, func(i, j int) bool {
		return stores[i].Hash < stores[j].Hash
	})
	return stores, nil
}

func (store projectStore) imagePath() string {
	return store.authoritativeImagePath()
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
	file, err := os.OpenFile(store.baseImageVersionPath(), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(file, "%s\n", version); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return syncDirectory(store.Path)
}

type projectBaseRuntimeVersions struct {
	Running  string
	Required string
}

func projectBaseRuntimeVersionsForStore(store projectStore) projectBaseRuntimeVersions {
	versions := projectBaseRuntimeVersions{Required: baseRootfsVersion()}
	recorded, ok, err := store.readBaseImageVersion()
	if err != nil {
		logDebug("could not read project base runtime version", "store", store.Hash, "err", err)
		return versions
	}
	if ok {
		versions.Running = recorded
	}
	return versions
}

func projectBaseRuntimeVersionsForRunningVM(store projectStore, port string, rootKeyPath string) projectBaseRuntimeVersions {
	versions := projectBaseRuntimeVersionsForStore(store)
	if port == "" || rootKeyPath == "" {
		return versions
	}
	body, err := sshReadPresetCommand(port, rootKeyPath, "cat /etc/base-image-version")
	if err != nil {
		logDebug("could not read running VM base runtime version", "port", port, "err", err)
		return versions
	}
	running := strings.TrimSpace(string(body))
	running = strings.TrimPrefix(running, "base-image:")
	if running != "" {
		versions.Running = running
	}
	return versions
}

func (versions projectBaseRuntimeVersions) upgradeRequired() bool {
	return versions.Running != "" && versions.Required != "" && versions.Running != versions.Required
}

func (versions projectBaseRuntimeVersions) runningLabel() string {
	if versions.Running == "" {
		return "unknown"
	}
	return versions.Running
}

func (versions projectBaseRuntimeVersions) requiredLabel() string {
	if versions.Required == "" {
		return "unknown"
	}
	return versions.Required
}

func (store projectStore) configPath() string {
	return filepath.Join(store.Path, "config")
}

func (store projectStore) hostname() string {
	return "zaigr-" + filepath.Base(store.Path)
}

func (store projectStore) firewallPath() string {
	return filepath.Join(store.Path, "firewall")
}

func (store projectStore) firewallIPsPath() string {
	return filepath.Join(store.Path, "firewall-ips")
}

func validateProjectFirewallIPv4(raw string) (string, error) {
	address, err := netip.ParseAddr(raw)
	if err != nil || !address.Is4() || address.String() != raw {
		return "", fmt.Errorf("invalid exact IPv4 address %q", raw)
	}
	if address.IsUnspecified() || address.IsMulticast() || raw == "255.255.255.255" {
		return "", fmt.Errorf("IPv4 address %s cannot be granted", raw)
	}
	return raw, nil
}

func (store projectStore) firewallIPs() ([]string, error) {
	data, err := os.ReadFile(store.firewallIPsPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read project firewall IP metadata: %w", err)
	}
	if len(data) == 0 {
		return nil, nil
	}
	if data[len(data)-1] != '\n' {
		return nil, fmt.Errorf("invalid project firewall IP metadata: nonempty file must end with a newline")
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	entries := make([]string, 0, len(lines))
	previous := ""
	for _, line := range lines {
		address, validationErr := validateProjectFirewallIPv4(line)
		if validationErr != nil {
			return nil, fmt.Errorf("invalid project firewall IP metadata: %w", validationErr)
		}
		if previous != "" && address <= previous {
			return nil, fmt.Errorf("invalid project firewall IP metadata: entries must be sorted and unique")
		}
		entries = append(entries, address)
		previous = address
	}
	return entries, nil
}

func (store projectStore) writeFirewallIPs(entries []string) error {
	normalized := append([]string(nil), entries...)
	for index, entry := range normalized {
		address, err := validateProjectFirewallIPv4(entry)
		if err != nil {
			return fmt.Errorf("write project firewall IP metadata: %w", err)
		}
		normalized[index] = address
	}
	sort.Strings(normalized)
	for index := 1; index < len(normalized); index++ {
		if normalized[index] == normalized[index-1] {
			return fmt.Errorf("write project firewall IP metadata: duplicate address %s", normalized[index])
		}
	}
	var data []byte
	if len(normalized) > 0 {
		data = []byte(strings.Join(normalized, "\n") + "\n")
	}
	if err := writeFileAtomically(store.firewallIPsPath(), data, 0644); err != nil {
		return fmt.Errorf("write project firewall IP metadata: %w", err)
	}
	return nil
}

func (store projectStore) runtimeDir() string {
	return filepath.Join(store.Path, "runtime")
}

func (store projectStore) ensureRuntimeDir() error {
	return os.MkdirAll(store.runtimeDir(), 0755)
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

func (store projectStore) serialLogPath() string {
	return filepath.Join(store.Path, "vm-serial.log")
}

func (store projectStore) appliedFirewallSyncMarkerPath() string {
	return filepath.Join(store.runtimeDir(), "applied-firewall-sync")
}

func (store projectStore) appliedFirewallIPsPath() string {
	return filepath.Join(store.runtimeDir(), "applied-firewall-ips")
}

func (store projectStore) attemptedFirewallIPsPath() string {
	return filepath.Join(store.runtimeDir(), "attempted-firewall-ips")
}

func (store projectStore) appliedFirewallIPs() ([]string, bool, error) {
	data, err := os.ReadFile(store.appliedFirewallIPsPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("read applied project firewall IP state: %w", err)
	}
	if len(data) == 0 {
		return nil, true, nil
	}
	if data[len(data)-1] != '\n' {
		return nil, false, fmt.Errorf("invalid applied project firewall IP state")
	}
	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n"), true, nil
}

func (store projectStore) writeAppliedFirewallIPs(entries []string) error {
	var data []byte
	if len(entries) > 0 {
		data = []byte(strings.Join(entries, "\n") + "\n")
	}
	if err := writeFileAtomically(store.appliedFirewallIPsPath(), data, 0644); err != nil {
		return fmt.Errorf("record applied project firewall IP state: %w", err)
	}
	return nil
}

func (store projectStore) attemptedFirewallIPs() ([]string, bool, error) {
	data, err := os.ReadFile(store.attemptedFirewallIPsPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("read pending project firewall IP sync: %w", err)
	}
	if len(data) == 0 {
		return nil, true, nil
	}
	if data[len(data)-1] != '\n' {
		return nil, false, fmt.Errorf("invalid pending project firewall IP sync")
	}
	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n"), true, nil
}

func (store projectStore) writeAttemptedFirewallIPs(entries []string) error {
	var data []byte
	if len(entries) > 0 {
		data = []byte(strings.Join(entries, "\n") + "\n")
	}
	if err := writeFileAtomically(store.attemptedFirewallIPsPath(), data, 0644); err != nil {
		return fmt.Errorf("record pending project firewall IP sync: %w", err)
	}
	return nil
}

func (store projectStore) clearAttemptedFirewallIPs() error {
	if err := removeFileIfExists(store.attemptedFirewallIPsPath()); err != nil {
		return fmt.Errorf("clear pending project firewall IP sync: %w", err)
	}
	return nil
}

func (store projectStore) readAppliedFirewallSyncMarker() (string, error) {
	data, err := os.ReadFile(store.appliedFirewallSyncMarkerPath())
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func (store projectStore) writeAppliedFirewallSyncMarker(hash string) error {
	return os.WriteFile(store.appliedFirewallSyncMarkerPath(), []byte(hash), 0644)
}

func (store projectStore) appliedGlobalFirewallPath() string {
	return filepath.Join(store.Path, "global-firewall-applied")
}

func (store projectStore) appliedGlobalFirewallEntries() ([]string, error) {
	return readFirewallListFile(store.appliedGlobalFirewallPath(), "applied global firewall metadata")
}

func (store projectStore) writeAppliedGlobalFirewallEntries(entries []string) error {
	return writeFirewallListFile(store.appliedGlobalFirewallPath(), entries, "applied global firewall metadata")
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

func (store projectStore) ramPath() string {
	return filepath.Join(store.Path, "ram")
}

func (store projectStore) cpus() string {
	return readTrimmedFile(filepath.Join(store.Path, "cpus"))
}

func (store projectStore) cpusPath() string {
	return filepath.Join(store.Path, "cpus")
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
	return writeFileAtomically(store.projectPathPath(), []byte(path+"\n"), 0644)
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

func (store projectStore) writeFirewallEntries(entries []string) error {
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
		return writeFileAtomically(store.firewallPath(), nil, 0644)
	}
	return writeFileAtomically(store.firewallPath(), []byte(strings.Join(normalized, "\n")+"\n"), 0644)
}

func (store projectStore) appendFirewallEntries(entries []string) error {
	current, err := store.firewallEntries()
	if err != nil {
		return err
	}
	return store.writeFirewallEntries(append(current, entries...))
}

func (store projectStore) presetSelectionPath() string {
	return filepath.Join(store.Path, "preset")
}

func (store projectStore) writePresetSelection(name, version string) error {
	if name == "" {
		return store.clearPresetSelection()
	}
	if err := os.MkdirAll(store.Path, 0755); err != nil {
		return fmt.Errorf("create store dir: %w", err)
	}
	content := fmt.Sprintf(
		"name=%s\nversion=%s\ntime=%s\n",
		name,
		version,
		resourceVersionTimestamp(time.Now()),
	)
	if err := os.WriteFile(store.presetSelectionPath(), []byte(content), 0644); err != nil {
		return fmt.Errorf("write preset selection: %w", err)
	}
	return nil
}

func (store projectStore) clearPresetSelection() error {
	if err := os.Remove(store.presetSelectionPath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove preset selection: %w", err)
	}
	return nil
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

func readTrimmedFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
