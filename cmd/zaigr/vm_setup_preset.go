package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

type setupDefinition struct {
	Name          string
	Version       string
	ProjectLocal  bool
	RootPath      string
	ScriptPaths   []string
	FirewallPaths []string
	SourceContent map[string][]byte
	FirewallRules []string
}

type presetDefinition struct {
	Name      string
	Version   string
	RunPath   string
	SetupRefs []string
}

func cmdSetupRun(names []string, ram string, cpu string, force bool) error {
	lock, err := lockCurrentProjectSetup("project setup run")
	if err != nil {
		return err
	}
	defer lock.releaseWithWarning()
	store := currentProjectStore()
	if err := lock.recover(store, "project setup run"); err != nil {
		return err
	}
	if len(names) == 0 {
		return fmt.Errorf("at least one setup name is required")
	}
	logInfo("starting project setup run", "names", strings.Join(names, ","), "ram", ram, "cpu", cpu, "force", force)
	initialized, err := isProjectInitialized(store.Path)
	if err != nil {
		return err
	}
	if initialized {
		if _, err := requireProject("project setup run"); err != nil {
			return err
		}
	}
	if err := requireNoActiveSetupCapture("zaigr project setup run"); err != nil {
		return err
	}
	definitions, err := loadSetupDefinitions(names)
	if err != nil {
		return err
	}
	logDebug("loaded setup definitions", "count", len(definitions))

	bootAfterApply := false
	if !initialized {
		fmt.Printf(":: `zaigr project setup run` will start a project VM to initialize this blank project\n")
		logInfo("project setup run will initialize blank project and boot a VM", "store", store.Path)
		if err := ensureProjectInitializedForVM(ram, cpu); err != nil {
			return err
		}
		bootAfterApply = true
	}
	_, stale := detectRunningProjectVM()
	if stale {
		_ = store.clearRuntimeState()
		logWarn("removed stale project VM marker during project setup run", "runtime_dir", store.runtimeDir())
	}
	if err = resolveProjectImageForCommand(); err != nil {
		return err
	}

	if !force {
		var skippedApplied []string
		definitions, skippedApplied, err = filterSetupDefinitionsByStoredState(definitions)
		if err != nil {
			return err
		}
		printSkippedAppliedSetups(skippedApplied)
		logDebug("filtered setup definitions", "count", len(definitions), "skipped_applied", len(skippedApplied))
	}
	if len(definitions) == 0 && !bootAfterApply {
		return nil
	}

	running, stale := detectRunningProjectVM()
	if stale {
		_ = store.clearRuntimeState()
		running = nil
	}
	if running != nil {
		if ram != "" || cpu != "" {
			return fmt.Errorf("project VM is already running; --ram and --cpu cannot be changed on a running VM")
		}
		logInfo("project setup run will apply to running VM", "port", running.Port, "count", len(definitions))
		return applySetupDefinitionsToVM(running.Port, definitions)
	}

	logInfo("project setup run will apply directly to project image", "count", len(definitions))
	if err := applySetupDefinitionsToImage(definitions, ram, cpu); err != nil {
		return err
	}
	if bootAfterApply {
		if err := offerProjectLocalSetupsBeforeBoot(ram, cpu); err != nil {
			return err
		}
		logInfo("starting project VM after blank-slate project setup run")
		port, err := startPreparedProjectVM(ram, cpu)
		if err != nil {
			return err
		}
		logInfo("project VM started after project setup run", "port", port)
		fmt.Printf(":: Project VM started on port %s\n", port)
	}
	return nil
}

func filterSetupDefinitionsByStoredState(definitions []setupDefinition) ([]setupDefinition, []string, error) {
	applied, err := currentProjectStore().readAppliedSetups()
	if err != nil {
		return nil, nil, err
	}
	appliedSet := make(map[string]appliedSetup, len(applied))
	for _, record := range applied {
		key := fmt.Sprintf("%t:%s", record.ProjectLocal, versionedResourceIdentity(record.Name, record.Version))
		appliedSet[key] = record
	}

	filtered := make([]setupDefinition, 0, len(definitions))
	skippedApplied := make([]string, 0, len(definitions))
	for _, definition := range definitions {
		key := fmt.Sprintf("%t:%s", definition.ProjectLocal, definition.Identity())
		if _, exists := appliedSet[key]; exists {
			skippedApplied = append(skippedApplied, displaySetupName(definition.Name, definition.ProjectLocal))
			continue
		}
		filtered = append(filtered, definition)
	}
	return filtered, skippedApplied, nil
}

func printSkippedAppliedSetups(skippedApplied []string) {
	if len(skippedApplied) > 0 {
		fmt.Printf(
			":: Skipping setups already applied at the current version: %s\n",
			strings.Join(skippedApplied, ", "),
		)
	}
}

func applySetupDefinitionsToVM(port string, definitions []setupDefinition) error {
	if err := confirmSetupAptCommands(definitions, "setup execution"); err != nil {
		return err
	}
	for _, def := range definitions {
		payload, err := buildSetupPayload(def)
		if err != nil {
			return err
		}

		if err := applySetupDirectlyToRunningVM(port, def, payload); err != nil {
			return fmt.Errorf("failed to run setup %s: %w", displaySetupName(def.Name, def.ProjectLocal), err)
		}
	}
	return nil
}

func applySetupDefinitionsToImage(definitions []setupDefinition, ram string, cpu string) error {
	if err := confirmSetupAptCommands(definitions, "setup execution"); err != nil {
		return err
	}
	for _, def := range definitions {
		payload, err := buildSetupPayload(def)
		if err != nil {
			return err
		}

		if err = applySetupDirectlyToStoppedProject(def, payload, ram, cpu); err != nil {
			return fmt.Errorf("failed to run setup %s: %w", displaySetupName(def.Name, def.ProjectLocal), err)
		}
	}
	return nil
}

func loadPresetPlan(preset string, extraSetups []string) (*presetDefinition, []byte, []setupDefinition, error) {
	if preset != "" {
		if err := ensureBuiltinPresetStructure(preset); err != nil {
			return nil, nil, nil, err
		}
	}

	names := append([]string{}, extraSetups...)
	var presetDef *presetDefinition

	if preset != "" {
		loadedPreset, err := loadPreset(preset)
		if err != nil {
			return nil, nil, nil, err
		}
		presetDef = &loadedPreset
		if len(loadedPreset.SetupRefs) > 0 {
			names = append(loadedPreset.SetupRefs, names...)
		}

		runScript, err := loadPresetRunScript(loadedPreset.RunPath)
		if err != nil {
			return nil, nil, nil, err
		}
		defs, err := loadSetupDefinitions(uniqueOrderedNames(names))
		if err != nil {
			return nil, nil, nil, err
		}
		return presetDef, runScript, defs, nil
	}

	defs, err := loadSetupDefinitions(uniqueOrderedNames(names))
	if err != nil {
		return nil, nil, nil, err
	}
	return nil, nil, defs, nil
}

func runPresetInVM(port string, presetName string, script []byte) error {
	if !isValidResourceName(presetName) {
		return fmt.Errorf("invalid preset name: %s", presetName)
	}
	rootKeyPath, _, err := ensureRootSSHKey()
	if err != nil {
		return fmt.Errorf("prepare trusted preset launcher: %w", err)
	}
	if _, err := sshReadPresetCommand(
		port,
		rootKeyPath,
		"test -x /usr/local/lib/zaigr/run-preset-isolated",
	); err != nil {
		versions := projectBaseRuntimeVersionsForRunningVM(currentProjectStore(), port, rootKeyPath)
		return fmt.Errorf(
			"project VM cannot start isolated presets because its runtime is outdated or missing preset-isolation support\n"+
				"  running VM base runtime: %s\n"+
				"  required base runtime: %s\n"+
				"Stop it with `zaigr project vm stop`, then run `zaigr project rebuild` "+
				"(preset agent state is preserved)",
			versions.runningLabel(),
			versions.requiredLabel(),
		)
	}
	if err := ensurePresetAgentStateDir(presetName); err != nil {
		return err
	}
	if err := rejectHardLinkedPresetState(presetName); err != nil {
		return err
	}
	return sshRunPresetCommand(port, rootKeyPath, presetName, string(script))
}

func ensurePresetAgentStateDir(presetName string) error {
	store := currentProjectStore()
	if err := store.ensureAgentStateDir(); err != nil {
		return err
	}
	path := filepath.Join(store.agentStateDir(), presetName)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if err := os.Mkdir(path, 0700); err != nil && !os.IsExist(err) {
			return fmt.Errorf("create agent state for preset %s: %w", presetName, err)
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return fmt.Errorf("inspect agent state for preset %s: %w", presetName, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("agent state for preset %s is not a directory", presetName)
	}
	return nil
}

func rejectHardLinkedPresetState(presetName string) error {
	stateDir := filepath.Join(currentProjectStore().agentStateDir(), presetName)
	type fileID struct {
		device uint64
		inode  uint64
	}
	type inodeLinks struct {
		path          string
		linksInPreset uint64
		totalLinks    uint64
	}
	linksByFile := make(map[fileID]*inodeLinks)
	err := filepath.WalkDir(stateDir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("inspect agent state for preset %s at %s: %w", presetName, path, walkErr)
		}
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("inspect agent state for preset %s at %s: %w", presetName, path, err)
		}
		if info.IsDir() {
			return nil
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("inspect hard-link count for preset state entry %s", path)
		}
		id := fileID{device: uint64(stat.Dev), inode: stat.Ino}
		links := linksByFile[id]
		if links == nil {
			links = &inodeLinks{path: path}
			linksByFile[id] = links
		}
		links.linksInPreset++
		if uint64(stat.Nlink) > links.totalLinks {
			links.totalLinks = uint64(stat.Nlink)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, links := range linksByFile {
		if links.totalLinks > links.linksInPreset {
			return fmt.Errorf(
				"unsafe preset state inode has %d hard links but only %d inside preset %s: %s; copy the external link to a new inode before starting the preset",
				links.totalLinks,
				links.linksInPreset,
				presetName,
				links.path,
			)
		}
	}
	return nil
}

func loadSetupDefinitions(names []string) ([]setupDefinition, error) {
	setups := make([]setupDefinition, 0, len(names))
	seen := make(map[string]bool)
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, fmt.Errorf("empty setup name")
		}
		if seen[name] {
			return nil, fmt.Errorf("duplicate setup: %s", name)
		}
		seen[name] = true
		rootPath, projectLocal, err := resolvedSetupDirectoryPath(name)
		if err != nil {
			return nil, err
		}
		definition, err := loadSetupDefinitionAt(name, rootPath, projectLocal)
		if err != nil {
			return nil, err
		}
		setups = append(setups, definition)
	}
	return setups, nil
}

func loadSetupDefinitionAt(name, rootPath string, projectLocal bool) (setupDefinition, error) {
	scriptPaths, err := setupScriptPaths(rootPath)
	if err != nil {
		return setupDefinition{}, err
	}
	if len(scriptPaths) == 0 {
		return setupDefinition{}, fmt.Errorf("setup has no scripts: %s", displaySetupName(name, projectLocal))
	}
	firewallPaths, err := setupFirewallPaths(rootPath)
	if err != nil {
		return setupDefinition{}, err
	}
	definition := setupDefinition{
		Name:          name,
		ProjectLocal:  projectLocal,
		RootPath:      rootPath,
		ScriptPaths:   scriptPaths,
		FirewallPaths: firewallPaths,
		SourceContent: make(map[string][]byte, len(scriptPaths)+len(firewallPaths)),
	}
	allPaths := append(append([]string{}, scriptPaths...), firewallPaths...)
	for _, path := range allPaths {
		content, err := os.ReadFile(path)
		if err != nil {
			return setupDefinition{}, fmt.Errorf("snapshot setup source %s: %w", path, err)
		}
		definition.SourceContent[path] = content
	}
	for _, path := range firewallPaths {
		definition.FirewallRules = appendUniqueFirewallEntries(
			definition.FirewallRules,
			firewallEntriesFromContent(definition.SourceContent[path]),
		)
	}
	sourceVersion, err := setupSourceVersion(definition)
	if err != nil {
		return setupDefinition{}, err
	}
	definition.Version = sourceVersion
	return definition, nil
}

func resolvedSetupDirectoryPath(name string) (string, bool, error) {
	if !isValidResourceName(name) {
		return "", false, fmt.Errorf("invalid setup name: %s", name)
	}
	localPath := filepath.Join(".zaigr", "setups", name)
	if info, err := os.Stat(localPath); err == nil {
		if !info.IsDir() {
			return "", true, fmt.Errorf("invalid setup path: %s", displaySetupName(name, true))
		}
		return localPath, true, nil
	} else if !os.IsNotExist(err) {
		return "", true, err
	}
	if err := ensureBuiltinSetupDefinition(name); err != nil {
		return "", false, err
	}
	path, err := setupDirectoryPath(name)
	return path, false, err
}

func loadGlobalSetupDefinition(name string) (setupDefinition, error) {
	if err := ensureBuiltinSetupDefinition(name); err != nil {
		return setupDefinition{}, err
	}
	root, err := setupDirectoryPath(name)
	if err != nil {
		return setupDefinition{}, err
	}
	return loadSetupDefinitionAt(name, root, false)
}

func displaySetupName(name string, projectLocal bool) string {
	if projectLocal {
		return "[Project local] " + name
	}
	return name
}

func (d setupDefinition) Identity() string {
	return versionedResourceIdentity(d.Name, d.Version)
}

func setupDirectoryPath(name string) (string, error) {
	if !isValidResourceName(name) {
		return "", fmt.Errorf("invalid setup name: %s", name)
	}
	path := filepath.Join(zaigDir(), "setups", name)
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("setup not found: %s", name)
		}
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("invalid setup path: %s", name)
	}
	return path, nil
}

func setupScriptPaths(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	return collectSetupPaths(root, entries, ".script"), nil
}

func setupFirewallPaths(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	return collectSetupPaths(root, entries, ".firewall"), nil
}

func collectSetupPaths(root string, entries []os.DirEntry, suffix string) []string {
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, suffix) {
			continue
		}
		paths = append(paths, filepath.Join(root, name))
	}
	sort.Strings(paths)
	return paths
}

func buildSetupPayload(def setupDefinition) ([]byte, error) {
	scriptPayload, err := buildSetupScriptPayload(def)
	if err != nil {
		return nil, err
	}

	firewallScript := setupFirewallPayload(def.Name, def.FirewallRules)
	if firewallScript == "" {
		return scriptPayload, nil
	}
	return []byte(firewallScript + "\n" + string(scriptPayload)), nil
}

func buildSetupScriptPayload(def setupDefinition) ([]byte, error) {
	if len(def.ScriptPaths) == 0 {
		return nil, fmt.Errorf("setup has no scripts: %s", def.Name)
	}

	scriptBuilder := strings.Builder{}
	for _, path := range def.ScriptPaths {
		script, ok := def.SourceContent[path]
		if !ok {
			return nil, fmt.Errorf("setup script is missing from source snapshot: %s", path)
		}
		scriptText := strings.TrimSpace(string(script))
		if scriptText == "" {
			return nil, fmt.Errorf("setup script is empty: %s", filepath.Base(path))
		}
		scriptBuilder.WriteString(scriptText)
		scriptBuilder.WriteByte('\n')
	}
	return []byte(scriptBuilder.String()), nil
}

func setupFirewallPayload(name string, entries []string) string {
	if len(entries) == 0 {
		return ""
	}
	return setupFirewallCommand(name, entries)
}

func setupSourceVersion(def setupDefinition) (string, error) {
	if len(def.ScriptPaths) == 0 {
		return "", fmt.Errorf("setup has no scripts: %s", def.Name)
	}

	allPaths := make([]string, 0, len(def.ScriptPaths)+len(def.FirewallPaths))
	allPaths = append(allPaths, def.ScriptPaths...)
	allPaths = append(allPaths, def.FirewallPaths...)
	sort.Strings(allPaths)

	var combined strings.Builder
	for _, path := range allPaths {
		relative, err := filepath.Rel(def.RootPath, path)
		if err != nil {
			return "", err
		}
		combined.WriteString(filepath.ToSlash(relative))
		combined.WriteByte(0)

		content, ok := def.SourceContent[path]
		if !ok {
			return "", fmt.Errorf("setup source is missing from snapshot: %s", path)
		}
		combined.Write(content)
		combined.WriteByte(0)
	}
	return contentVersion([]byte(combined.String())), nil
}

func firewallEntriesFromContent(data []byte) []string {
	seen := make(map[string]bool)
	var entries []string
	for _, line := range strings.Split(string(data), "\n") {
		entry := strings.TrimSpace(line)
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		if seen[entry] {
			continue
		}
		entries = append(entries, entry)
		seen[entry] = true
	}
	return entries
}

func setupFirewallCommand(name string, entries []string) string {
	var block strings.Builder
	block.WriteString(`mkdir -p /etc/opensnitchd/lists/domains
allowed_file=/etc/opensnitchd/lists/domains/allowed.txt
touch "$allowed_file"
`)
	block.WriteString(`
  while IFS= read -r domain; do
    case "$domain" in
      ""|"#"*)
        continue
        ;;
    esac
    if [ "$domain" = "" ]; then
      continue
    fi
    if ! grep -qxF "$domain" "$allowed_file" 2>/dev/null; then
      printf '%s\n' "$domain" >> "$allowed_file"
    fi
  done <<'__ZAIGR_FIREWALL__'
`)
	for _, entry := range entries {
		block.WriteString(entry)
		block.WriteByte('\n')
	}
	block.WriteString(`__ZAIGR_FIREWALL__
/usr/local/sbin/zaigr-inside firewall reload-domains
`)
	return block.String()
}

func loadPreset(name string) (presetDefinition, error) {
	if strings.Contains(name, string(os.PathSeparator)) || strings.Contains(name, "..") {
		return presetDefinition{}, fmt.Errorf("invalid preset name: %s", name)
	}
	dir := filepath.Join(zaigDir(), "presets", name)
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return presetDefinition{}, fmt.Errorf("preset not found: %s", name)
		}
		return presetDefinition{}, fmt.Errorf("invalid preset name: %s", name)
	}
	if !info.IsDir() {
		return presetDefinition{}, fmt.Errorf("invalid preset path: %s", name)
	}

	runPath := filepath.Join(dir, "run")
	runInfo, err := os.Stat(runPath)
	if err != nil || !runInfo.Mode().IsRegular() {
		return presetDefinition{}, fmt.Errorf("preset missing run script: %s", name)
	}

	setupsPath := filepath.Join(dir, "setups")
	entries, err := os.ReadDir(setupsPath)
	if err != nil && !os.IsNotExist(err) {
		return presetDefinition{}, fmt.Errorf("read preset setups for %s: %w", name, err)
	}
	setups := make([]string, 0, len(entries))
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			candidate := setupNameFromPresetEntry(entry.Name())
			if candidate == "" || strings.HasPrefix(candidate, ".") {
				continue
			}
			setups = append(setups, candidate)
		}
		sort.Strings(setups)
	}

	version, err := presetDirectoryVersion(dir)
	if err != nil {
		return presetDefinition{}, err
	}

	return presetDefinition{Name: name, Version: version, RunPath: runPath, SetupRefs: setups}, nil
}

func setupNameFromPresetEntry(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if strings.ContainsRune(name, os.PathSeparator) {
		return ""
	}
	ext := filepath.Ext(name)
	switch ext {
	case "", ".script":
	default:
		return ""
	}
	name = strings.TrimSuffix(name, ".script")
	name = strings.TrimSuffix(name, filepath.Ext(name))
	return name
}

func loadPresetRunScript(path string) ([]byte, error) {
	script, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read preset run script: %w", err)
	}
	if len(script) == 0 {
		return nil, fmt.Errorf("preset run script is empty")
	}
	return script, nil
}

func uniqueOrderedNames(names []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out
}

func presetDirectoryVersion(dir string) (string, error) {
	combined := make([]byte, 0)
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		combined = append(combined, []byte(filepath.ToSlash(rel))...)
		combined = append(combined, 0)

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		combined = append(combined, data...)
		combined = append(combined, 0)
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("hash preset %s: %w", filepath.Base(dir), err)
	}
	return contentVersion(combined), nil
}

func requireProject(ctx string) (string, error) {
	store := currentProjectStore()
	storePath := store.Path
	logDebug("checking project initialization", "context", ctx, "store", storePath)
	initialized, err := isProjectInitialized(storePath)
	if err != nil {
		logError("project initialization check failed", "context", ctx, "store", storePath, "err", err)
		return "", err
	}
	if !initialized {
		logInfo("project is not initialized", "context", ctx, "store", storePath)
		return "", fmt.Errorf("%s requires a project. Run 'zaigr shell' to initialize it", ctx)
	}
	if ctx != "project clean" && ctx != "project rebuild" && ctx != "project delete" {
		if err := store.requireCurrentImageFormat(ctx); err != nil {
			return "", err
		}
		if err := store.writeProjectPath(canonicalPath(".")); err != nil {
			return "", err
		}
	}
	logDebug("project initialization check passed", "context", ctx, "store", storePath)
	return storePath, nil
}
