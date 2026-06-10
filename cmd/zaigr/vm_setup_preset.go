package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type setupDefinition struct {
	Name          string
	Version       string
	RootPath      string
	ScriptPaths   []string
	FirewallPaths []string
}

type presetDefinition struct {
	Name      string
	Version   string
	RunPath   string
	SetupRefs []string
}

func cmdSetupRun(names []string, ram string, cpu string, force bool) error {
	if len(names) == 0 {
		return fmt.Errorf("at least one setup name is required")
	}
	logInfo("starting project setup run", "names", strings.Join(names, ","), "ram", ram, "cpu", cpu, "force", force)
	if err := requireNoActiveSetupCapture("zaigr project setup run"); err != nil {
		return err
	}
	definitions, err := loadSetupDefinitions(names)
	if err != nil {
		return err
	}
	logDebug("loaded setup definitions", "count", len(definitions))

	bootAfterApply := false
	if _, err := requireProject("project setup run"); err != nil {
		fmt.Printf(":: `zaigr project setup run` will start a project VM to initialize this blank project\n")
		logInfo("project setup run will initialize blank project and boot a VM", "store", storeDir())
		if err := ensureProjectInitializedForVM(ram, cpu); err != nil {
			return err
		}
		bootAfterApply = true
	}

	if !force {
		var skippedCommitted []string
		var skippedAwaitingCommit []string
		definitions, skippedCommitted, skippedAwaitingCommit, err = filterSetupDefinitionsByStoredState(definitions, true)
		if err != nil {
			return err
		}
		printSkippedSetupStates(skippedCommitted, skippedAwaitingCommit)
		logDebug("filtered setup definitions", "count", len(definitions), "skipped_committed", len(skippedCommitted), "skipped_awaiting_commit", len(skippedAwaitingCommit))
	}

	running, stale := detectRunningProjectVM()
	if stale {
		_ = storeClearRuntimeState()
		logWarn("removed stale project VM marker during project setup run", "runtime_dir", storeRuntimeDir())
	}
	projectImageDiagnosis, err := resolveProjectImageForCommand(true, running == nil)
	if err != nil {
		return err
	}
	running, stale = detectRunningProjectVM()
	if stale {
		_ = storeClearRuntimeState()
		running = nil
	}
	definitions = filterSetupsByKeep(definitions, projectImageDiagnosis)
	if running != nil {
		if ram != "" || cpu != "" {
			return fmt.Errorf("project VM is already running; --ram and --cpu cannot be changed on a running VM")
		}
		logInfo("project setup run will apply to running VM", "port", running.Port, "count", len(definitions))
		return applySetupDefinitionsToVM(running.Port, definitions)
	}

	logInfo("project setup run will apply directly to project image", "count", len(definitions))
	if err := applySetupDefinitionsToImage(definitions, ram, cpu, force); err != nil {
		return err
	}
	if bootAfterApply {
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

func filterSetupDefinitionsByStoredState(definitions []setupDefinition, includeAwaitingCommit bool) ([]setupDefinition, []string, []string, error) {
	committed, err := storeCommittedSetups()
	if err != nil {
		return nil, nil, nil, err
	}
	awaitingCommit, err := func() ([]string, error) {
		if !includeAwaitingCommit {
			return nil, nil
		}
		return storeAwaitingCommitSetups()
	}()
	if err != nil {
		return nil, nil, nil, err
	}

	committedSet := map[string]struct{}{}
	for _, path := range committed {
		identity, err := storeSetupIdentityFromPath(path)
		if err != nil {
			return nil, nil, nil, err
		}
		if identity == "" {
			continue
		}
		committedSet[identity] = struct{}{}
	}

	awaitingCommitSet := map[string]struct{}{}
	for _, path := range awaitingCommit {
		identity, err := storeSetupIdentityFromPath(path)
		if err != nil {
			return nil, nil, nil, err
		}
		if identity == "" {
			continue
		}
		awaitingCommitSet[identity] = struct{}{}
	}

	filtered := make([]setupDefinition, 0, len(definitions))
	skippedCommitted := make([]string, 0, len(definitions))
	skippedAwaitingCommit := make([]string, 0, len(definitions))
	for _, definition := range definitions {
		if _, exists := awaitingCommitSet[definition.Identity()]; exists {
			skippedAwaitingCommit = append(skippedAwaitingCommit, definition.Name)
			continue
		}
		if setupStateContainsDefinition(awaitingCommit, definition) {
			skippedAwaitingCommit = append(skippedAwaitingCommit, definition.Name)
			continue
		}
		if _, exists := committedSet[definition.Identity()]; exists {
			skippedCommitted = append(skippedCommitted, definition.Name)
			continue
		}
		if setupStateContainsDefinition(committed, definition) {
			skippedCommitted = append(skippedCommitted, definition.Name)
			continue
		}
		filtered = append(filtered, definition)
	}
	return filtered, skippedCommitted, skippedAwaitingCommit, nil
}

func setupStateContainsDefinition(paths []string, def setupDefinition) bool {
	for _, path := range paths {
		if storeScriptBaseNameFromPath(path) != def.Name {
			continue
		}
		matches, err := storedSetupScriptMatchesDefinition(path, def)
		if err == nil && matches {
			return true
		}
	}
	return false
}

func printSkippedSetupStates(skippedCommitted, skippedAwaitingCommit []string) {
	if len(skippedCommitted) > 0 {
		fmt.Printf(
			":: Skipping setups already committed to the project image: %s\n",
			strings.Join(skippedCommitted, ", "),
		)
	}
	if len(skippedAwaitingCommit) > 0 {
		fmt.Printf(
			":: Skipping setups already awaiting image commit: %s\n",
			strings.Join(skippedAwaitingCommit, ", "),
		)
	}
}

func applySetupDefinitionsToVM(port string, definitions []setupDefinition) error {
	for _, def := range definitions {
		payload, err := buildSetupPayload(def)
		if err != nil {
			return err
		}

		if err := cmdApplyScriptToRunningVM(payload, def.Name, port, true); err != nil {
			return fmt.Errorf("failed to run setup %s: %w", def.Name, err)
		}
		if err := appendProjectFirewallFromSetup(def); err != nil {
			return fmt.Errorf("failed to record setup firewall for %s: %w", def.Name, err)
		}
	}
	return nil
}

func applySetupDefinitionsToImage(definitions []setupDefinition, ram string, cpu string, replaceCommitted bool) error {
	for _, def := range definitions {
		payload, err := buildSetupPayload(def)
		if err != nil {
			return err
		}

		if replaceCommitted {
			err = cmdApplyScriptToImageReplacingCommitted(payload, def.Name, ram, cpu, true)
		} else {
			err = cmdApplyScriptToImage(payload, def.Name, ram, cpu, true)
		}
		if err != nil {
			return fmt.Errorf("failed to run setup %s: %w", def.Name, err)
		}
		if err := appendProjectFirewallFromSetup(def); err != nil {
			return fmt.Errorf("failed to record setup firewall for %s: %w", def.Name, err)
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

func runPresetInVM(port string, script []byte, rootUser bool) error {
	user := "user"
	keyPath := ""
	if rootUser {
		user = "root"
		var err error
		keyPath, _, err = ensureRootSSHKey()
		if err != nil {
			return err
		}
	}
	return sshRunPresetCommand(port, keyPath, user, string(script))
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
		if err := ensureBuiltinSetupDefinition(name); err != nil {
			return nil, err
		}

		rootPath, err := setupDirectoryPath(name)
		if err != nil {
			return nil, err
		}
		scriptPaths, err := setupScriptPaths(rootPath)
		if err != nil {
			return nil, err
		}
		if len(scriptPaths) == 0 {
			return nil, fmt.Errorf("setup has no scripts: %s", name)
		}
		firewallPaths, err := setupFirewallPaths(rootPath)
		if err != nil {
			return nil, err
		}
		definition := setupDefinition{
			Name:          name,
			RootPath:      rootPath,
			ScriptPaths:   scriptPaths,
			FirewallPaths: firewallPaths,
		}
		sourceVersion, err := setupSourceVersion(definition)
		if err != nil {
			return nil, err
		}
		definition.Version = sourceVersion

		setups = append(setups, definition)
	}
	return setups, nil
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

	firewallScript, err := setupFirewallPayload(def.Name, def.FirewallPaths)
	if err != nil {
		return nil, err
	}
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
		script, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read setup script %s: %w", path, err)
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

func storedSetupScriptMatchesDefinition(path string, def setupDefinition) (bool, error) {
	stored, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	payload, err := buildSetupPayload(def)
	if err != nil {
		return false, err
	}
	if contentVersion(stored) == contentVersion(payload) {
		return true, nil
	}

	scriptPayload, err := buildSetupScriptPayload(def)
	if err != nil {
		return false, err
	}
	storedText := strings.TrimSpace(string(stored))
	scriptText := strings.TrimSpace(string(scriptPayload))
	if storedText != scriptText && !strings.HasSuffix(storedText, scriptText) {
		return false, nil
	}

	for _, firewallPath := range def.FirewallPaths {
		entries, err := readFirewallEntries(firewallPath)
		if err != nil {
			return false, err
		}
		for _, entry := range entries {
			if !strings.Contains(storedText, "\n"+entry+"\n") {
				return false, nil
			}
		}
	}
	return true, nil
}

func setupFirewallPayload(name string, paths []string) (string, error) {
	if len(paths) == 0 {
		return "", nil
	}
	commands := make([]string, 0, len(paths))
	for _, path := range paths {
		domains, err := readFirewallEntries(path)
		if err != nil {
			return "", err
		}
		if len(domains) == 0 {
			continue
		}
		commands = append(commands, setupFirewallCommand(name, domains))
	}
	return strings.Join(commands, "\n"), nil
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

		content, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		combined.Write(content)
		combined.WriteByte(0)
	}
	return contentVersion([]byte(combined.String())), nil
}

func readFirewallEntries(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read setup firewall %s: %w", path, err)
	}

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
	return entries, nil
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
`)
	return block.String()
}

func appendProjectFirewallFromSetup(def setupDefinition) error {
	if len(def.FirewallPaths) == 0 {
		return nil
	}
	entries := make([]string, 0)
	for _, path := range def.FirewallPaths {
		values, err := readFirewallEntries(path)
		if err != nil {
			return err
		}
		entries = append(entries, values...)
	}
	if len(entries) == 0 {
		return nil
	}
	return storeAppendFirewallEntries(entries)
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
	storePath := storeDir()
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
	if err := storeWriteCurrentProjectPath(); err != nil {
		return "", err
	}
	logDebug("project initialization check passed", "context", ctx, "store", storePath)
	return storePath, nil
}
