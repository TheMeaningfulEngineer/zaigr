package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func newGlobalProjectsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "projects",
		Short: "Inspect and manage project stores",
	}
	cmd.AddCommand(newGlobalProjectsListCommand())
	cmd.AddCommand(newGlobalProjectsDetailsCommand())
	cmd.AddCommand(newGlobalProjectsKillCommand())
	cmd.AddCommand(newGlobalProjectsRebuildCommand())
	return cmd
}

func newGlobalProjectsListCommand() *cobra.Command {
	var fullPaths bool
	var showBaseImage bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List projects and their VM resources",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cmdGlobalProjectsList(fullPaths, showBaseImage)
		},
	}
	cmd.Flags().BoolVar(&fullPaths, "full-paths", false, "Show full project paths")
	cmd.Flags().BoolVar(&showBaseImage, "show-base-image", false, "Show saved and required base image runtime versions")
	return cmd
}

func newGlobalProjectsDetailsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "details <project> [<project> ...]",
		Short: "Show details about one project",
		Long:  "Show details about one project. Select by exact ID or exact recorded basename; exact IDs take precedence over names, and ambiguous names require an ID. Details normally takes one project and accepts multiple selectors for compatibility.",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return cmdGlobalProjectsDetails(args)
		},
	}
	cmd.ValidArgsFunction = completeProjectStoreSelector
	return cmd
}

func newGlobalProjectsKillCommand() *cobra.Command {
	var abrupt bool
	cmd := &cobra.Command{
		Use:   "kill <project> [...]",
		Short: "Stop selected project VMs",
		Long:  "Select a project by exact ID or exact recorded basename. Exact IDs take precedence over names; ambiguous names require an ID. Repeated selectors are processed once.",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return cmdGlobalProjectsKill(args, abrupt)
		},
	}
	cmd.Flags().BoolVar(&abrupt, "abrupt", false, "Force kill the VM process, even during an active project operation")
	cmd.ValidArgsFunction = completeProjectStoreSelector
	return cmd
}

func completeProjectStoreSelector(_ *cobra.Command, args []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
	stores, err := listProjectStores()
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}
	type completionStore struct {
		store projectStore
		path  string
		name  string
	}
	infos := make([]completionStore, 0, len(stores))
	byID := make(map[string]completionStore, len(stores))
	byName := make(map[string][]completionStore)
	for _, store := range stores {
		path, ok, readErr := store.readProjectPath()
		if readErr != nil || !ok {
			path = unknownProjectPathLabel
		}
		info := completionStore{store: store, path: path, name: globalProjectBasename(path)}
		infos = append(infos, info)
		byID[store.Hash] = info
		if info.name != "" {
			byName[info.name] = append(byName[info.name], info)
		}
	}
	usedStores := make(map[string]struct{}, len(args))
	for _, arg := range args {
		if info, ok := byID[arg]; ok {
			usedStores[info.store.Hash] = struct{}{}
			continue
		}
		if matches := byName[arg]; len(matches) == 1 {
			usedStores[matches[0].store.Hash] = struct{}{}
		}
	}
	completions := make([]cobra.Completion, 0, len(stores))
	seenNames := make(map[string]struct{})
	for _, info := range infos {
		if _, used := usedStores[info.store.Hash]; !used && strings.HasPrefix(info.store.Hash, toComplete) {
			completions = append(completions, cobra.Completion(info.store.Hash+"\t"+globalProjectCompletionDescription(info.store, info.path, info.name)))
		}
		// A basename equal to any persisted ID is reserved for that ID and is
		// therefore not a usable name selector.
		if info.name == "" || len(byName[info.name]) != 1 || info.name == info.store.Hash {
			continue
		}
		if _, duplicate := seenNames[info.name]; duplicate {
			continue
		}
		seenNames[info.name] = struct{}{}
		if _, reserved := byID[info.name]; reserved {
			continue
		}
		if _, used := usedStores[info.store.Hash]; !used && strings.HasPrefix(info.name, toComplete) {
			completions = append(completions, cobra.Completion(info.name+"\t"+globalProjectCompletionDescription(info.store, info.path, info.name)))
		}
	}
	return completions, cobra.ShellCompDirectiveNoFileComp
}

func globalProjectCompletionDescription(store projectStore, path, name string) string {
	if name == "" {
		name = unknownProjectPathLabel
	}
	return fmt.Sprintf("%s (%s; ID %s)", path, name, store.Hash)
}

func cmdGlobalProjectsList(fullPaths, showBaseImage bool) error {
	stores, err := listProjectStores()
	if err != nil {
		return err
	}

	type statusRow struct {
		store        projectStore
		path         string
		status       string
		cpu          string
		ram          string
		disk         string
		vm           globalProjectVM
		baseImage    string
		requiredBase string
	}
	rows := make([]statusRow, 0, len(stores))
	baseCounts := make(map[string]int)
	for _, store := range stores {
		path, ok, err := store.readProjectPath()
		warnGlobalProject(store, err)
		vm := inspectGlobalProjectVM(store)
		baseImage, baseImageErr := readGlobalProjectBaseImage(store)
		warnGlobalProject(store, baseImageErr)
		_, captureActive, captureErr := readGlobalProjectCapture(store)
		warnGlobalProject(store, captureErr)
		status := globalProjectStatusValue(vm, captureActive, captureErr, baseImage.OutdatedBaseImage)
		disk, diskErr := globalProjectDiskUsage(store)
		if diskErr != nil {
			warnGlobalProject(store, diskErr)
		}
		row := statusRow{
			store:        store,
			status:       status,
			cpu:          coalesce(vm.cpu, "?"),
			ram:          formatGlobalProjectRAM(vm.ram),
			disk:         disk,
			vm:           vm,
			baseImage:    coalesce(baseImage.RecordedBaseVersion, "?"),
			requiredBase: coalesce(baseImage.RequiredBaseVersion, "?"),
		}
		if ok {
			row.path = path
			base := filepath.Base(path)
			if base != "" && base != "." && base != string(filepath.Separator) {
				baseCounts[base]++
			}
		}
		rows = append(rows, row)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		return rows[i].vm.running != nil && rows[j].vm.running == nil
	})

	writer := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	columns := []string{"PROJECT", "STATUS", "CPU", "RAM", "DISK USED"}
	if showBaseImage {
		columns = append(columns, "BASE IMAGE", "REQUIRED BASE")
	}
	columns = append(columns, "ID")
	if _, err := fmt.Fprintln(writer, strings.Join(columns, "\t")); err != nil {
		return err
	}
	var staleStores []projectStore
	for _, row := range rows {
		if row.vm.stale {
			staleStores = append(staleStores, row.store)
		}
		values := []string{
			projectStorePathDisplay(row.path, fullPaths, baseCounts),
			row.status,
			row.cpu,
			row.ram,
			row.disk,
		}
		if showBaseImage {
			values = append(values, row.baseImage, row.requiredBase)
		}
		values = append(values, row.store.Hash)
		if _, err := fmt.Fprintln(writer, strings.Join(values, "\t")); err != nil {
			return err
		}
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	if len(rows) > 0 {
		fmt.Println("\nStop VMs: zaigr global projects kill <project> [<project> ...] (add --abrupt to force)")
	}
	for _, store := range staleStores {
		fmt.Fprintf(
			os.Stderr,
			"warning: project %s has leftover VM runtime state; run `zaigr global projects kill %s` to clear it.\n",
			globalProjectLabel(store),
			store.Hash,
		)
	}
	return nil
}

func cmdGlobalProjectsDetails(hashes []string) error {
	var failures []error
	processed := make(map[string]struct{}, len(hashes))
	printed := 0
	for _, selector := range hashes {
		store, err := resolveProjectStoreSelector(selector)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if _, ok := processed[store.Hash]; ok {
			continue
		}
		processed[store.Hash] = struct{}{}
		if printed > 0 {
			fmt.Println()
		}
		printGlobalProjectDetails(store)
		printed++
	}
	return errors.Join(failures...)
}

func cmdGlobalProjectsKill(hashes []string, abrupt bool) error {
	var failed []string
	processed := make(map[string]struct{}, len(hashes))
	for _, selector := range hashes {
		store, err := resolveProjectStoreSelector(selector)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", selector, err)
			failed = append(failed, selector)
			continue
		}
		if _, ok := processed[store.Hash]; ok {
			continue
		}
		processed[store.Hash] = struct{}{}
		lock, lockErr := acquireExclusiveProjectMutationLock(store, "global projects kill", true)
		if lockErr != nil && !abrupt {
			fmt.Fprintf(os.Stderr, "%s: %v; use `zaigr global projects kill %s --abrupt` to force stop\n", store.Hash, lockErr, store.Hash)
			failed = append(failed, store.Hash)
			continue
		}
		if lockErr != nil {
			warnGlobalProject(store, lockErr)
		}
		result, killErr := killGlobalProject(store, abrupt, lock != nil)
		if killErr != nil && !abrupt {
			killErr = fmt.Errorf("%w; force stop with `zaigr global projects kill %s --abrupt`", killErr, store.Hash)
		}
		releaseErr := lock.release()
		err = errors.Join(killErr, releaseErr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", store.Hash, err)
			failed = append(failed, store.Hash)
			continue
		}
		fmt.Printf("%s: %s\n", store.Hash, result)
	}
	if len(failed) > 0 {
		return fmt.Errorf("failed to stop %d project VM(s): %s", len(failed), strings.Join(failed, ", "))
	}
	return nil
}

func killGlobalProject(store projectStore, abrupt bool, locked bool) (string, error) {
	processes, err := openQemuProcessesForSocket(store.monitorSockPath())
	if err != nil {
		return "", err
	}
	defer releaseQemuProcesses(processes)

	running, stale := detectRunningProjectVMInStore(store)
	if len(processes) == 0 {
		if running != nil {
			return "", fmt.Errorf("could not identify the running QEMU process")
		}
		if stale {
			if !locked {
				return "", fmt.Errorf("runtime state is busy; retry after the active operation finishes")
			}
			if err := store.clearRuntimeState(); err != nil {
				return "", err
			}
			return "cleared stale runtime state", nil
		}
		return "already off", nil
	}

	sessions, err := store.readActiveShellSessions(false)
	if err != nil {
		if !abrupt {
			return "", err
		}
		warnGlobalProject(store, err)
	}
	if len(sessions) > 0 && !confirmGlobalProjectKillWithShells(store, sessions) {
		return "skipped", nil
	}
	if abrupt {
		if err := killQemuProcesses(processes); err != nil {
			return "", err
		}
		// An in-flight workflow owns its runtime files. Only clean them when
		// holding the project lock; emergency stop only kills the process.
		if locked {
			if err := store.clearRuntimeState(); err != nil {
				return "", fmt.Errorf("VM stopped, but %w", err)
			}
		}
		return "stopped", nil
	}
	if running == nil {
		return "", fmt.Errorf("QEMU is running but its monitor is unavailable")
	}

	result, err := stopProjectVMInStore(store, abrupt)
	if err != nil {
		return "", err
	}
	switch result.State {
	case projectVMStopStateStopped:
		return "stopped", nil
	case projectVMStopStateStale:
		return "cleared stale runtime state", nil
	case projectVMStopStateOff:
		return "already off", nil
	default:
		return "", fmt.Errorf("unknown stop result: %s", result.State)
	}
}

func confirmGlobalProjectKillWithShells(store projectStore, sessions []shellSession) bool {
	projectLabel := globalProjectFullPathLabel(store)
	if projectLabel != unknownProjectPathLabel {
		projectLabel = "(" + projectLabel + ")"
	}
	fmt.Fprintf(
		os.Stderr,
		"Project %s %s has %d active shell session(s). Stopping the VM will close them. Stop VM anyway? [y/N] ",
		store.Hash,
		projectLabel,
		len(sessions),
	)
	var answer string
	_, _ = fmt.Scanln(&answer)
	return strings.EqualFold(strings.TrimSpace(answer), "y") || strings.EqualFold(strings.TrimSpace(answer), "yes")
}

func printGlobalProjectDetails(store projectStore) {
	projectImageDiagnosis, err := readGlobalProjectBaseImage(store)
	warnGlobalProject(store, err)
	warnGlobalProject(store, store.requireCurrentImageFormat("project inspection"))

	applied, appliedErr := store.readAppliedSetups()
	warnGlobalProject(store, appliedErr)
	hasSetupFailure, err := store.hasSetupFailureMarker()
	warnGlobalProject(store, err)
	vm := inspectGlobalProjectVM(store)
	presetSelection, hasPresetSelection, err := store.readPresetSelection()
	warnGlobalProject(store, err)
	firewallEntries, firewallErr := store.firewallEntries()
	warnGlobalProject(store, firewallErr)
	dirtyImage, hasDirtyImage, err := store.readProjectImageDirty()
	warnGlobalProject(store, err)
	imagePath := store.authoritativeImagePath()
	_, imageErr := os.Stat(imagePath)
	imageMissing := os.IsNotExist(imageErr)
	if !imageMissing {
		warnGlobalProject(store, imageErr)
	}
	legacyImages := []string(nil)
	if imageMissing {
		currentFormat, formatErr := store.usesCurrentImageFormat()
		if formatErr != nil {
			warnGlobalProject(store, formatErr)
		} else if currentFormat {
			projectImageDiagnosis.MissingImage = true
			projectImageDiagnosis.ExpectedImage = filepath.Base(imagePath)
		} else {
			legacyImages = legacyProjectImagePaths(store)
		}
	}
	disk, diskErr := globalProjectDiskUsage(store)
	warnGlobalProject(store, diskErr)
	image := projectStatusImageFromPaths(imagePath, imageMissing, imagePath, imageErr)
	captureMeta, captureActive, captureErr := readGlobalProjectCapture(store)
	if captureErr != nil {
		warnGlobalProject(store, captureErr)
	}
	fmt.Printf("project-label: %s\n", globalProjectLabel(store))
	fmt.Printf("project: %s\n", globalProjectFullPathLabel(store))
	fmt.Printf("status: %s\n", globalProjectStatusValue(vm, captureActive, captureErr, projectImageDiagnosis.OutdatedBaseImage))
	if vm.pid != 0 {
		fmt.Printf("vm-pid: %d\n", vm.pid)
	}
	fmt.Printf("resources: cpu=%s, ram=%s\n", coalesce(vm.cpu, "?"), formatGlobalProjectRAM(vm.ram))
	fmt.Printf("disk: %s\n", disk)
	if captureErr != nil {
		fmt.Println("setup-capture: unknown (metadata unreadable)")
	} else if captureActive {
		fmt.Printf("setup-capture: active (%s)\n", captureMeta.Name)
		fmt.Printf("  started: %s\n", coalesce(captureMeta.StartedAt, "?"))
		fmt.Printf("  base-image: %s\n", coalesce(captureMeta.BaseImagePath, "?"))
		fmt.Printf("  overlay: %s\n", coalesce(captureMeta.OverlayImagePath, "?"))
	}
	printGlobalProjectDetailsExtras(store, image, legacyImages, projectImageDiagnosis, dirtyImage, hasDirtyImage, applied, appliedErr != nil, hasSetupFailure, firewallEntries, firewallErr != nil, presetSelection, hasPresetSelection)
}

func printGlobalProjectDetailsExtras(store projectStore, image projectStatusImage, legacyImages []string, diagnosis projectImageMismatchReport, dirtyImage projectImageDirtyInfo, hasDirtyImage bool, applied []appliedSetup, appliedUnavailable bool, setupFailed bool, firewallEntries []string, firewallUnavailable bool, preset storedPresetSelection, hasPreset bool) {
	fmt.Printf("store-path: %s\n", store.Path)
	fmt.Printf("project-image: %s\n", image.Display)
	if len(legacyImages) > 0 {
		labels := make([]string, 0, len(legacyImages))
		for _, path := range legacyImages {
			labels = append(labels, filepath.Base(path))
		}
		fmt.Printf("legacy-images: %s\n", strings.Join(labels, ", "))
		fmt.Println("project-image-note: legacy or unsupported image format; details are best effort")
	}
	if hasDirtyImage {
		fmt.Printf("project-image-dirty: %s\n", projectImageDirtyStatus(dirtyImage))
	}
	if hasPreset {
		fmt.Printf("preset: %s %s\n", preset.Name, statusVersionLabel(preset.Version, preset.Time))
	}
	printProjectStatusImageWarning(diagnosis)
	fmt.Println("setups:")
	if appliedUnavailable {
		fmt.Println("  applied: unavailable")
	} else {
		fmt.Printf("  applied (%d):\n", len(applied))
		if len(applied) == 0 {
			fmt.Println("    (none)")
		} else {
			for _, record := range applied {
				fmt.Printf("    %s  %s\n", displaySetupName(record.Name, record.ProjectLocal), record.Version)
			}
		}
	}
	if setupFailed {
		fmt.Println("This VM had a failed setup once.")
	}
	if firewallUnavailable {
		fmt.Println("firewall entries: unavailable")
		return
	}
	fmt.Printf("firewall entries (%d):\n", len(firewallEntries))
	if len(firewallEntries) == 0 {
		fmt.Println("  (none)")
		return
	}
	for _, entry := range firewallEntries {
		fmt.Printf("  %s\n", entry)
	}
}

func warnGlobalProject(store projectStore, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: project %s: %v\n", store.Hash, err)
	}
}

type globalProjectVM struct {
	running *runningVMInfo
	stale   bool
	pid     int
	cpu     string
	ram     string
}

// Inspect the host process so overrides and unresponsive guests remain visible.
// No image validation, project recovery, or guest SSH is needed for inspection.
func inspectGlobalProjectVM(store projectStore) globalProjectVM {
	vm := globalProjectVM{cpu: store.cpus(), ram: store.ram()}
	pids, err := findQemuProcessesForSocket(store.monitorSockPath())
	warnGlobalProject(store, err)
	if len(pids) == 0 {
		vm.running, vm.stale = detectRunningProjectVMInStore(store)
		if vm.running != nil {
			// Saved defaults are not evidence of a running VM's configuration.
			vm.cpu, vm.ram = "", ""
		}
		return vm
	}
	vm.pid = pids[0]
	port, _ := store.sshPort()
	vm.running = &runningVMInfo{Port: port}
	vm.cpu, vm.ram = "", ""
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(vm.pid), "cmdline"))
	if err != nil {
		warnGlobalProject(store, err)
		return vm
	}
	args := strings.Split(strings.TrimRight(string(data), "\x00"), "\x00")
	for index := 1; index+1 < len(args); index++ {
		switch args[index] {
		case "-smp":
			for partIndex, part := range strings.Split(args[index+1], ",") {
				value, explicit := strings.CutPrefix(part, "cpus=")
				if partIndex == 0 || explicit {
					if count, err := strconv.ParseUint(value, 10, 32); err == nil && count > 0 {
						vm.cpu = strconv.FormatUint(count, 10)
					}
				}
			}
		case "-m":
			vm.ram = qemuRAMMegabytes(args[index+1])
		case "-drive":
			for _, option := range strings.Split(args[index+1], ",") {
				if path, ok := strings.CutPrefix(option, "file="); ok {
					vm.running.ImagePath = path
				}
			}
		}
	}
	return vm
}

func qemuRAMMegabytes(value string) string {
	value = strings.TrimPrefix(strings.SplitN(value, ",", 2)[0], "size=")
	multiplier := uint64(1)
	switch {
	case strings.HasSuffix(value, "G"):
		multiplier = 1024
		value = strings.TrimSuffix(value, "G")
	case strings.HasSuffix(value, "M"):
		value = strings.TrimSuffix(value, "M")
	}
	amount, err := strconv.ParseUint(value, 10, 32)
	if err != nil || amount == 0 {
		return ""
	}
	return strconv.FormatUint(amount*multiplier, 10)
}

func projectStorePathDisplay(path string, fullPaths bool, baseCounts map[string]int) string {
	if path == "" {
		return unknownProjectPathLabel
	}
	if fullPaths {
		return path
	}
	base := filepath.Base(path)
	if base == "" || base == "." || base == string(filepath.Separator) {
		return path
	}
	return base
}

func globalProjectFullPathLabel(store projectStore) string {
	path, ok, err := store.readProjectPath()
	if err != nil || !ok {
		return unknownProjectPathLabel
	}
	return path
}
