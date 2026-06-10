package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func newGlobalProjectsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "projects",
		Short: "Inspect and manage project stores",
	}
	cmd.AddCommand(newGlobalProjectsStatusCommand())
	cmd.AddCommand(newGlobalProjectsDetailsCommand())
	cmd.AddCommand(newGlobalProjectsKillCommand())
	return cmd
}

func newGlobalProjectsStatusCommand() *cobra.Command {
	var fullPaths bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show all project stores and VM state",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cmdGlobalProjectsStatus(fullPaths)
		},
	}
	cmd.Flags().BoolVar(&fullPaths, "full-paths", false, "Show full project paths")
	return cmd
}

func newGlobalProjectsDetailsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "details <store> [<store> ...]",
		Short: "Show detailed project store state",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return cmdGlobalProjectsDetails(args)
		},
	}
	cmd.ValidArgsFunction = completeProjectStoreHash
	return cmd
}

func newGlobalProjectsKillCommand() *cobra.Command {
	var abrupt bool
	cmd := &cobra.Command{
		Use:   "kill <store> [<store> ...]",
		Short: "Stop running project VMs",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return cmdGlobalProjectsKill(args, abrupt)
		},
	}
	cmd.Flags().BoolVar(&abrupt, "abrupt", false, "Force kill the VM process")
	cmd.ValidArgsFunction = completeProjectStoreHash
	return cmd
}

func completeProjectStoreHash(_ *cobra.Command, args []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
	stores, err := listProjectStores()
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}
	used := make(map[string]struct{}, len(args))
	for _, arg := range args {
		used[arg] = struct{}{}
	}
	completions := make([]cobra.Completion, 0, len(stores))
	for _, store := range stores {
		if _, ok := used[store.Hash]; ok {
			continue
		}
		if !strings.HasPrefix(store.Hash, toComplete) {
			continue
		}
		path, ok, err := store.readProjectPath()
		if err != nil || !ok {
			path = unknownProjectPathLabel
		}
		completions = append(completions, cobra.Completion(store.Hash+"\t"+path))
	}
	return completions, cobra.ShellCompDirectiveNoFileComp
}

func cmdGlobalProjectsStatus(fullPaths bool) error {
	stores, err := listProjectStores()
	if err != nil {
		return err
	}

	paths := make(map[string]string, len(stores))
	baseCounts := make(map[string]int)
	for _, store := range stores {
		path, ok, err := store.readProjectPath()
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		paths[store.Hash] = path
		base := filepath.Base(path)
		if base != "" && base != "." && base != string(filepath.Separator) {
			baseCounts[base]++
		}
	}

	writer := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(writer, "STORE\tVM\tCPU\tRAM\tPROJECT")
	var staleStores []projectStore
	for _, store := range stores {
		vmState := globalProjectVMState(store)
		if vmState == "stale" {
			staleStores = append(staleStores, store)
		}
		fmt.Fprintf(
			writer,
			"%s\t%s\t%s\t%s\t%s\n",
			store.Hash,
			vmState,
			projectStoreCPUDisplay(store),
			projectStoreRAMDisplay(store),
			projectStorePathDisplay(paths[store.Hash], fullPaths, baseCounts),
		)
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	for _, store := range staleStores {
		fmt.Fprintf(
			os.Stderr,
			"warning: project %s has leftover VM runtime state; run `zaigr global projects kill %s` to clear it.\n",
			store.Hash,
			store.Hash,
		)
	}
	return nil
}

func cmdGlobalProjectsDetails(hashes []string) error {
	stores, err := resolveProjectStoreHashes(hashes)
	if err != nil {
		return err
	}
	for i, store := range stores {
		if i > 0 {
			fmt.Println()
		}
		if err := printGlobalProjectDetails(store); err != nil {
			return err
		}
	}
	return nil
}

func cmdGlobalProjectsKill(hashes []string, abrupt bool) error {
	stores, err := resolveProjectStoreHashes(hashes)
	if err != nil {
		return err
	}

	var failed []string
	for _, store := range stores {
		result, err := killGlobalProject(store, abrupt)
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

func killGlobalProject(store projectStore, abrupt bool) (string, error) {
	running, stale := detectRunningProjectVMInStore(store)
	if stale {
		_ = store.clearRuntimeState()
		return "cleared stale runtime state", nil
	}
	if running == nil {
		return "already off", nil
	}

	sessions, err := store.activeShellSessions()
	if err != nil {
		return "", err
	}
	if len(sessions) > 0 && !confirmGlobalProjectKillWithShells(store, sessions) {
		return "skipped", nil
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

func printGlobalProjectDetails(store projectStore) error {
	projectImageDiagnosis, err := collectProjectImageMismatchesForStore(store)
	if err != nil {
		return err
	}

	committed, err := store.committedSetups()
	if err != nil {
		return err
	}
	committedImagePath, committedImageMissing, err := store.validateCommittedProjectImage(committed)
	if err != nil {
		return err
	}
	awaitingCommit, err := store.awaitingCommitSetups()
	if err != nil {
		return err
	}
	failed, err := store.failedSetups()
	if err != nil {
		return err
	}
	running, stale := detectRunningProjectVMWithMetadataInStore(store)
	presetSelection, hasPresetSelection, err := store.readPresetSelection()
	if err != nil {
		return err
	}
	shells, err := store.activeShellSessions()
	if err != nil {
		return err
	}

	firewallEntries, err := store.firewallEntries()
	if err != nil {
		return err
	}
	dirtyImage, hasDirtyImage, err := store.readProjectImageDirty()
	if err != nil {
		return err
	}
	imagePath, imageErr := store.imagePath()
	activeShellCount := len(shells)
	printProjectStatus(projectStatusRender{
		ProjectPath:      globalProjectFullPathLabel(store),
		StorePath:        store.Path,
		CPU:              store.cpus(),
		RAM:              store.ram(),
		Disk:             store.disk(),
		ShowDisk:         true,
		Image:            projectStatusImageFromPaths(committedImagePath, committedImageMissing, imagePath, imageErr),
		ImageMismatch:    projectImageDiagnosis,
		DirtyImage:       dirtyImage,
		HasDirtyImage:    hasDirtyImage,
		Running:          running,
		Stale:            stale,
		Preset:           presetSelection,
		HasPreset:        hasPresetSelection,
		Committed:        committed,
		AwaitingCommit:   awaitingCommit,
		Failed:           failed,
		ActiveShellCount: &activeShellCount,
		FirewallEntries:  firewallEntries,
		ShowFirewall:     true,
	})
	return nil
}

func globalProjectVMState(store projectStore) string {
	running, stale := detectRunningProjectVMInStore(store)
	switch {
	case stale:
		return "stale"
	case running != nil:
		return "running"
	default:
		return "off"
	}
}

func projectStoreCPUDisplay(store projectStore) string {
	if cpu := store.cpus(); cpu != "" {
		return cpu
	}
	return "?"
}

func projectStoreRAMDisplay(store projectStore) string {
	if ram := store.ram(); ram != "" {
		return ram + "MB"
	}
	return "?"
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
	if baseCounts[base] > 1 {
		return fmt.Sprintf("%s (%s)", base, path)
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
