package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

type globalRebuildMode int

const (
	globalRebuildSelectors globalRebuildMode = iota + 1
	globalRebuildAll
	globalRebuildOutdated
)

type globalRebuildPlanItem struct {
	store     projectStore
	label     string
	status    string
	action    string
	reason    string
	eligible  bool
	outdated  bool
	ignored   bool
	aptIssues []setupAptConfirmationIssue
}

type globalRebuildResult struct {
	store  projectStore
	label  string
	status string
}

// newGlobalProjectsRebuildCommand constructs the batch rebuild command.
func newGlobalProjectsRebuildCommand() *cobra.Command {
	var all, outdated, force, yes bool
	cmd := &cobra.Command{
		Use:   "rebuild [<project> ...]",
		Short: "Rebuild selected project VMs",
		Long:  "Rebuild selected project VMs. Select by exact ID or exact recorded basename; exact IDs take precedence over names, and ambiguous names require an ID. Choose exactly one mode: project selectors, --all, or --outdated.",
		Args:  cobra.ArbitraryArgs,
		RunE: func(_ *cobra.Command, args []string) error {
			return cmdGlobalProjectsRebuild(args, all, outdated, force, yes)
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "Rebuild all project VMs")
	cmd.Flags().BoolVar(&outdated, "outdated", false, "Rebuild projects needing a base-image or runtime upgrade")
	cmd.Flags().BoolVar(&force, "force", false, "Rebuild despite manual project-image changes")
	cmd.Flags().BoolVar(&yes, "yes", false, "Approve the batch without prompting")
	cmd.ValidArgsFunction = completeProjectStoreHash
	return cmd
}

func cmdGlobalProjectsRebuild(selectors []string, all, outdated, force, yes bool) error {
	if (all && outdated) || (all && len(selectors) > 0) || (outdated && len(selectors) > 0) {
		return fmt.Errorf("global projects rebuild requires exactly one mode: project selectors, --all, or --outdated")
	}
	if !all && !outdated && len(selectors) == 0 {
		return fmt.Errorf("global projects rebuild requires project selectors, --all, or --outdated")
	}

	mode := globalRebuildSelectors
	if all {
		mode = globalRebuildAll
	} else if outdated {
		mode = globalRebuildOutdated
	}
	stores, selectionErrors := selectGlobalRebuildStores(selectors, mode)
	plan := make([]globalRebuildPlanItem, 0, len(stores))
	for _, store := range stores {
		item := preflightGlobalRebuild(store, mode == globalRebuildOutdated, force)
		if !item.ignored {
			plan = append(plan, item)
		}
	}
	skipped := globalRebuildPlanSkips(plan)
	for _, err := range selectionErrors {
		fmt.Fprintf(os.Stderr, "skip: %v\n", err)
		skipped = append(skipped, globalRebuildResult{label: err.Error()})
	}

	eligible := 0
	for _, item := range plan {
		if item.eligible {
			eligible++
		}
	}
	if len(plan) == 0 && len(selectionErrors) == 0 {
		fmt.Println("No projects need rebuilding.")
		return nil
	}
	if mode == globalRebuildOutdated {
		fmt.Printf("%d of %d projects selected for rebuilding; %d eligible, %d skipped.\n", len(plan), len(stores), eligible, len(skipped))
	} else {
		fmt.Printf("%d projects selected; %d eligible, %d skipped.\n", len(plan)+len(selectionErrors), eligible, len(skipped))
	}
	if err := printGlobalRebuildPreview(plan); err != nil {
		return err
	}
	if eligible == 0 {
		printGlobalRebuildSummary(nil, nil, skipped)
		return globalRebuildSelectionError(selectionErrors, plan)
	}
	if !yes && !confirmGlobalRebuild(eligible) {
		fmt.Fprintln(os.Stderr, "Rebuild cancelled; no project was changed.")
		return globalRebuildSelectionError(selectionErrors, plan)
	}

	var rebuilt, failed []globalRebuildResult
	attempted := 0
	for index := range plan {
		item := &plan[index]
		if !item.eligible {
			continue
		}
		attempted++
		fmt.Printf("[%d/%d] %s: rebuilding...\n", attempted, eligible, item.label)
		err := executeGlobalRebuild(item.store, force)
		if err != nil {
			var skipErr globalRebuildSkipError
			if errors.As(err, &skipErr) {
				skipped = append(skipped, globalRebuildResult{store: item.store, label: item.label, status: skipErr.Error()})
				fmt.Fprintf(os.Stderr, "[%d/%d] %s: skipped — %v\n", attempted, eligible, item.label, skipErr.Error())
				continue
			}
			fmt.Fprintf(os.Stderr, "[%d/%d] %s: FAILED — %v\n", attempted, eligible, item.label, err)
			failed = append(failed, globalRebuildResult{store: item.store, label: item.label, status: err.Error()})
			continue
		}
		fmt.Printf("[%d/%d] %s: rebuilt, VM off\n", attempted, eligible, item.label)
		rebuilt = append(rebuilt, globalRebuildResult{store: item.store, label: item.label})
	}

	printGlobalRebuildSummary(rebuilt, failed, skipped)
	if len(selectionErrors) > 0 || len(failed) > 0 || len(skipped) > 0 {
		return fmt.Errorf("global project rebuild completed with %d rebuilt, %d failed, and %d skipped", len(rebuilt), len(failed), len(skipped))
	}
	return nil
}

func selectGlobalRebuildStores(selectors []string, mode globalRebuildMode) ([]projectStore, []error) {
	if mode == globalRebuildAll || mode == globalRebuildOutdated {
		stores, err := listProjectStores()
		if err != nil {
			return nil, []error{err}
		}
		return stores, nil
	}
	seen := make(map[string]struct{})
	stores := make([]projectStore, 0, len(selectors))
	var errs []error
	for _, selector := range selectors {
		store, err := resolveProjectStoreSelector(selector)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", selector, err))
			continue
		}
		if _, ok := seen[store.Hash]; ok {
			continue
		}
		seen[store.Hash] = struct{}{}
		stores = append(stores, store)
	}
	return stores, errs
}

func preflightGlobalRebuild(store projectStore, wantOutdated, force bool) globalRebuildPlanItem {
	item := globalRebuildPlanItem{store: store, label: globalProjectLabel(store)}
	vm := inspectGlobalProjectVM(store)
	item.status = globalRebuildStatus(store, vm)
	if reason := globalRebuildMetadataBlocker(store); reason != "" {
		item.reason = "skip: " + reason
		return item
	}
	if err := withGlobalProjectDirectory(store, func() error {
		return preflightGlobalRebuildProject(store, wantOutdated, &item)
	}); err != nil {
		item.reason = "skip: " + err.Error()
		return item
	}
	if item.reason != "" {
		return item
	}
	if reason := globalRebuildCaptureBlocker(store); reason != "" {
		item.reason = "skip: " + reason
		return item
	}
	if !force {
		dirty, hasDirty, err := store.readProjectImageDirty()
		if err != nil {
			item.reason = "skip: unreadable manual-change marker"
			return item
		}
		if hasDirty {
			source := dirty.Source
			if source == "" {
				source = dirty.Reason
			}
			item.reason = fmt.Sprintf("skip: manual image changes (%s); use --force", source)
			return item
		}
	}
	lock, err := acquireExclusiveProjectMutationLock(store, "global projects rebuild", true)
	if err != nil {
		item.reason = "skip: " + err.Error()
		return item
	}
	if err := lock.release(); err != nil {
		item.reason = "skip: release project lock: " + err.Error()
		return item
	}
	item.eligible = true
	item.action = "rebuild"
	if vm.running != nil {
		item.action = "stop and rebuild"
	}
	return item
}

func preflightGlobalRebuildProject(store projectStore, wantOutdated bool, item *globalRebuildPlanItem) error {
	path, ok, err := store.readProjectPath()
	if err != nil || !ok || path == "" {
		return fmt.Errorf("project path metadata is unavailable")
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("project root is unavailable")
	}
	if storeDirForPath(path) != store.Path {
		return fmt.Errorf("recorded project root does not belong to this store")
	}
	format, err := os.ReadFile(store.imageFormatPath())
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read project image format: %w", err)
	}
	currentFormat := strings.TrimSpace(string(format)) == projectImageFormatVersion
	if len(format) > 0 && !currentFormat {
		return fmt.Errorf("unsupported project image format")
	}
	if currentFormat {
		imageInfo, err := os.Stat(store.authoritativeImagePath())
		if err != nil || !imageInfo.Mode().IsRegular() {
			return fmt.Errorf("project image is missing or unreadable")
		}
	} else if !legacyProjectImageExists(store) {
		return fmt.Errorf("legacy project image is missing")
	}
	records, err := readBatchRebuildRecords(store, currentFormat)
	if err != nil {
		return err
	}
	working := make([]appliedSetup, 0, len(records))
	for _, record := range records {
		if !record.Inherited {
			working = append(working, record)
		}
	}
	baseOutdated, err := preflightGlobalBase(store, currentFormat)
	if err != nil {
		return err
	}
	item.outdated = !currentFormat || baseOutdated
	if wantOutdated && !item.outdated {
		item.reason = "current base/runtime and backing selection"
		item.ignored = true
		return nil
	}
	definitions, missing, err := resolveAppliedSetupDefinitionsReadOnly(working)
	if err != nil {
		return err
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing applied setup definitions: %s", strings.Join(displayAppliedSetupNames(missing), ", "))
	}
	item.aptIssues = setupAptConfirmationIssues(definitions)
	return nil
}

func preflightGlobalBase(store projectStore, currentFormat bool) (bool, error) {
	disk := store.disk()
	if disk == "" || disk == "unknown" {
		return false, fmt.Errorf("project disk metadata is unavailable")
	}
	manifest, customized, err := readGlobalBaseManifest()
	if err != nil {
		return false, fmt.Errorf("current base image is unavailable: %w", err)
	}
	var expected projectBackingPin
	var backing string
	if customized {
		backing = filepath.Join(globalBaseRevisionRoot(manifest.Revision), "sizes", contentVersion([]byte(disk))[:12], "base.qcow2")
		expected = projectBackingPin{Schema: 1, Kind: "custom", RuntimeVersion: manifest.RuntimeVersion, Revision: manifest.Revision, Disk: disk, Path: backing}
	} else {
		backing = sharedBaseImagePath(disk)
		expected = projectBackingPin{Schema: 1, Kind: "factory", RuntimeVersion: baseRootfsVersion(), Disk: disk, Path: backing}
	}
	if info, err := os.Stat(backing); err == nil {
		if !info.Mode().IsRegular() {
			return false, fmt.Errorf("current base image variant is unavailable")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		output, err := exec.CommandContext(ctx, findTool("qemu-img", "/usr/bin/qemu-img"), "info", "-f", "qcow2", "--output=json", backing).CombinedOutput()
		if err != nil {
			return false, fmt.Errorf("current base image variant is unreadable: %w (%s)", err, strings.TrimSpace(string(output)))
		}
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("current base image variant is unavailable: %w", err)
	}
	recordedRuntime, recorded, err := store.readBaseImageVersion()
	if err != nil || !recorded || recordedRuntime == "" {
		return false, fmt.Errorf("recorded base runtime version is incomplete")
	}
	pin, ok, err := store.readBackingPin()
	if err != nil {
		return false, err
	}
	if !currentFormat && !ok {
		return true, nil
	}
	if !ok || pin.Schema != 1 || pin.Path == "" || pin.RuntimeVersion == "" || pin.Disk == "" || (pin.Kind != "factory" && pin.Kind != "custom") {
		return false, fmt.Errorf("project backing selection is incomplete")
	}
	if pin.Kind == "custom" && pin.Revision == "" {
		return false, fmt.Errorf("project custom backing revision is incomplete")
	}
	if pin.Kind != expected.Kind || pin.Disk != expected.Disk || pin.RuntimeVersion == "" {
		return true, nil
	}
	return recordedRuntime != baseRootfsVersion() || pin.Path != expected.Path || pin.Revision != expected.Revision || pin.RuntimeVersion != expected.RuntimeVersion, nil
}

func globalRebuildMetadataBlocker(store projectStore) string {
	for _, path := range []string{projectTransactionJournalPath(store), projectMetadataJournalPath(store), store.setupExecutionIntentPath()} {
		if _, err := os.Lstat(path); err == nil {
			return "project recovery is needed before rebuild"
		} else if !os.IsNotExist(err) {
			return "project transaction metadata is unreadable"
		}
	}
	return ""
}

func globalRebuildCaptureBlocker(store projectStore) string {
	info, err := os.Lstat(store.setupCaptureMetadataPath())
	if err == nil && !info.Mode().IsRegular() {
		return "capture metadata is unreadable"
	}
	if err == nil {
		if _, _, readErr := store.readSetupCaptureMetadata(); readErr != nil {
			return "capture metadata is unreadable"
		}
		return "capture pending"
	}
	if !os.IsNotExist(err) {
		return "capture metadata is unreadable"
	}
	if _, err := os.Lstat(store.setupCaptureOverlayPath()); err == nil {
		return "capture pending"
	} else if !os.IsNotExist(err) {
		return "capture overlay is unreadable"
	}
	return ""
}

func globalRebuildStatus(store projectStore, vm globalProjectVM) string {
	status := globalProjectStatus(store, vm)
	if !strings.Contains(status, ", capture") && globalRebuildCaptureBlocker(store) != "" {
		status += ", capture"
	}
	return status
}

func printGlobalRebuildPreview(plan []globalRebuildPlanItem) error {
	writer := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(writer, "\nPROJECT\tSTATUS\tACTION"); err != nil {
		return err
	}
	for _, item := range plan {
		action := item.action
		if action == "" {
			action = item.reason
		}
		if _, err := fmt.Fprintf(writer, "%s\t%s\t%s\n", item.label, item.status, action); err != nil {
			return err
		}
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	eligibleRunning := make([]string, 0)
	for _, item := range plan {
		if item.eligible && strings.HasPrefix(item.action, "stop") {
			eligibleRunning = append(eligibleRunning, item.label)
		}
	}
	if len(eligibleRunning) > 0 {
		fmt.Printf("\nWill stop %s and close attached shells.\n", strings.Join(eligibleRunning, ", "))
	}
	fmt.Println("Rebuilt VMs will remain stopped.")
	for _, item := range plan {
		if !item.eligible {
			continue
		}
		for _, issue := range item.aptIssues {
			fmt.Fprintf(os.Stderr, "warning: %s: setup %s has an APT command without automatic confirmation (%s:%d): %s\n", item.label, issue.SetupName, filepath.Base(issue.Path), issue.Line, issue.Command)
		}
	}
	return nil
}

func confirmGlobalRebuild(eligible int) bool {
	fmt.Printf("\nRebuild %d project(s)? [y/N] ", eligible)
	var answer string
	_, err := fmt.Scanln(&answer)
	if err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(answer), "y") || strings.EqualFold(strings.TrimSpace(answer), "yes")
}

func executeGlobalRebuild(store projectStore, force bool) error {
	lock, err := acquireExclusiveProjectMutationLock(store, "global projects rebuild", true)
	if err != nil {
		return globalRebuildSkipError{reason: err.Error()}
	}
	defer lock.releaseWithWarning()
	if reason := globalRebuildMetadataBlocker(store); reason != "" {
		return globalRebuildSkipError{reason: reason}
	}
	if reason := globalRebuildCaptureBlocker(store); reason != "" {
		return globalRebuildSkipError{reason: reason}
	}
	if err := lock.recover(store, "global projects rebuild"); err != nil {
		return globalRebuildSkipError{reason: fmt.Sprintf("recovery required: %v", err)}
	}
	path, ok, err := store.readProjectPath()
	if err != nil || !ok || storeDirForPath(path) != store.Path {
		return globalRebuildSkipError{reason: "recorded project root changed or is unavailable"}
	}
	executionErr := withGlobalProjectDirectory(store, func() error {
		if err := recheckGlobalRebuildInputs(store, force); err != nil {
			return globalRebuildSkipError{reason: err.Error()}
		}
		vm := inspectGlobalProjectVM(store)
		if vm.running != nil {
			monitorVM, _ := detectRunningProjectVMInStore(store)
			if monitorVM == nil {
				return fmt.Errorf("VM remains running; monitor is unavailable")
			}
			fmt.Printf(":: %s: stopping VM...\n", globalProjectLabel(store))
			if _, err := stopProjectVMInStore(store, false); err != nil {
				state := "VM is off"
				if inspectGlobalProjectVM(store).running != nil {
					state = "VM remains running"
				}
				return fmt.Errorf("VM stop failed; %s: %w", state, err)
			}
		}
		if observed := inspectGlobalProjectVM(store); observed.running != nil {
			return fmt.Errorf("VM stop returned without stopping the VM")
		}
		if err := store.clearRuntimeState(); err != nil {
			return fmt.Errorf("VM is off, but runtime cleanup failed: %w", err)
		}
		if err := rebuildProjectFromRecordsBatch(force); err != nil {
			return fmt.Errorf("%w; previous image retained, VM remains off", err)
		}
		return nil
	})
	var contextErr globalRebuildContextError
	if errors.As(executionErr, &contextErr) {
		return globalRebuildSkipError{reason: contextErr.Error()}
	}
	return executionErr
}

type globalRebuildSkipError struct{ reason string }

func (err globalRebuildSkipError) Error() string { return err.reason }

type globalRebuildContextError struct{ reason string }

func (err globalRebuildContextError) Error() string { return err.reason }

func recheckGlobalRebuildInputs(store projectStore, force bool) error {
	if reason := globalRebuildMetadataBlocker(store); reason != "" {
		return fmt.Errorf("%s", reason)
	}
	if reason := globalRebuildCaptureBlocker(store); reason != "" {
		return fmt.Errorf("%s", reason)
	}
	if !force {
		_, dirty, err := store.readProjectImageDirty()
		if err != nil {
			return fmt.Errorf("manual-change marker is unreadable: %w", err)
		}
		if dirty {
			return fmt.Errorf("manual image changes appeared after preview")
		}
	}
	item := globalRebuildPlanItem{}
	return preflightGlobalRebuildProject(store, false, &item)
}

func legacyProjectImageExists(store projectStore) bool {
	return len(legacyProjectImagePaths(store)) > 0
}

func legacyProjectImagePaths(store projectStore) []string {
	entries, err := os.ReadDir(store.Path)
	if err != nil {
		return nil
	}
	var paths []string
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "image-") || !strings.HasSuffix(entry.Name(), ".qcow2") {
			continue
		}
		info, err := entry.Info()
		if err == nil && info.Mode().IsRegular() {
			paths = append(paths, filepath.Join(store.Path, entry.Name()))
		}
	}
	return paths
}

func resolveAppliedSetupDefinitionsReadOnly(records []appliedSetup) ([]setupDefinition, []appliedSetup, error) {
	definitions := make([]setupDefinition, 0, len(records))
	missing := make([]appliedSetup, 0)
	var temporaryRoots []string
	defer func() {
		for _, root := range temporaryRoots {
			_ = os.RemoveAll(root)
		}
	}()
	for _, record := range records {
		if !isValidResourceName(record.Name) {
			return nil, nil, fmt.Errorf("invalid applied setup name: %q", record.Name)
		}
		var root string
		if record.ProjectLocal {
			root = filepath.Join(".zaigr", "setups", record.Name)
			info, err := os.Stat(root)
			if os.IsNotExist(err) {
				missing = append(missing, record)
				continue
			}
			if err != nil || !info.IsDir() {
				return nil, nil, fmt.Errorf("invalid setup path: %s", displaySetupName(record.Name, true))
			}
		} else {
			root = filepath.Join(zaigDir(), "setups", record.Name)
			sourceRoot := path.Join("builtin/setups", record.Name)
			if _, err := fs.Stat(builtinAssets, sourceRoot); err == nil {
				// Execution refreshes bundled setups from this binary. Inspect
				// that same source without rewriting the user's setup directory.
				temporaryRoot, tempErr := os.MkdirTemp("", "zaigr-rebuild-preflight-")
				if tempErr != nil {
					return nil, nil, tempErr
				}
				temporaryRoots = append(temporaryRoots, temporaryRoot)
				if tempErr := syncEmbeddedPresetDir(sourceRoot, temporaryRoot); tempErr != nil {
					return nil, nil, tempErr
				}
				root = temporaryRoot
			} else if !os.IsNotExist(err) {
				return nil, nil, err
			} else {
				info, err := os.Stat(root)
				if os.IsNotExist(err) {
					missing = append(missing, record)
					continue
				}
				if err != nil || !info.IsDir() {
					return nil, nil, fmt.Errorf("invalid setup path: %s", record.Name)
				}
			}
		}
		definition, err := loadSetupDefinitionAt(record.Name, root, record.ProjectLocal)
		if err != nil {
			return nil, nil, err
		}
		definitions = append(definitions, definition)
	}
	return definitions, missing, nil
}

func withGlobalProjectDirectory(store projectStore, action func() error) (returnErr error) {
	path, ok, err := store.readProjectPath()
	if err != nil {
		return globalRebuildContextError{reason: err.Error()}
	}
	if !ok || path == "" {
		return globalRebuildContextError{reason: "project path metadata is unavailable"}
	}
	old, err := os.Getwd()
	if err != nil {
		return globalRebuildContextError{reason: err.Error()}
	}
	if err := os.Chdir(path); err != nil {
		return globalRebuildContextError{reason: err.Error()}
	}
	defer func() {
		if restoreErr := os.Chdir(old); restoreErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("restore working directory: %w", restoreErr))
		}
	}()
	return action()
}

func globalRebuildSelectionError(selectionErrors []error, plan []globalRebuildPlanItem) error {
	if len(selectionErrors) > 0 {
		return errors.Join(selectionErrors...)
	}
	if !hasHardPlanSkips(plan) {
		return nil
	}
	return fmt.Errorf("%d selected project(s) skipped", len(globalRebuildPlanSkips(plan)))
}

func globalRebuildPlanSkips(plan []globalRebuildPlanItem) []globalRebuildResult {
	results := make([]globalRebuildResult, 0)
	for _, item := range plan {
		if item.eligible || item.ignored {
			continue
		}
		results = append(results, globalRebuildResult{store: item.store, label: item.label, status: item.reason})
	}
	return results
}

func hasHardPlanSkips(plan []globalRebuildPlanItem) bool {
	for _, item := range plan {
		if !item.eligible && !item.ignored {
			return true
		}
	}
	return false
}

func printGlobalRebuildSummary(rebuilt, failed, skipped []globalRebuildResult) {
	fmt.Printf("\nRebuilt: %d", len(rebuilt))
	for _, result := range rebuilt {
		fmt.Printf(" — %s", result.label)
	}
	fmt.Printf("\nFailed:  %d", len(failed))
	for _, result := range failed {
		fmt.Printf(" — %s", result.label)
	}
	fmt.Printf("\nSkipped: %d", len(skipped))
	for _, result := range skipped {
		fmt.Printf(" — %s", result.label)
		if result.status != "" {
			fmt.Printf(" (%s)", strings.TrimPrefix(result.status, "skip: "))
		}
	}
	fmt.Println()
}
