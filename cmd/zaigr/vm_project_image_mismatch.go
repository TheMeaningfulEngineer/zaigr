package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type projectImageRecoveryAction int

const (
	projectImageRecoveryActionCancel projectImageRecoveryAction = iota
	projectImageRecoveryActionRebuild
	projectImageRecoveryActionKeep
	projectImageRecoveryActionStatus
)

type projectImageSetupMismatch struct {
	Name             string
	RecordedVersion  string
	AvailableVersion string
}

type projectImageDuplicateSetup struct {
	Name    string
	Version string
	Count   int
}

type projectImageMismatchReport struct {
	BaseImageMismatch  bool
	RecordedBaseImage  string
	AvailableBaseImage string
	MissingImage       bool
	ExpectedImage      string
	UnclearState       bool
	SetupMismatches    []projectImageSetupMismatch
	DuplicateSetups    []projectImageDuplicateSetup
	DirtyImage         bool
	DirtyImageReason   string
	DirtyImageSource   string
	CanRebuild         bool
	CanKeep            bool
}

func (report projectImageMismatchReport) hasBlockingIssue() bool {
	return report.BaseImageMismatch || report.MissingImage || report.UnclearState || len(report.SetupMismatches) > 0
}

func resolveProjectImageForCommand(canKeep bool, canRebuild bool) (projectImageMismatchReport, error) {
	for {
		report, err := collectProjectImageMismatchesForStore(currentProjectStore())
		if err != nil {
			return report, err
		}

		action, err := resolveProjectImageForAction(report, canKeep, canRebuild)
		if err != nil {
			return report, err
		}

		switch action {
		case projectImageRecoveryActionKeep:
			return report, nil
		case projectImageRecoveryActionRebuild:
			if err := stopRunningProjectVMBeforeRecoveryRebuild(); err != nil {
				return report, err
			}
			if err := rebuildProjectImageForMismatchReport(report); err != nil {
				return report, err
			}
			continue
		case projectImageRecoveryActionStatus:
			if err := cmdProjectStatus(); err != nil {
				return report, err
			}
		case projectImageRecoveryActionCancel:
			return report, exitError(1)
		}

		// Recheck after status so the prompt reflects any external changes made while inspecting.
		continue
	}
}

func rebuildProjectImageFromCommittedState() error {
	committed, err := currentProjectStore().committedSetups()
	if err != nil {
		return err
	}
	if len(committed) == 0 {
		if _, err := rebuildProjectImageToBase(); err != nil {
			return err
		}
		if err := currentProjectStore().clearProjectImageDirty(); err != nil {
			return err
		}
		return nil
	}
	if _, err := applyStepsToImage(committed, "", "", "", true); err != nil {
		return err
	}
	if err := currentProjectStore().clearProjectImageDirty(); err != nil {
		return err
	}
	return nil
}

func rebuildProjectImageForMismatchReport(report projectImageMismatchReport) error {
	if len(report.SetupMismatches) == 0 {
		return rebuildProjectImageFromCommittedState()
	}
	return rebuildProjectImageWithLatestSetupDefinitions(report.SetupMismatches)
}

type committedSetupBackup struct {
	content []byte
	mode    os.FileMode
	modTime time.Time
}

func rebuildProjectImageWithLatestSetupDefinitions(mismatches []projectImageSetupMismatch) error {
	committed, err := currentProjectStore().committedSetups()
	if err != nil {
		return err
	}
	if len(committed) == 0 {
		return fmt.Errorf("cannot update setup versions without committed setup state")
	}

	mismatchNames := make([]string, 0, len(mismatches))
	mismatchSet := make(map[string]struct{}, len(mismatches))
	for _, mismatch := range mismatches {
		if _, ok := mismatchSet[mismatch.Name]; ok {
			continue
		}
		mismatchSet[mismatch.Name] = struct{}{}
		mismatchNames = append(mismatchNames, mismatch.Name)
	}

	definitions, err := loadSetupDefinitions(mismatchNames)
	if err != nil {
		return err
	}
	payloadByName := make(map[string][]byte, len(definitions))
	for _, def := range definitions {
		payload, err := buildSetupPayload(def)
		if err != nil {
			return err
		}
		payloadByName[def.Name] = payload
	}

	replacements := make(map[string][]byte, len(payloadByName))
	seen := make(map[string]string, len(payloadByName))
	candidate := append([]string{}, committed...)
	for _, path := range committed {
		name := storeScriptBaseNameFromPath(path)
		payload, ok := payloadByName[name]
		if !ok {
			continue
		}
		if firstPath, exists := seen[name]; exists {
			return fmt.Errorf(
				"cannot rebuild setup %q to latest version with multiple committed records (%s, %s); run `zaigr project status`",
				name,
				filepath.Base(firstPath),
				filepath.Base(path),
			)
		}
		seen[name] = path
		replacements[path] = payload
	}
	for name := range payloadByName {
		if _, ok := seen[name]; !ok {
			return fmt.Errorf("cannot rebuild setup %q to latest version because it is not committed", name)
		}
	}

	latestDir, err := os.MkdirTemp(storeDir(), "latest-setups-")
	if err != nil {
		return fmt.Errorf("create latest setup staging dir: %w", err)
	}
	defer os.RemoveAll(latestDir)

	for index, path := range committed {
		payload, ok := replacements[path]
		if !ok {
			continue
		}
		stagedPath := filepath.Join(latestDir, filepath.Base(path))
		if err := os.WriteFile(stagedPath, payload, 0755); err != nil {
			return fmt.Errorf("stage latest setup %s: %w", filepath.Base(path), err)
		}
		if err := stampScriptVersionTime(stagedPath, payload); err != nil {
			return err
		}
		candidate[index] = stagedPath
	}

	if _, err := applyStepsToImage(candidate, "", "", "", true); err != nil {
		return err
	}

	backups := make(map[string]committedSetupBackup, len(replacements))
	restoreBackups := func() {
		for path, backup := range backups {
			if err := os.WriteFile(path, backup.content, backup.mode); err != nil {
				fmt.Fprintf(os.Stderr, ":: Could not restore committed setup %s: %v\n", filepath.Base(path), err)
				continue
			}
			_ = os.Chmod(path, backup.mode)
			_ = os.Chtimes(path, backup.modTime, backup.modTime)
		}
	}

	for path, payload := range replacements {
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		backups[path] = committedSetupBackup{
			content: content,
			mode:    info.Mode().Perm(),
			modTime: info.ModTime(),
		}
		if err := os.WriteFile(path, payload, info.Mode().Perm()); err != nil {
			restoreBackups()
			return fmt.Errorf("update committed setup %s: %w", filepath.Base(path), err)
		}
		if err := stampScriptVersionTime(path, payload); err != nil {
			restoreBackups()
			return err
		}
	}

	if err := currentProjectStore().clearProjectImageDirty(); err != nil {
		return err
	}
	return nil
}

func collectProjectImageMismatchesForStore(store projectStore) (projectImageMismatchReport, error) {
	report := projectImageMismatchReport{
		CanRebuild: true,
		CanKeep:    true,
	}

	committed, err := store.committedSetups()
	if err != nil {
		return projectImageMismatchReport{}, err
	}

	versionsByName, duplicateSetups, err := collectSetupVersionIndex(committed)
	if err != nil {
		return projectImageMismatchReport{}, err
	}
	report.DuplicateSetups = duplicateSetups

	availableDefinitionsByName := availableSetupDefinitions(versionsByName)
	for name, versions := range versionsByName {
		availableDefinition, ok := availableDefinitionsByName[name]
		if !ok {
			continue
		}
		availableVersion := availableDefinition.Version
		matchesAvailableSetup := false
		for _, recorded := range versions {
			if recorded == availableVersion {
				matchesAvailableSetup = true
				break
			}
		}
		if !matchesAvailableSetup {
			matchesAvailableSetup, err = committedSetupMatchesAvailableDefinition(committed, availableDefinition)
			if err != nil {
				return projectImageMismatchReport{}, err
			}
		}
		if matchesAvailableSetup {
			continue
		}
		report.SetupMismatches = append(report.SetupMismatches, projectImageSetupMismatch{
			Name:             name,
			RecordedVersion:  versions[0],
			AvailableVersion: availableVersion,
		})
	}
	sort.Slice(report.SetupMismatches, func(i, j int) bool {
		if report.SetupMismatches[i].Name == report.SetupMismatches[j].Name {
			return report.SetupMismatches[i].RecordedVersion < report.SetupMismatches[j].RecordedVersion
		}
		return report.SetupMismatches[i].Name < report.SetupMismatches[j].Name
	})

	recordBaseImage, hasRecordedBaseImage, err := store.readBaseImageVersion()
	if err != nil {
		return projectImageMismatchReport{}, err
	}
	if hasRecordedBaseImage && recordBaseImage != "" {
		report.RecordedBaseImage = recordBaseImage
		report.AvailableBaseImage = baseRootfsVersion()
		if report.RecordedBaseImage != report.AvailableBaseImage {
			report.BaseImageMismatch = true
			report.CanKeep = false
		}
	}

	committedImagePath, committedImageMissing, err := validateCommittedProjectImage(committed)
	if err != nil {
		return projectImageMismatchReport{}, err
	}
	if committedImagePath == "" {
		if imagePath, err := store.imagePath(); err == nil {
			committedImagePath = imagePath
		} else {
			return projectImageMismatchReport{}, err
		}
	}
	if committedImageMissing {
		report.MissingImage = true
		report.ExpectedImage = filepath.Base(committedImagePath)
		report.CanKeep = false
	}
	dirty, hasDirty, err := store.readProjectImageDirty()
	if err != nil {
		return projectImageMismatchReport{}, err
	}
	if hasDirty {
		report.DirtyImage = true
		report.DirtyImageReason = dirty.Reason
		report.DirtyImageSource = dirty.Source
	}

	return report, nil
}

func collectSetupVersionIndex(setups []string) (map[string][]string, []projectImageDuplicateSetup, error) {
	byName := make(map[string][]string)
	for _, path := range setups {
		name := storeScriptBaseNameFromPath(path)
		if name == "" {
			continue
		}
		version, err := contentVersionFromPath(path)
		if err != nil {
			return nil, nil, err
		}
		byName[name] = append(byName[name], version)
	}

	duplicates := make([]projectImageDuplicateSetup, 0)
	for name, versions := range byName {
		sort.Strings(versions)
		seen := make(map[string]int)
		for _, version := range versions {
			seen[version]++
		}
		for version, count := range seen {
			if count > 1 {
				duplicates = append(duplicates, projectImageDuplicateSetup{
					Name:    name,
					Version: version,
					Count:   count,
				})
			}
		}
	}
	sort.Slice(duplicates, func(i, j int) bool {
		if duplicates[i].Name == duplicates[j].Name {
			return duplicates[i].Version < duplicates[j].Version
		}
		return duplicates[i].Name < duplicates[j].Name
	})
	return byName, duplicates, nil
}

func availableSetupDefinitions(namesToVersion map[string][]string) map[string]setupDefinition {
	availableDefinitions := make(map[string]setupDefinition, len(namesToVersion))
	for name := range namesToVersion {
		defs, err := loadSetupDefinitions([]string{name})
		if err != nil || len(defs) == 0 {
			continue
		}
		availableDefinitions[name] = defs[0]
	}
	return availableDefinitions
}

func committedSetupMatchesAvailableDefinition(committed []string, def setupDefinition) (bool, error) {
	for _, path := range committed {
		if storeScriptBaseNameFromPath(path) != def.Name {
			continue
		}
		matches, err := storedSetupScriptMatchesDefinition(path, def)
		if err != nil {
			return false, err
		}
		if matches {
			return true, nil
		}
	}
	return false, nil
}

func findImageFilesForStore(storePath string) ([]string, error) {
	paths, err := filepath.Glob(filepath.Join(storePath, "image-*.qcow2"))
	if err != nil {
		return nil, nil
	}
	return paths, nil
}

func resolveProjectImageForAction(report projectImageMismatchReport, canKeep bool, canRebuild bool) (projectImageRecoveryAction, error) {
	if !report.hasBlockingIssue() {
		return projectImageRecoveryActionKeep, nil
	}
	includeKeep, includeRebuild := projectImageRecoveryChoices(report, canKeep, canRebuild)
	displayReport := report
	displayReport.CanKeep = includeKeep
	displayReport.CanRebuild = includeRebuild
	printProjectImageMismatchWarnings(os.Stderr, displayReport)
	if !isInteractive() {
		return projectImageRecoveryActionCancel, exitError(1)
	}

	if includeRebuild && !canRebuild {
		fmt.Fprintln(os.Stderr, projectImageRecoveryRunningVMWarning())
	}
	if includeRebuild {
		fmt.Fprintf(os.Stderr, "   [r] rebuild  %s\n", projectImageRecoveryRebuildPrompt(canRebuild, report))
	}
	if includeKeep {
		fmt.Fprintf(os.Stderr, "   [k] keep     Continue with the current image\n")
	}
	fmt.Fprintf(os.Stderr, "   [s] status   Show project status\n")
	fmt.Fprintf(os.Stderr, "   [c] cancel   Leave project unchanged\n")
	fmt.Fprintf(os.Stderr, "   [Enter] cancel\n")

	parts := make([]string, 0, 3)
	if includeRebuild {
		parts = append(parts, "r")
	}
	if includeKeep {
		parts = append(parts, "k")
	}
	parts = append(parts, "s", "c")
	fmt.Fprintf(os.Stderr, "Action [%s]: ", strings.Join(parts, "/"))

	for {
		var answer string
		n, err := fmt.Scanln(&answer)
		if err != nil && n == 0 {
			fmt.Fprintf(os.Stderr, "\nCancelled.\n")
			return projectImageRecoveryActionCancel, nil
		}
		switch strings.ToLower(strings.TrimSpace(answer)) {
		case "rebuild", "r":
			if includeRebuild {
				return projectImageRecoveryActionRebuild, nil
			}
		case "keep", "k":
			if includeKeep {
				return projectImageRecoveryActionKeep, nil
			}
		case "status", "s":
			return projectImageRecoveryActionStatus, nil
		case "cancel", "c", "":
			return projectImageRecoveryActionCancel, nil
		}
		fmt.Fprintf(os.Stderr, "\nInvalid choice. ")
		if includeRebuild {
			fmt.Fprintf(os.Stderr, "enter r")
		}
		if includeKeep {
			if includeRebuild {
				fmt.Fprintf(os.Stderr, ", k")
			} else {
				fmt.Fprintf(os.Stderr, "enter k")
			}
		}
		if includeRebuild || includeKeep {
			fmt.Fprintf(os.Stderr, " to act, ")
		}
		fmt.Fprintf(os.Stderr, "enter s to show project status, or press Enter to cancel.\n")
		fmt.Fprintf(os.Stderr, "Action [%s]: ", strings.Join(parts, "/"))
	}
}

func projectImageRecoveryChoices(report projectImageMismatchReport, canKeep bool, canRebuild bool) (includeKeep bool, includeRebuild bool) {
	includeKeep = canKeep && (report.CanKeep || !canRebuild)
	includeRebuild = report.CanRebuild && (canRebuild || report.BaseImageMismatch || len(report.SetupMismatches) > 0)
	return includeKeep, includeRebuild
}

func projectImageRecoveryRebuildPrompt(canRebuildWithoutStopping bool, report projectImageMismatchReport) string {
	if len(report.SetupMismatches) > 0 {
		if canRebuildWithoutStopping {
			return "Rebuild with latest setup versions"
		}
		return "Stop the running VM and rebuild with latest setup versions"
	}
	if canRebuildWithoutStopping {
		return "Rebuild the project image"
	}
	return "Stop the running VM and rebuild the project image"
}

func projectImageRecoveryRunningVMWarning() string {
	return "warning: rebuilding will stop the running project VM and close any open shells connected to it."
}

func stopRunningProjectVMBeforeRecoveryRebuild() error {
	running, stale := detectRunningProjectVM()
	if stale {
		_ = storeClearRuntimeState()
		return nil
	}
	if running == nil {
		return nil
	}
	fmt.Fprintln(os.Stderr, ":: Stopping running project VM before rebuilding the project image")
	result, err := stopProjectVMInStore(currentProjectStore(), false)
	if err != nil {
		return err
	}
	if result.State != projectVMStopStateStopped {
		return fmt.Errorf("project VM is running; stop it with 'zaigr project vm stop' before rebuilding")
	}
	return nil
}

func printNonInteractiveProjectImageRecoveryHelp(report projectImageMismatchReport) {
	if !report.hasBlockingIssue() {
		return
	}
	if report.BaseImageMismatch || report.MissingImage {
		fmt.Fprintln(os.Stderr, "You can rebuild the project image or inspect project status.")
		return
	}
	if len(report.SetupMismatches) > 0 {
		fmt.Fprintln(os.Stderr, "You can keep using the recorded version, rebuild with the latest setup versions, or inspect project status.")
		return
	}
	if report.UnclearState {
		fmt.Fprintln(os.Stderr, "Run `zaigr project status` for details.")
	}
}

func printProjectImageMismatchWarnings(w io.Writer, report projectImageMismatchReport) {
	if report.BaseImageMismatch {
		fmt.Fprintln(w, "warning: detected a mismatch in the base image versions.")
		fmt.Fprintf(w, "  recorded base image: %s\n", report.RecordedBaseImage)
		fmt.Fprintf(w, "  available base image: %s\n", report.AvailableBaseImage)
		fmt.Fprintln(w)
		fmt.Fprintln(w, "This can happen after updating zaigr.")
		fmt.Fprintln(w)
	}

	if report.UnclearState {
		fmt.Fprintln(w, "warning: the project image state is unclear.")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "zaigr will not choose another image automatically.")
		fmt.Fprintln(w, "Run `zaigr project status` for details.")
		fmt.Fprintln(w)
	}

	for _, mismatch := range report.SetupMismatches {
		fmt.Fprintf(w, "warning: setup \"%s\" has changed.\n", mismatch.Name)
		fmt.Fprintf(w, "  recorded version: %s\n", mismatch.RecordedVersion)
		fmt.Fprintf(w, "  available version: %s\n", mismatch.AvailableVersion)
		fmt.Fprintln(w)
	}

	if report.MissingImage {
		fmt.Fprintln(w, "warning: the project image cannot be found.")
		if report.ExpectedImage != "" {
			fmt.Fprintf(w, "  expected image: %s\n", report.ExpectedImage)
		}
		fmt.Fprintln(w)
	}

	if report.DirtyImage {
		fmt.Fprintf(w, "Your current image has unsaved changes from %s.\n", projectImageDirtySourceForMessage(report))
		fmt.Fprintln(w, "Those changes will be lost if you rebuild.")
	}

	printProjectImageRecoveryAdvice(w, report)
}

func projectImageDirtySourceForMessage(report projectImageMismatchReport) string {
	if report.DirtyImageSource != "" {
		return report.DirtyImageSource
	}
	if report.DirtyImageReason != "" {
		return report.DirtyImageReason
	}
	return "root access"
}

func printProjectImageRecoveryAdvice(w io.Writer, report projectImageMismatchReport) {
	switch {
	case report.UnclearState:
		// Status output only; no default action text.
	case (report.BaseImageMismatch || report.MissingImage) && report.CanRebuild && report.CanKeep:
		fmt.Fprintln(w, "You can keep using the current image, rebuild, or inspect project status.")
	case (report.BaseImageMismatch || report.MissingImage) && report.CanKeep:
		fmt.Fprintln(w, "You can keep using the current image or inspect project status.")
	case report.BaseImageMismatch || report.MissingImage:
		fmt.Fprintln(w, "You can rebuild the project image or inspect project status.")
	case len(report.SetupMismatches) > 0 && report.CanRebuild && report.CanKeep:
		fmt.Fprintln(w, "You can keep using the recorded version, rebuild with the latest setup versions, or inspect project status.")
	case len(report.SetupMismatches) > 0 && report.CanKeep:
		fmt.Fprintln(w, "You can keep using the recorded version or inspect project status.")
	case len(report.SetupMismatches) > 0:
		fmt.Fprintln(w, "You can rebuild with the latest setup versions or inspect project status.")
	}
}

func printProjectImageDuplicateSummary(w io.Writer, duplicates []projectImageDuplicateSetup) {
	if len(duplicates) == 0 {
		return
	}
	fmt.Fprintln(w, "warning: duplicate committed setup records were detected.")
	for _, entry := range duplicates {
		fmt.Fprintf(w, "  %s: %s (%d records)\n", entry.Name, entry.Version, entry.Count)
	}
	fmt.Fprintln(w, "Project recovery paths preserve committed setup metadata; duplicates are not deduplicated automatically.")
}

func isInteractive() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

func projectSetupNamesFromDefinitions(setups []setupDefinition) map[string]struct{} {
	names := make(map[string]struct{}, len(setups))
	for _, def := range setups {
		names[def.Name] = struct{}{}
	}
	return names
}

func filterSetupsByKeep(definitions []setupDefinition, report projectImageMismatchReport) []setupDefinition {
	if len(report.SetupMismatches) == 0 {
		return definitions
	}
	mismatchNames := make(map[string]struct{}, len(report.SetupMismatches))
	for _, mismatch := range report.SetupMismatches {
		mismatchNames[mismatch.Name] = struct{}{}
	}
	filtered := make([]setupDefinition, 0, len(definitions))
	for _, def := range definitions {
		if _, ok := mismatchNames[def.Name]; ok {
			continue
		}
		filtered = append(filtered, def)
	}
	return filtered
}

func projectImageMismatchActionRequiresStatus(action projectImageRecoveryAction) bool {
	return action == projectImageRecoveryActionStatus
}

func projectImageMismatchActionNeedsRebuild(action projectImageRecoveryAction) bool {
	return action == projectImageRecoveryActionRebuild
}
