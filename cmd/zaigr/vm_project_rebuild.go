package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

type setupScopeKey struct {
	name         string
	projectLocal bool
}

func cleanProjectToCurrentBase() error {
	store := currentProjectStore()
	current, err := store.usesCurrentImageFormat()
	if err != nil {
		return err
	}
	disk, _ := resolveDisk("")
	ram := store.ram()
	cpus := store.cpus()
	projectPath, hasProjectPath, err := store.readProjectPath()
	if err != nil {
		return err
	}
	firewallIPs, err := store.firewallIPs()
	if err != nil {
		return err
	}

	stagingDir, err := os.MkdirTemp(projectStoreRoot(), ".clean-*")
	if err != nil {
		return fmt.Errorf("create clean staging directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(stagingDir) }()
	candidate := filepath.Join(stagingDir, projectImageFileName)
	selection, err := createProjectOverlayFromCurrent(candidate, disk, ram, cpus)
	if err != nil {
		return fmt.Errorf("create clean project overlay: %w", err)
	}

	if !current {
		stagedStore := projectStore{Path: filepath.Join(stagingDir, "store")}
		if err := os.MkdirAll(stagedStore.Path, 0755); err != nil {
			return fmt.Errorf("stage clean project store: %w", err)
		}
		if err := os.Rename(candidate, stagedStore.authoritativeImagePath()); err != nil {
			return fmt.Errorf("stage clean project image: %w", err)
		}
		if err := writeCleanProjectMetadata(stagedStore, disk, ram, cpus, projectPath, hasProjectPath, selection); err != nil {
			return fmt.Errorf("stage clean project metadata: %w", err)
		}
		if err := stagedStore.writeFirewallIPs(firewallIPs); err != nil {
			return fmt.Errorf("preserve project firewall IP permissions: %w", err)
		}
		fmt.Fprintln(os.Stderr, ":: Discarding incompatible legacy project image and setup state")
		if err := publishLegacyCleanStore(store, stagedStore.Path); err != nil {
			return err
		}
	} else {
		metadataPaths := cleanMetadataPaths(store)
		if err := publishProjectReplacement(store, candidate, metadataPaths, func() error {
			return writeCleanProjectMetadata(store, disk, ram, cpus, projectPath, hasProjectPath, selection)
		}); err != nil {
			return fmt.Errorf("clean project transaction: %w", err)
		}
	}
	fmt.Printf(":: Cleaned project to current base: %s\n", filepath.Base(store.authoritativeImagePath()))
	return nil
}

func writeCleanProjectMetadata(store projectStore, disk, ram, cpus, projectPath string, hasProjectPath bool, selection baseImageSelection) error {
	if err := writeFileAtomically(store.configPath(), []byte(fmt.Sprintf("disk=%s\n", disk)), 0644); err != nil {
		return err
	}
	if ram != "" {
		if err := writeFileAtomically(filepath.Join(store.Path, "ram"), []byte(ram+"\n"), 0644); err != nil {
			return err
		}
	}
	if cpus != "" {
		if err := writeFileAtomically(filepath.Join(store.Path, "cpus"), []byte(cpus+"\n"), 0644); err != nil {
			return err
		}
	}
	if hasProjectPath {
		if err := store.writeProjectPath(projectPath); err != nil {
			return err
		}
	} else if err := store.writeProjectPath(canonicalPath(".")); err != nil {
		return err
	}
	if err := store.writeAppliedSetups(selection.Applied); err != nil {
		return err
	}
	if err := store.clearSetupFailureMarker(); err != nil {
		return err
	}
	if err := store.writeFirewallEntries(selection.Firewall); err != nil {
		return err
	}
	if err := removeFileIfExists(store.presetSelectionPath()); err != nil {
		return fmt.Errorf("remove preset selection: %w", err)
	}
	if err := store.clearProjectImageDirty(); err != nil {
		return err
	}
	if err := store.writeBaseImageVersion(baseRootfsVersion()); err != nil {
		return err
	}
	if err := store.writeBackingPin(selection.Pin); err != nil {
		return err
	}
	return store.writeCurrentImageFormat()
}

func cleanMetadataPaths(store projectStore) []string {
	return []string{
		store.configPath(),
		filepath.Join(store.Path, "ram"),
		filepath.Join(store.Path, "cpus"),
		store.projectPathPath(),
		store.appliedSetupsPath(),
		store.setupFailureMarkerPath(),
		store.firewallPath(),
		store.presetSelectionPath(),
		store.projectImageDirtyPath(),
		store.baseImageVersionPath(),
		store.imageFormatPath(),
		store.backingPinPath(),
	}
}

func rebuildMetadataPaths(store projectStore) []string {
	return []string{
		store.configPath(),
		store.appliedSetupsPath(),
		store.firewallPath(),
		store.baseImageVersionPath(),
		store.projectImageDirtyPath(),
		store.backingPinPath(),
	}
}

type projectFileSnapshot struct {
	path   string
	data   []byte
	mode   os.FileMode
	exists bool
}

const (
	projectTransactionJournalFile = ".project-replacement-transaction.json"
	projectMetadataJournalFile    = ".project-metadata-transaction.json"
	projectTransactionBackupFile  = ".project.qcow2.transaction-old"
	transactionPhasePrepared      = "prepared"
	transactionPhaseCommitted     = "committed"
	transactionPhaseBackupReady   = "backup-ready"
	transactionPhaseImageReady    = "image-published"
	transactionPhaseMetadataReady = "metadata-published"
)

type projectFileSnapshotJournal struct {
	Path   string `json:"path"`
	Data   []byte `json:"data,omitempty"`
	Mode   uint32 `json:"mode,omitempty"`
	Exists bool   `json:"exists"`
}

type projectReplacementJournal struct {
	Phase     string                       `json:"phase"`
	HadImage  bool                         `json:"had_image"`
	Candidate string                       `json:"candidate"`
	Snapshots []projectFileSnapshotJournal `json:"snapshots"`
}

type projectMetadataJournal struct {
	Phase     string                       `json:"phase"`
	Snapshots []projectFileSnapshotJournal `json:"snapshots"`
}

func projectTransactionJournalPath(store projectStore) string {
	return filepath.Join(store.Path, projectTransactionJournalFile)
}

func projectMetadataJournalPath(store projectStore) string {
	return filepath.Join(store.Path, projectMetadataJournalFile)
}

func snapshotsToJournal(snapshots []projectFileSnapshot) []projectFileSnapshotJournal {
	entries := make([]projectFileSnapshotJournal, 0, len(snapshots))
	for _, snapshot := range snapshots {
		entries = append(entries, projectFileSnapshotJournal{
			Path: snapshot.path, Data: snapshot.data, Mode: uint32(snapshot.mode.Perm()), Exists: snapshot.exists,
		})
	}
	return entries
}

func snapshotsFromJournal(store projectStore, entries []projectFileSnapshotJournal) ([]projectFileSnapshot, error) {
	snapshots := make([]projectFileSnapshot, 0, len(entries))
	for _, entry := range entries {
		path := filepath.Clean(entry.Path)
		relative, err := filepath.Rel(store.Path, path)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
			return nil, fmt.Errorf("transaction snapshot path escapes project store: %s", entry.Path)
		}
		snapshots = append(snapshots, projectFileSnapshot{
			path: path, data: entry.Data, mode: os.FileMode(entry.Mode), exists: entry.Exists,
		})
	}
	return snapshots, nil
}

func writeProjectReplacementJournal(store projectStore, journal projectReplacementJournal) error {
	body, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(store.Path, 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(store.Path, ".project-transaction-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(body, '\n')); err != nil {
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
	if err := os.Rename(tmpPath, projectTransactionJournalPath(store)); err != nil {
		return err
	}
	return syncDirectory(store.Path)
}

func clearProjectReplacementJournal(store projectStore) error {
	if err := removeFileIfExists(projectTransactionJournalPath(store)); err != nil {
		return err
	}
	return syncDirectory(store.Path)
}

func writeProjectMetadataJournal(store projectStore, journal projectMetadataJournal) error {
	body, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomically(projectMetadataJournalPath(store), append(body, '\n'), 0600); err != nil {
		return fmt.Errorf("write project metadata transaction journal: %w", err)
	}
	return nil
}

func clearProjectMetadataJournal(store projectStore) error {
	if err := removeFileIfExists(projectMetadataJournalPath(store)); err != nil {
		return err
	}
	return syncDirectory(store.Path)
}

func recoverProjectMetadataTransaction(store projectStore) error {
	body, err := os.ReadFile(projectMetadataJournalPath(store))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var journal projectMetadataJournal
	if err := json.Unmarshal(body, &journal); err != nil {
		return fmt.Errorf("parse project metadata transaction journal: %w", err)
	}
	if journal.Phase == transactionPhaseCommitted {
		return clearProjectMetadataJournal(store)
	}
	if journal.Phase != transactionPhasePrepared {
		return fmt.Errorf("unknown project metadata transaction phase: %s", journal.Phase)
	}
	snapshots, err := snapshotsFromJournal(store, journal.Snapshots)
	if err != nil {
		return err
	}
	if err := restoreProjectFiles(snapshots); err != nil {
		return fmt.Errorf("restore interrupted project metadata transaction: %w", err)
	}
	return clearProjectMetadataJournal(store)
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return err
	}
	return dir.Close()
}

func recoverProjectReplacementTransaction(store projectStore) error {
	journalPath := projectTransactionJournalPath(store)
	body, err := os.ReadFile(journalPath)
	if err != nil {
		if os.IsNotExist(err) {
			return recoverOrphanedProjectReplacementBackup(store)
		}
		return err
	}
	var journal projectReplacementJournal
	if err := json.Unmarshal(body, &journal); err != nil {
		return fmt.Errorf("parse project replacement journal: %w", err)
	}
	snapshots, err := snapshotsFromJournal(store, journal.Snapshots)
	if err != nil {
		return err
	}
	backupPath := filepath.Join(store.Path, projectTransactionBackupFile)
	imagePath := store.authoritativeImagePath()
	if journal.Phase == transactionPhaseMetadataReady {
		if err := removeFileIfExists(backupPath); err != nil {
			return fmt.Errorf("finish committed project image cleanup: %w", err)
		}
		removeSafeTransactionCandidate(store, journal.Candidate)
		return clearProjectReplacementJournal(store)
	}

	if journal.HadImage {
		if _, err := os.Stat(backupPath); err == nil {
			if err := os.Rename(backupPath, imagePath); err != nil {
				return fmt.Errorf("restore interrupted project image: %w", err)
			}
		} else if !os.IsNotExist(err) {
			return err
		} else if journal.Phase != transactionPhasePrepared {
			return fmt.Errorf("cannot recover project transaction: previous image backup is missing")
		}
	} else if err := removeFileIfExists(imagePath); err != nil {
		return fmt.Errorf("restore missing project image state: %w", err)
	}
	if err := restoreProjectFiles(snapshots); err != nil {
		return err
	}
	removeSafeTransactionCandidate(store, journal.Candidate)
	if err := removeFileIfExists(backupPath); err != nil {
		return err
	}
	return clearProjectReplacementJournal(store)
}

func recoverOrphanedProjectReplacementBackup(store projectStore) error {
	backupPath := filepath.Join(store.Path, projectTransactionBackupFile)
	backupInfo, err := os.Lstat(backupPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if !backupInfo.Mode().IsRegular() {
		return fmt.Errorf("cannot recover project transaction: backup is not a regular file")
	}

	imagePath := store.authoritativeImagePath()
	if imageInfo, err := os.Lstat(imagePath); err == nil {
		if !imageInfo.Mode().IsRegular() {
			return fmt.Errorf("cannot recover project transaction: project image is not a regular file")
		}
		if err := os.Remove(backupPath); err != nil {
			return fmt.Errorf("remove orphaned project transaction backup: %w", err)
		}
	} else if os.IsNotExist(err) {
		if err := os.Rename(backupPath, imagePath); err != nil {
			return fmt.Errorf("restore orphaned project transaction backup: %w", err)
		}
	} else {
		return err
	}
	return syncDirectory(store.Path)
}

func removeSafeTransactionCandidate(store projectStore, candidate string) {
	if candidate == "" {
		return
	}
	path := filepath.Clean(candidate)
	root := projectStoreRoot()
	relativeToStore, storeErr := filepath.Rel(store.Path, path)
	insideStore := storeErr == nil && relativeToStore != ".." && !strings.HasPrefix(relativeToStore, ".."+string(os.PathSeparator))
	parent := filepath.Dir(path)
	relativeParent, parentErr := filepath.Rel(root, parent)
	insideCleanStaging := parentErr == nil && filepath.Dir(relativeParent) == "." && strings.HasPrefix(filepath.Base(parent), ".clean-")
	if !insideStore && !insideCleanStaging {
		return
	}
	if path == store.authoritativeImagePath() {
		return
	}
	_ = os.Remove(path)
	if insideCleanStaging {
		_ = os.Remove(parent)
	}
}

func snapshotProjectFiles(paths []string) ([]projectFileSnapshot, error) {
	snapshots := make([]projectFileSnapshot, 0, len(paths))
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				snapshots = append(snapshots, projectFileSnapshot{path: path})
				continue
			}
			return nil, fmt.Errorf("snapshot %s: %w", filepath.Base(path), err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("snapshot %s: expected a regular file", filepath.Base(path))
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("snapshot %s: %w", filepath.Base(path), err)
		}
		snapshots = append(snapshots, projectFileSnapshot{
			path:   path,
			data:   data,
			mode:   info.Mode().Perm(),
			exists: true,
		})
	}
	return snapshots, nil
}

func restoreProjectFiles(snapshots []projectFileSnapshot) error {
	var restoreErr error
	for _, snapshot := range snapshots {
		if snapshot.exists {
			if err := writeFileAtomically(snapshot.path, snapshot.data, snapshot.mode); err != nil {
				restoreErr = errors.Join(restoreErr, fmt.Errorf("restore %s: %w", filepath.Base(snapshot.path), err))
			}
			continue
		}
		if err := removeFileIfExists(snapshot.path); err != nil {
			restoreErr = errors.Join(restoreErr, fmt.Errorf("restore absence of %s: %w", filepath.Base(snapshot.path), err))
		}
	}
	return restoreErr
}

func updateProjectMetadataTransaction(store projectStore, paths []string, update func() error) error {
	if _, err := os.Lstat(projectMetadataJournalPath(store)); err == nil {
		return fmt.Errorf("project metadata transaction journal still exists after recovery")
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect project metadata transaction journal: %w", err)
	}
	snapshots, err := snapshotProjectFiles(paths)
	if err != nil {
		return err
	}
	journal := projectMetadataJournal{Phase: transactionPhasePrepared, Snapshots: snapshotsToJournal(snapshots)}
	if err := writeProjectMetadataJournal(store, journal); err != nil {
		return err
	}
	if err := update(); err != nil {
		if restoreErr := restoreProjectFiles(snapshots); restoreErr != nil {
			return fmt.Errorf("%w (metadata rollback failed: %v)", err, restoreErr)
		}
		if journalErr := clearProjectMetadataJournal(store); journalErr != nil {
			return fmt.Errorf("%w (metadata rollback cleanup failed: %v)", err, journalErr)
		}
		return err
	}
	journal.Phase = transactionPhaseCommitted
	if err := writeProjectMetadataJournal(store, journal); err != nil {
		if restoreErr := restoreProjectFiles(snapshots); restoreErr != nil {
			return fmt.Errorf("%w (metadata rollback failed: %v)", err, restoreErr)
		}
		if journalErr := clearProjectMetadataJournal(store); journalErr != nil {
			return fmt.Errorf("%w (metadata rollback cleanup failed: %v)", err, journalErr)
		}
		return err
	}
	if err := clearProjectMetadataJournal(store); err != nil {
		logWarn("committed project metadata transaction cleanup is incomplete", "error", err)
		fmt.Fprintf(os.Stderr, "warning: project metadata was committed, but transaction cleanup is incomplete: %v\n", err)
	}
	return nil
}

func removeFileIfExists(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func publishProjectReplacement(store projectStore, candidate string, metadataPaths []string, updateMetadata func() error) error {
	snapshots, err := snapshotProjectFiles(metadataPaths)
	if err != nil {
		return err
	}
	imagePath := store.authoritativeImagePath()
	backupPath := filepath.Join(store.Path, projectTransactionBackupFile)
	if _, err := os.Lstat(backupPath); err == nil {
		return fmt.Errorf("project image transaction backup still exists after recovery: %s", backupPath)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect project image transaction backup: %w", err)
	}
	hadImage := true
	if _, err := os.Stat(imagePath); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("inspect current project image: %w", err)
		}
		hadImage = false
	}
	journal := projectReplacementJournal{
		Phase: transactionPhasePrepared, HadImage: hadImage, Candidate: candidate, Snapshots: snapshotsToJournal(snapshots),
	}
	if err := writeProjectReplacementJournal(store, journal); err != nil {
		return fmt.Errorf("record project replacement transaction: %w", err)
	}
	if hadImage {
		if err := os.Link(imagePath, backupPath); err != nil {
			_ = clearProjectReplacementJournal(store)
			return fmt.Errorf("preserve current project image: %w", err)
		}
		journal.Phase = transactionPhaseBackupReady
		if err := writeProjectReplacementJournal(store, journal); err != nil {
			_ = os.Remove(backupPath)
			_ = clearProjectReplacementJournal(store)
			return fmt.Errorf("record project image backup: %w", err)
		}
	}
	rollback := func(cause error) error {
		var imageErr error
		if hadImage {
			imageErr = os.Rename(backupPath, imagePath)
		} else {
			imageErr = removeFileIfExists(imagePath)
		}
		metadataErr := restoreProjectFiles(snapshots)
		if imageErr != nil || metadataErr != nil {
			return fmt.Errorf("%w (rollback failed: %v)", cause, errors.Join(imageErr, metadataErr))
		}
		if journalErr := clearProjectReplacementJournal(store); journalErr != nil {
			return fmt.Errorf("%w (rollback cleanup failed: %v)", cause, journalErr)
		}
		return cause
	}
	if err := os.Rename(candidate, imagePath); err != nil {
		if hadImage {
			_ = os.Remove(backupPath)
		}
		_ = clearProjectReplacementJournal(store)
		return fmt.Errorf("publish replacement project image: %w", err)
	}
	journal.Phase = transactionPhaseImageReady
	if err := writeProjectReplacementJournal(store, journal); err != nil {
		return rollback(fmt.Errorf("record published project image: %w", err))
	}
	if err := updateMetadata(); err != nil {
		return rollback(fmt.Errorf("publish replacement project metadata: %w", err))
	}
	journal.Phase = transactionPhaseMetadataReady
	if err := writeProjectReplacementJournal(store, journal); err != nil {
		return rollback(fmt.Errorf("record published project metadata: %w", err))
	}
	if hadImage {
		if err := os.Remove(backupPath); err != nil {
			logWarn("committed project replacement cleanup is incomplete", "error", err)
			fmt.Fprintf(os.Stderr, "warning: project replacement was committed, but superseded image cleanup is incomplete: %v\n", err)
			return nil
		}
	}
	if err := clearProjectReplacementJournal(store); err != nil {
		logWarn("committed project replacement journal cleanup is incomplete", "error", err)
		fmt.Fprintf(os.Stderr, "warning: project replacement was committed, but transaction cleanup is incomplete: %v\n", err)
	}
	return nil
}

func publishLegacyCleanStore(store projectStore, stagedStore string) error {
	backupPath := store.Path + ".legacy-clean-transaction-old"
	if _, err := os.Lstat(backupPath); err == nil {
		return fmt.Errorf("stale legacy clean transaction backup exists: %s", backupPath)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect legacy clean transaction backup: %w", err)
	}
	if err := requireRemovableTree(store.Path); err != nil {
		return fmt.Errorf("legacy project store cannot be safely discarded: %w", err)
	}
	if err := os.Rename(store.Path, backupPath); err != nil {
		return fmt.Errorf("preserve legacy project store: %w", err)
	}
	if err := syncDirectory(filepath.Dir(store.Path)); err != nil {
		restoreErr := os.Rename(backupPath, store.Path)
		return fmt.Errorf("sync preserved legacy project store: %w (rollback: %v)", err, restoreErr)
	}
	if err := os.Rename(stagedStore, store.Path); err != nil {
		restoreErr := os.Rename(backupPath, store.Path)
		if restoreErr != nil {
			return fmt.Errorf("publish clean project store: %w (rollback failed: %v)", err, restoreErr)
		}
		return fmt.Errorf("publish clean project store: %w", err)
	}
	if err := syncDirectory(filepath.Dir(store.Path)); err != nil {
		removeNewErr := os.RemoveAll(store.Path)
		restoreErr := os.Rename(backupPath, store.Path)
		return fmt.Errorf("sync clean project store: %w (rollback failed: %v)", err, errors.Join(removeNewErr, restoreErr))
	}
	if err := os.RemoveAll(backupPath); err != nil {
		logWarn("committed legacy clean cleanup is incomplete", "error", err)
		fmt.Fprintf(os.Stderr, "warning: project clean was committed, but old store cleanup is incomplete: %v\n", err)
		return nil
	}
	if err := syncDirectory(filepath.Dir(store.Path)); err != nil {
		logWarn("committed legacy clean directory sync is incomplete", "error", err)
		fmt.Fprintf(os.Stderr, "warning: project clean was committed, but final directory sync is incomplete: %v\n", err)
	}
	return nil
}

func recoverLegacyCleanTransaction(store projectStore) error {
	backupPath := store.Path + ".legacy-clean-transaction-old"
	backupInfo, err := os.Lstat(backupPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if !backupInfo.IsDir() {
		return fmt.Errorf("legacy clean backup is not a directory: %s", backupPath)
	}

	if _, err := os.Lstat(store.Path); err == nil {
		if err := os.RemoveAll(backupPath); err != nil {
			return fmt.Errorf("finish legacy clean backup removal: %w", err)
		}
	} else if os.IsNotExist(err) {
		if err := os.Rename(backupPath, store.Path); err != nil {
			return fmt.Errorf("restore interrupted legacy clean: %w", err)
		}
	} else {
		return err
	}
	return syncDirectory(filepath.Dir(store.Path))
}

func requireRemovableTree(root string) error {
	const writeAndExecute = 3
	if err := syscall.Access(filepath.Dir(root), writeAndExecute); err != nil {
		return fmt.Errorf("access parent directory: %w", err)
	}
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() {
			return nil
		}
		if err := syscall.Access(path, writeAndExecute); err != nil {
			return fmt.Errorf("access directory %s: %w", path, err)
		}
		return nil
	})
}

func rebuildProjectFromAppliedState(force bool) error {
	store := currentProjectStore()
	records, err := store.readAppliedSetups()
	if err != nil {
		return err
	}
	return rebuildProjectFromRecords(force, records)
}

// rebuildProjectFromRecordsBatch is the non-interactive rebuild path used by
// global batch rebuild. All protections that can require a user decision are
// handled by its preflight; a failed setup leaves the candidate unpublished.
func rebuildProjectFromRecordsBatch(force bool) error {
	store := currentProjectStore()
	currentFormat, err := store.usesCurrentImageFormat()
	if err != nil {
		return err
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
	definitions, missing, err := resolveAppliedSetupDefinitions(working)
	if err != nil {
		return err
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing applied setup definitions: %s", strings.Join(displayAppliedSetupNames(missing), ", "))
	}
	if !force {
		dirty, hasDirty, err := store.readProjectImageDirty()
		if err != nil {
			return err
		}
		if hasDirty {
			source := dirty.Source
			if source == "" {
				source = dirty.Reason
			}
			return fmt.Errorf("project image has changes made with %s; rerun with --force to rebuild", source)
		}
	}
	if currentFormat {
		_, err = buildRebuildCandidate(store, store, definitions)
		return err
	}
	_, err = rebuildLegacyProjectStore(store, definitions)
	return err
}

// Legacy stores may already have structured records. Use their older script
// history only when that metadata is absent, matching single-project rebuild.
func readBatchRebuildRecords(store projectStore, currentFormat bool) ([]appliedSetup, error) {
	// Current stores deliberately omit this file when no setups are applied.
	if currentFormat {
		return store.readAppliedSetups()
	}
	if _, err := os.Stat(store.appliedSetupsPath()); err == nil {
		return store.readAppliedSetups()
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect applied setup records: %w", err)
	}
	records, err := readLegacyCommittedSetups(store)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("legacy project has no recoverable applied setup records")
	}
	return records, nil
}

func rebuildProjectFromRecords(force bool, records []appliedSetup) error {
	store := currentProjectStore()
	currentFormat, err := store.usesCurrentImageFormat()
	if err != nil {
		return err
	}
	if !force {
		dirty, hasDirty, err := store.readProjectImageDirty()
		if err != nil {
			return err
		}
		if hasDirty {
			source := dirty.Source
			if source == "" {
				source = dirty.Reason
			}
			return fmt.Errorf(
				"project image has changes made with %s. "+
					"Zaigr cannot recover these changes or determine what they are. "+
					"A rebuild will not include them. Rerun with --force to rebuild",
				source,
			)
		}
	}

	if !currentFormat {
		if _, statErr := os.Stat(store.appliedSetupsPath()); os.IsNotExist(statErr) {
			records, err = readLegacyCommittedSetups(store)
			if err != nil {
				return err
			}
			if len(records) == 0 {
				return fmt.Errorf("project rebuild found no recoverable applied setups in the incompatible legacy store; refusing to replace it with a blank image")
			}
		} else if statErr != nil {
			return fmt.Errorf("inspect applied setup records: %w", statErr)
		}
	}
	working := make([]appliedSetup, 0, len(records))
	for _, record := range records {
		if !record.Inherited {
			working = append(working, record)
		}
	}
	for {
		definitions, missing, err := resolveAppliedSetupDefinitions(working)
		if err != nil {
			return err
		}
		if len(missing) > 0 {
			displayedMissing := displayAppliedSetupNames(missing)
			if !promptRemoveSetupsForRebuild("The following applied setups are missing:", displayedMissing) {
				return fmt.Errorf("project rebuild aborted; original project left unchanged")
			}
			working = removeAppliedSetups(working, missing)
			continue
		}
		if err := confirmSetupAptCommands(definitions, "project rebuild"); err != nil {
			return err
		}

		printRebuildVersionChanges(working, definitions)
		var failedSetup *appliedSetup
		if currentFormat {
			failedSetup, err = buildRebuildCandidate(store, store, definitions)
		} else {
			failedSetup, err = rebuildLegacyProjectStore(store, definitions)
		}
		if err != nil {
			if failedSetup == nil {
				return err
			}
			failedDisplayName := displaySetupName(failedSetup.Name, failedSetup.ProjectLocal)
			fmt.Fprintf(os.Stderr, ":: Rebuild setup failed: %s\n", failedDisplayName)
			if !promptRemoveSetupsForRebuild("Remove the failing setup and restart the rebuild?", []string{failedDisplayName}) {
				return fmt.Errorf("project rebuild aborted after setup %s failed; original project left unchanged", failedDisplayName)
			}
			fmt.Printf(":: Restarting rebuild without setup: %s\n", failedDisplayName)
			working = removeAppliedSetups(working, []appliedSetup{*failedSetup})
			continue
		}
		return nil
	}
}

func readLegacyCommittedSetups(store projectStore) ([]appliedSetup, error) {
	seen := make(map[string]struct{})
	records := make([]appliedSetup, 0)
	for _, directory := range []string{"committed", "steps"} {
		entries, err := os.ReadDir(filepath.Join(store.Path, directory))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("read legacy %s setup records: %w", directory, err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := legacySetupName(entry.Name())
			if name == "" {
				continue
			}
			if _, exists := seen[name]; exists {
				continue
			}
			body, err := os.ReadFile(filepath.Join(store.Path, directory, entry.Name()))
			if err != nil {
				return nil, fmt.Errorf("read legacy applied setup %s: %w", name, err)
			}
			records = append(records, appliedSetup{Name: name, Version: contentVersion(body)})
			seen[name] = struct{}{}
		}
	}
	return records, nil
}

func legacySetupName(filename string) string {
	name := strings.TrimSuffix(filename, filepath.Ext(filename))
	if len(name) > 4 && name[3] == '-' {
		name = name[4:]
	}
	return name
}

func rebuildLegacyProjectStore(store projectStore, definitions []setupDefinition) (*appliedSetup, error) {
	disk, _ := resolveDisk("")
	ram := store.ram()
	cpus := store.cpus()
	hadSetupFailure, err := store.hasSetupFailureMarker()
	if err != nil {
		return nil, err
	}
	projectPath, hasProjectPath, err := store.readProjectPath()
	if err != nil {
		return nil, err
	}
	firewallIPs, err := store.firewallIPs()
	if err != nil {
		return nil, err
	}

	stagingDir, err := os.MkdirTemp(projectStoreRoot(), ".legacy-rebuild-*")
	if err != nil {
		return nil, fmt.Errorf("create legacy rebuild staging directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(stagingDir) }()
	stagedStore := projectStore{Hash: store.Hash, Path: filepath.Join(stagingDir, "store")}
	if err := os.MkdirAll(stagedStore.Path, 0755); err != nil {
		return nil, fmt.Errorf("stage rebuilt project store: %w", err)
	}
	selection, err := resolveCurrentBaseSelection(disk, ram, cpus)
	if err != nil {
		return nil, err
	}
	if err := writeCleanProjectMetadata(stagedStore, disk, ram, cpus, projectPath, hasProjectPath, selection); err != nil {
		return nil, fmt.Errorf("stage rebuilt project metadata: %w", err)
	}
	if err := stagedStore.writeFirewallIPs(firewallIPs); err != nil {
		return nil, fmt.Errorf("preserve project firewall IP permissions: %w", err)
	}
	if hadSetupFailure {
		if err := stagedStore.markSetupFailure(); err != nil {
			return nil, fmt.Errorf("preserve setup failure marker: %w", err)
		}
	}

	if err := preserveLegacyAgentState(store, stagedStore); err != nil {
		return nil, err
	}
	failedSetup, err := buildRebuildCandidate(stagedStore, store, definitions)
	if err != nil {
		return failedSetup, err
	}
	if err := publishLegacyCleanStore(store, stagedStore.Path); err != nil {
		return nil, fmt.Errorf("publish rebuilt legacy project store: %w", err)
	}
	fmt.Println(":: Replaced incompatible legacy project store with rebuilt current-format state")
	return nil, nil
}

func preserveLegacyAgentState(sourceStore projectStore, stagedStore projectStore) error {
	source := sourceStore.agentStateDir()
	info, err := os.Lstat(source)
	if os.IsNotExist(err) {
		if err := os.Mkdir(stagedStore.agentStateDir(), 0700); err != nil {
			return fmt.Errorf("stage empty legacy agent state: %w", err)
		}
		return syncDirectory(stagedStore.Path)
	}
	if err != nil {
		return fmt.Errorf("inspect legacy agent state: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("legacy agent state is not a directory: %s", source)
	}

	destination := stagedStore.agentStateDir()
	output, err := exec.Command(
		"cp",
		"--archive",
		"--reflink=auto",
		"--no-target-directory",
		"--",
		source,
		destination,
	).CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			message = err.Error()
		}
		return fmt.Errorf("preserve legacy agent state at %s: %s", source, message)
	}
	if err := syncPreservedTree(destination); err != nil {
		return fmt.Errorf("sync preserved legacy agent state: %w", err)
	}
	return syncDirectory(stagedStore.Path)
}

func syncPreservedTree(root string) error {
	directories := make([]string, 0)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.IsDir() {
			directories = append(directories, path)
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return err
		}
		return file.Close()
	})
	if err != nil {
		return err
	}
	for index := len(directories) - 1; index >= 0; index-- {
		if err := syncDirectory(directories[index]); err != nil {
			return err
		}
	}
	return nil
}

func resolveAppliedSetupDefinitions(records []appliedSetup) ([]setupDefinition, []appliedSetup, error) {
	definitions := make([]setupDefinition, 0, len(records))
	missing := make([]appliedSetup, 0)
	for _, record := range records {
		root := filepath.Join(zaigDir(), "setups", record.Name)
		if record.ProjectLocal {
			root = filepath.Join(".zaigr", "setups", record.Name)
		} else if err := ensureBuiltinSetupDefinition(record.Name); err != nil {
			return nil, nil, err
		}
		if info, err := os.Stat(root); err != nil || !info.IsDir() {
			if err == nil || os.IsNotExist(err) {
				missing = append(missing, record)
				continue
			}
			return nil, nil, err
		}
		loaded, err := loadSetupDefinitionAt(record.Name, root, record.ProjectLocal)
		if err != nil {
			return nil, nil, fmt.Errorf("load applied setup %s: %w", displaySetupName(record.Name, record.ProjectLocal), err)
		}
		definitions = append(definitions, loaded)
	}
	return definitions, missing, nil
}

func displayAppliedSetupNames(records []appliedSetup) []string {
	displayed := make([]string, 0, len(records))
	for _, record := range records {
		displayed = append(displayed, displaySetupName(record.Name, record.ProjectLocal))
	}
	return displayed
}

func printRebuildVersionChanges(records []appliedSetup, definitions []setupDefinition) {
	current := make(map[setupScopeKey]string, len(definitions))
	for _, definition := range definitions {
		current[setupScopeKey{definition.Name, definition.ProjectLocal}] = definition.Version
	}
	changed := make([]appliedSetup, 0)
	for _, record := range records {
		if version, ok := current[setupScopeKey{record.Name, record.ProjectLocal}]; ok && version != record.Version {
			changed = append(changed, record)
		}
	}
	if len(changed) == 0 {
		return
	}
	fmt.Println("The following setups will be applied with a newer version:")
	for _, record := range changed {
		fmt.Printf("  %s: %s -> %s\n", displaySetupName(record.Name, record.ProjectLocal), record.Version, current[setupScopeKey{record.Name, record.ProjectLocal}])
	}
}

func buildRebuildCandidate(store projectStore, sourceStore projectStore, definitions []setupDefinition) (*appliedSetup, error) {
	disk, _ := resolveDisk("")
	candidate := filepath.Join(store.Path, projectImageFileName+".rebuild-wip")
	_ = os.Remove(candidate)
	defer func() { _ = os.Remove(candidate) }()
	selection, err := createProjectOverlayFromCurrent(candidate, disk, store.ram(), store.cpus())
	if err != nil {
		return nil, fmt.Errorf("create rebuild overlay: %w", err)
	}

	stagingDir, err := os.MkdirTemp(store.Path, ".rebuild-setups-*")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(stagingDir) }()
	agentStateDir := filepath.Join(stagingDir, "agent-state")
	if err := copyRebuildAgentState(sourceStore.agentStateDir(), agentStateDir); err != nil {
		return nil, err
	}
	scripts := make([]string, 0, len(definitions))
	for index, definition := range definitions {
		payload, err := buildSetupPayload(definition)
		if err != nil {
			return nil, err
		}
		path := filepath.Join(stagingDir, fmt.Sprintf("%03d-%s.script", index, definition.Name))
		if err := os.WriteFile(path, payload, 0600); err != nil {
			return nil, err
		}
		scripts = append(scripts, path)
	}
	if len(scripts) > 0 {
		ram, ramSource := resolveRAM("")
		if ramSource == "default" {
			ram = "4096"
		}
		cpus, _ := resolveCPUs("")
		port, err := allocateEphemeralSSHPort()
		if err != nil {
			return nil, err
		}
		if err := applyStepsViaSSHWithAgentState(candidate, scripts, ram, cpus, port, true, agentStateDir); err != nil {
			if isGuestSetupExecutionError(err) {
				step := guestSetupExecutionStep(err)
				for index, path := range scripts {
					if filepath.Base(path) == step {
						return &appliedSetup{Name: definitions[index].Name, ProjectLocal: definitions[index].ProjectLocal}, err
					}
				}
				return nil, err
			}
			return nil, err
		}
	}

	newRecords := append([]appliedSetup(nil), selection.Applied...)
	firewallEntries := append([]string(nil), selection.Firewall...)
	for _, definition := range definitions {
		newRecords = upsertAppliedSetup(newRecords, appliedSetup{Name: definition.Name, Version: definition.Version, ProjectLocal: definition.ProjectLocal})
		firewallEntries = appendUniqueFirewallEntries(firewallEntries, definition.FirewallRules)
	}
	if err := publishProjectReplacement(store, candidate, rebuildMetadataPaths(store), func() error {
		if err := writeFileAtomically(store.configPath(), []byte(fmt.Sprintf("disk=%s\n", disk)), 0644); err != nil {
			return err
		}
		if err := store.writeAppliedSetups(newRecords); err != nil {
			return err
		}
		if err := store.writeFirewallEntries(firewallEntries); err != nil {
			return err
		}
		if err := store.writeBaseImageVersion(baseRootfsVersion()); err != nil {
			return err
		}
		if err := store.writeBackingPin(selection.Pin); err != nil {
			return err
		}
		return store.clearProjectImageDirty()
	}); err != nil {
		return nil, err
	}
	fmt.Printf(":: Rebuilt project image from applied setups: %s\n", filepath.Base(store.authoritativeImagePath()))
	fmt.Printf(":: Recorded base image version: %s\n", baseRootfsVersion())
	return nil, nil
}

func copyRebuildAgentState(source, destination string) error {
	info, err := os.Lstat(source)
	if os.IsNotExist(err) {
		if err := os.Mkdir(destination, 0700); err != nil {
			return fmt.Errorf("stage empty rebuild agent state: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect rebuild agent state: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("rebuild agent state is not a directory: %s", source)
	}
	output, err := exec.Command(
		"cp",
		"--archive",
		"--reflink=auto",
		"--no-target-directory",
		"--",
		source,
		destination,
	).CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			message = err.Error()
		}
		return fmt.Errorf("stage rebuild agent state at %s: %s", source, message)
	}
	return nil
}

func promptRemoveSetupsForRebuild(message string, names []string) bool {
	fmt.Fprintln(os.Stderr, message)
	for _, name := range names {
		fmt.Fprintf(os.Stderr, "  %s\n", name)
	}
	fmt.Fprintln(os.Stderr, "   [a] abort               Keep the original project unchanged")
	fmt.Fprintln(os.Stderr, "   [r] remove and rebuild  Exclude the listed setup(s) and restart")
	fmt.Fprint(os.Stderr, "Action [a/r]: ")
	var answer string
	if _, err := fmt.Scanln(&answer); err != nil {
		return false
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "r" || answer == "remove"
}

func removeAppliedSetups(records []appliedSetup, unwanted []appliedSetup) []appliedSetup {
	removed := make(map[setupScopeKey]struct{}, len(unwanted))
	for _, record := range unwanted {
		removed[setupScopeKey{record.Name, record.ProjectLocal}] = struct{}{}
	}
	updated := make([]appliedSetup, 0, len(records))
	for _, record := range records {
		if _, ok := removed[setupScopeKey{record.Name, record.ProjectLocal}]; ok {
			continue
		}
		updated = append(updated, record)
	}
	return updated
}
