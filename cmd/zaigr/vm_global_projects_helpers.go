package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

const (
	globalProjectDiskBudget = 250 * time.Millisecond
	globalProjectDiskBatch  = 128
	globalProjectDiskLimit  = 1000000
)

type globalProjectInode struct {
	device uint64
	inode  uint64
}

// resolveProjectStoreSelector gives the persisted ID precedence over a project
// basename. Names are display conveniences and must identify one store.
func resolveProjectStoreSelector(selector string) (projectStore, error) {
	stores, err := listProjectStores()
	if err != nil {
		return projectStore{}, err
	}
	for _, store := range stores {
		if store.Hash == selector {
			return store, nil
		}
	}

	matches := make([]projectStore, 0, 1)
	for _, store := range stores {
		path, ok, readErr := store.readProjectPath()
		if readErr != nil {
			warnGlobalProject(store, readErr)
			continue
		}
		if ok && globalProjectBasename(path) == selector {
			matches = append(matches, store)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return projectStore{}, fmt.Errorf("project not found: %s", selector)
	default:
		ids := make([]string, 0, len(matches))
		for _, store := range matches {
			ids = append(ids, store.Hash)
		}
		sort.Strings(ids)
		return projectStore{}, fmt.Errorf("project name %q is ambiguous; use an ID (%s)", selector, strings.Join(ids, ", "))
	}
}

// completeProjectStoreHash remains available to commands that share the
// historical completion hook while selectors now accept names as well as IDs.
func completeProjectStoreHash(cmd *cobra.Command, args []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
	return completeProjectStoreSelector(cmd, args, toComplete)
}

func globalProjectBasename(path string) string {
	if path == "" || path == unknownProjectPathLabel {
		return ""
	}
	base := filepath.Base(filepath.Clean(path))
	if base == "." || base == string(filepath.Separator) || base == "" {
		return ""
	}
	return base
}

func globalProjectLabel(store projectStore) string {
	path, ok, err := store.readProjectPath()
	if err != nil || !ok {
		return fmt.Sprintf("%s (%s)", unknownProjectPathLabel, store.Hash)
	}
	base := globalProjectBasename(path)
	if base == "" {
		base = unknownProjectPathLabel
	}
	return fmt.Sprintf("%s (%s)", base, store.Hash)
}

func globalProjectStatus(store projectStore, vm globalProjectVM) string {
	baseImage, baseImageErr := readGlobalProjectBaseImage(store)
	warnGlobalProject(store, baseImageErr)
	_, active, err := readGlobalProjectCapture(store)
	if err != nil {
		warnGlobalProject(store, err)
	}
	return globalProjectStatusValue(vm, active, err, baseImage.OutdatedBaseImage)
}

func globalProjectStatusValue(vm globalProjectVM, capture bool, captureErr error, outdated bool) string {
	state := "off"
	if vm.running != nil {
		state = "running"
	}
	if vm.stale {
		state += ", stale"
	}
	if capture || captureErr != nil {
		state += ", capture"
	}
	if outdated {
		state += ", outdated"
	}
	return state
}

// readGlobalProjectBaseImage inspects saved runtime metadata without requiring
// the current image format. Like capture inspection, it only reads regular
// files so a leftover FIFO or symlink cannot block version inspection.
func readGlobalProjectBaseImage(store projectStore) (projectImageMismatchReport, error) {
	report := projectImageMismatchReport{RequiredBaseVersion: baseRootfsVersion()}
	info, err := os.Lstat(store.baseImageVersionPath())
	if os.IsNotExist(err) {
		return report, nil
	}
	if err != nil {
		return report, fmt.Errorf("read recorded base image version: %w", err)
	}
	if !info.Mode().IsRegular() {
		return report, fmt.Errorf("recorded base image version is not a regular file")
	}
	recordedBase, recorded, err := store.readBaseImageVersion()
	if err != nil {
		return report, err
	}
	if recorded {
		report.RecordedBaseVersion = recordedBase
		// Match collectProjectImageMismatchesForStore: unknown versions do not
		// establish a mismatch, and no backing selection or revision is compared.
		report.OutdatedBaseImage = recordedBase != "" && report.RequiredBaseVersion != "" && recordedBase != report.RequiredBaseVersion
	}
	return report, nil
}

// readGlobalProjectCapture checks the marker without following links or
// opening special files. The only file passed to the JSON reader is a regular
// marker, so inspection cannot block on a FIFO or read outside the store.
func readGlobalProjectCapture(store projectStore) (setupCaptureMetadata, bool, error) {
	info, err := os.Lstat(store.setupCaptureMetadataPath())
	if os.IsNotExist(err) {
		return setupCaptureMetadata{}, false, nil
	}
	if err != nil {
		return setupCaptureMetadata{}, false, err
	}
	if !info.Mode().IsRegular() {
		return setupCaptureMetadata{}, false, fmt.Errorf("setup capture metadata is not a regular file")
	}
	return store.readSetupCaptureMetadata()
}

func formatGlobalProjectRAM(megabytes string) string {
	if megabytes == "" {
		return "?"
	}
	value, err := strconv.ParseUint(megabytes, 10, 64)
	if err != nil {
		return "?"
	}
	if value == 0 {
		return "?"
	}
	if value > ^uint64(0)/(1024*1024) {
		return "?"
	}
	return formatGlobalProjectBytes(value * 1024 * 1024)
}

func globalProjectDiskUsage(store projectStore) (string, error) {
	bytes, err := allocatedProjectStoreBytes(store.Path, globalProjectDiskBudget)
	if err != nil {
		return "?", err
	}
	return formatGlobalProjectBytes(bytes), nil
}

func allocatedProjectStoreBytes(root string, budget time.Duration) (uint64, error) {
	deadline := time.Now().Add(budget)
	seen := make(map[globalProjectInode]struct{})
	var total uint64
	entries := 0
	var walk func(string) error
	walk = func(path string) error {
		if time.Now().After(deadline) {
			return fmt.Errorf("disk measurement exceeded %s", budget)
		}
		entries++
		if entries > globalProjectDiskLimit {
			return fmt.Errorf("disk measurement exceeded %d entries", globalProjectDiskLimit)
		}
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			key := globalProjectInode{device: uint64(stat.Dev), inode: uint64(stat.Ino)}
			if _, exists := seen[key]; exists {
				return nil
			}
			seen[key] = struct{}{}
			total += uint64(stat.Blocks) * 512
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open %s: %w", path, err)
		}
		closeDirectory := func(walkErr error) error {
			return errors.Join(walkErr, file.Close())
		}
		for {
			children, readErr := file.Readdir(globalProjectDiskBatch)
			for _, child := range children {
				if err := walk(filepath.Join(path, child.Name())); err != nil {
					return closeDirectory(err)
				}
			}
			if readErr != nil {
				if readErr == io.EOF {
					return closeDirectory(nil)
				}
				return closeDirectory(fmt.Errorf("read directory %s: %w", path, readErr))
			}
		}
	}
	if err := walk(root); err != nil {
		return 0, err
	}
	return total, nil
}

func formatGlobalProjectBytes(value uint64) string {
	units := []struct {
		name  string
		value float64
	}{
		{"GiB", float64(uint64(1024) * 1024 * 1024)},
		{"MiB", float64(uint64(1024) * 1024)},
		{"KiB", float64(1024)},
	}
	for _, unit := range units {
		if float64(value) >= unit.value {
			return fmt.Sprintf("%.1f%s", float64(value)/unit.value, unit.name)
		}
	}
	return fmt.Sprintf("%dB", value)
}
