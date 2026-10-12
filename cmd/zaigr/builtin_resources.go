package main

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

//go:embed builtin/setups/* builtin/setups/*/* builtin/presets/*/* builtin/presets/*/*/*
var builtinAssets embed.FS

func completePresetName(_ *cobra.Command, _ []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
	return completeNames(listAvailablePresets, toComplete)
}

func completeSetupName(_ *cobra.Command, _ []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
	return completeNames(listAvailableSetups, toComplete)
}

func completeNames(lookup func() ([]string, error), toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
	names, err := lookup()
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}
	out := make([]cobra.Completion, 0, len(names))
	for _, name := range names {
		if name == "" {
			continue
		}
		if strings.HasPrefix(name, toComplete) {
			out = append(out, cobra.Completion(name))
		}
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}

func listAvailablePresets() ([]string, error) {
	names := make(map[string]struct{})
	for _, name := range listDirectoryNames(filepath.Join(zaigDir(), "presets"), isPresetDirectory) {
		names[name] = struct{}{}
	}

	for name := range builtinPresetNames() {
		names[name] = struct{}{}
	}

	items := make([]string, 0, len(names))
	for name := range names {
		items = append(items, name)
	}
	sort.Strings(items)
	return items, nil
}

func listAvailableSetups() ([]string, error) {
	names := make(map[string]struct{})
	for _, name := range listDirectoryNames(filepath.Join(zaigDir(), "setups"), isSetupDirectory) {
		names[name] = struct{}{}
	}

	for name := range builtinSetupNames() {
		names[name] = struct{}{}
	}

	items := make([]string, 0, len(names))
	for name := range names {
		items = append(items, name)
	}
	sort.Strings(items)
	return items, nil
}

func listDirectoryNames(dir string, include func(string) bool) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if include == nil {
			out = append(out, name)
			continue
		}
		if include(name) {
			out = append(out, name)
		}
	}
	return out
}

func isPresetDirectory(name string) bool {
	if name == "" || strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return false
	}
	presetRoot := filepath.Join(zaigDir(), "presets", name)
	runPath := filepath.Join(presetRoot, "run")
	_, err := os.Stat(runPath)
	return err == nil
}

func isSetupDirectory(name string) bool {
	if name == "" || strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return false
	}
	setupRoot := filepath.Join(zaigDir(), "setups", name)
	entries, err := os.ReadDir(setupRoot)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.HasSuffix(entry.Name(), ".script") {
			return true
		}
	}
	return false
}

func builtinSetupNames() map[string]struct{} {
	names := make(map[string]struct{})
	entries, err := fs.ReadDir(builtinAssets, "builtin/setups")
	if err != nil {
		return names
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if hasBuiltinSetupScript(path.Join("builtin/setups", name)) {
			names[name] = struct{}{}
		}
	}
	return names
}

func hasBuiltinSetupScript(sourceRoot string) bool {
	entries, err := fs.ReadDir(builtinAssets, sourceRoot)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.HasSuffix(entry.Name(), ".script") {
			return true
		}
	}
	return false
}

func builtinPresetNames() map[string]struct{} {
	names := make(map[string]struct{})
	entries, err := fs.ReadDir(builtinAssets, "builtin/presets")
	if err != nil {
		return names
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if isBuiltinPresetAvailable(name) {
			names[name] = struct{}{}
		}
	}
	return names
}

func isBuiltinPresetAvailable(name string) bool {
	runPath := path.Join("builtin/presets", name, "run")
	_, err := fs.Stat(builtinAssets, runPath)
	return err == nil
}

func ensureBuiltinPresetStructure(name string) error {
	if !isValidResourceName(name) {
		return fmt.Errorf("invalid preset name: %s", name)
	}
	if _, err := fs.Stat(builtinAssets, path.Join("builtin/presets", name, "run")); err == nil {
		return syncEmbeddedPreset(filepath.Join("builtin/presets", name))
	}
	return nil
}

func ensureBuiltinSetupDefinition(name string) error {
	if !isValidResourceName(name) {
		return fmt.Errorf("invalid setup name: %s", name)
	}
	sourceRoot := path.Join("builtin/setups", name)
	if _, err := fs.Stat(builtinAssets, sourceRoot); err == nil {
		destRoot := filepath.Join(zaigDir(), "setups", name)
		if err := os.MkdirAll(filepath.Dir(destRoot), 0755); err != nil {
			return err
		}
		if err := os.Mkdir(destRoot, 0755); err == nil {
			if err := syncEmbeddedPresetDir(sourceRoot, destRoot); err != nil {
				// This call created the directory; do not leave an incomplete
				// default that a retry would mistake for a customization.
				return errors.Join(err, os.RemoveAll(destRoot))
			}
			return nil
		} else if !os.IsExist(err) {
			return err
		}
		matches, err := embeddedSetupDirectoryMatches(sourceRoot, destRoot)
		if err != nil {
			return err
		}
		if !matches {
			fmt.Fprintf(os.Stderr, "warning: global setup %q at %s differs from the built-in default; preserving the existing setup.\n", name, destRoot)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

// refreshBuiltinSetupDefinition replaces a global setup with this binary's embedded default.
func refreshBuiltinSetupDefinition(name string) error {
	if !isValidResourceName(name) {
		return fmt.Errorf("invalid setup name: %s", name)
	}
	sourceRoot := path.Join("builtin/setups", name)
	if !hasBuiltinSetupScript(sourceRoot) {
		if _, err := fs.Stat(builtinAssets, sourceRoot); os.IsNotExist(err) {
			return nil
		} else if err != nil {
			return err
		}
		return nil
	}
	destRoot := filepath.Join(zaigDir(), "setups", name)
	parent := filepath.Dir(destRoot)
	if err := os.MkdirAll(parent, 0755); err != nil {
		return err
	}
	tempRoot, err := os.MkdirTemp(parent, "."+name+"-rebuild-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tempRoot) }()
	if err := syncEmbeddedPresetDir(sourceRoot, tempRoot); err != nil {
		return err
	}
	if err := os.RemoveAll(destRoot); err != nil {
		return err
	}
	return os.Rename(tempRoot, destRoot)
}

// Compare the whole directory so additions and intentional deletions are also
// recognized as customizations. Existing setups are never synchronized in place.
func embeddedSetupDirectoryMatches(sourceRoot, destRoot string) (bool, error) {
	info, err := os.Lstat(destRoot)
	if err != nil {
		return false, err
	}
	if !info.IsDir() {
		return false, nil
	}
	sourceEntries, err := fs.ReadDir(builtinAssets, sourceRoot)
	if err != nil {
		return false, err
	}
	destEntries, err := os.ReadDir(destRoot)
	if err != nil {
		return false, err
	}
	if len(sourceEntries) != len(destEntries) {
		return false, nil
	}
	for i, sourceEntry := range sourceEntries {
		destEntry := destEntries[i]
		if sourceEntry.Name() != destEntry.Name() || sourceEntry.Type() != destEntry.Type() {
			return false, nil
		}
		sourcePath := path.Join(sourceRoot, sourceEntry.Name())
		destPath := filepath.Join(destRoot, destEntry.Name())
		if sourceEntry.IsDir() {
			matches, err := embeddedSetupDirectoryMatches(sourcePath, destPath)
			if err != nil || !matches {
				return matches, err
			}
			continue
		}
		sourceData, err := builtinAssets.ReadFile(sourcePath)
		if err != nil {
			return false, err
		}
		destData, err := os.ReadFile(destPath)
		if err != nil {
			return false, err
		}
		if !bytes.Equal(sourceData, destData) {
			return false, nil
		}
	}
	return true, nil
}

func syncEmbeddedPreset(sourceRoot string) error {
	destRoot := filepath.Join(zaigDir(), strings.TrimPrefix(sourceRoot, "builtin/"))
	entries, err := fs.ReadDir(builtinAssets, sourceRoot)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		sourcePath := path.Join(sourceRoot, entry.Name())
		destPath := filepath.Join(destRoot, entry.Name())
		if entry.IsDir() {
			if err := os.MkdirAll(destPath, 0755); err != nil {
				return err
			}
			if err := syncEmbeddedPresetDir(sourcePath, destPath); err != nil {
				return err
			}
			continue
		}
		if err := syncEmbeddedFile(sourcePath, destPath); err != nil {
			return err
		}
	}
	return nil
}

func syncEmbeddedPresetDir(sourceRoot, destRoot string) error {
	entries, err := fs.ReadDir(builtinAssets, sourceRoot)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		sourcePath := path.Join(sourceRoot, entry.Name())
		destPath := filepath.Join(destRoot, entry.Name())
		if entry.IsDir() {
			if err := os.MkdirAll(destPath, 0755); err != nil {
				return err
			}
			if err := syncEmbeddedPresetDir(sourcePath, destPath); err != nil {
				return err
			}
			continue
		}
		if err := syncEmbeddedFile(sourcePath, destPath); err != nil {
			return err
		}
	}
	return nil
}

func syncEmbeddedFile(sourcePath, destPath string) error {
	data, err := builtinAssets.ReadFile(sourcePath)
	if err != nil {
		return err
	}
	existing, err := os.ReadFile(destPath)
	if err == nil && string(existing) == string(data) {
		return nil
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return err
	}
	return os.WriteFile(destPath, data, 0644)
}

func isValidResourceName(name string) bool {
	if name == "" {
		return false
	}
	if name == "." || name == ".." || strings.Contains(name, "..") {
		return false
	}
	if strings.ContainsAny(name, "/\\") {
		return false
	}
	return true
}
