package main

import (
	"embed"
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
		if err := os.RemoveAll(destRoot); err != nil {
			return err
		}
		if err := os.MkdirAll(destRoot, 0755); err != nil {
			return err
		}
		return syncEmbeddedPresetDir(sourceRoot, destRoot)
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
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
