package main

import (
	"os"
	"path/filepath"
	"testing"
)

func withTempCurrentProject(t *testing.T) {
	t.Helper()

	home := t.TempDir()
	projectDir := t.TempDir()
	t.Setenv("HOME", home)

	originalWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	if err := os.Chdir(projectDir); err != nil {
		t.Fatalf("chdir project: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(originalWd); err != nil {
			t.Fatalf("restore working directory: %v", err)
		}
	})
}

func TestCommitAwaitingSetupsPromotesCleanProjectImageWithoutReplay(t *testing.T) {
	withTempCurrentProject(t)

	awaitingPath, err := storeSaveScript(setupStateAwaitingCommit, []byte("printf 'already-applied'\n"), "fast-promote")
	if err != nil {
		t.Fatalf("save awaiting setup: %v", err)
	}
	committed, err := storeCommittedSetups()
	if err != nil {
		t.Fatalf("load committed setups: %v", err)
	}
	oldImagePath, err := storeImagePathForSteps(committed)
	if err != nil {
		t.Fatalf("resolve current image path: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(oldImagePath), 0755); err != nil {
		t.Fatalf("create store dir: %v", err)
	}
	imageContent := []byte("runtime setup changes already present")
	if err := os.WriteFile(oldImagePath, imageContent, 0644); err != nil {
		t.Fatalf("write current image: %v", err)
	}

	if err := cmdModCommitAwaitingSetups(); err != nil {
		t.Fatalf("commit awaiting setups: %v", err)
	}

	if _, err := os.Stat(oldImagePath); !os.IsNotExist(err) {
		t.Fatalf("old image path still exists or stat failed unexpectedly: %v", err)
	}
	awaiting, err := storeAwaitingCommitSetups()
	if err != nil {
		t.Fatalf("load awaiting setups: %v", err)
	}
	if len(awaiting) != 0 {
		t.Fatalf("awaiting setups = %v, want none", awaiting)
	}
	committed, err = storeCommittedSetups()
	if err != nil {
		t.Fatalf("reload committed setups: %v", err)
	}
	if len(committed) != 1 {
		t.Fatalf("committed setups = %v, want one", committed)
	}
	newImagePath, err := storeImagePathForSteps(committed)
	if err != nil {
		t.Fatalf("resolve promoted image path: %v", err)
	}
	data, err := os.ReadFile(newImagePath)
	if err != nil {
		t.Fatalf("read promoted image: %v", err)
	}
	if string(data) != string(imageContent) {
		t.Fatalf("promoted image content = %q, want %q", string(data), string(imageContent))
	}

	if _, err := os.Stat(awaitingPath); !os.IsNotExist(err) {
		t.Fatalf("awaiting setup file still exists or stat failed unexpectedly: %v", err)
	}
}

func TestPromoteCleanAwaitingSetupsSkipsDirtyProjectImage(t *testing.T) {
	withTempCurrentProject(t)

	awaitingPath, err := storeSaveScript(setupStateAwaitingCommit, []byte("printf 'already-applied'\n"), "dirty-skip")
	if err != nil {
		t.Fatalf("save awaiting setup: %v", err)
	}
	committed, err := storeCommittedSetups()
	if err != nil {
		t.Fatalf("load committed setups: %v", err)
	}
	oldImagePath, err := storeImagePathForSteps(committed)
	if err != nil {
		t.Fatalf("resolve current image path: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(oldImagePath), 0755); err != nil {
		t.Fatalf("create store dir: %v", err)
	}
	if err := os.WriteFile(oldImagePath, []byte("dirty current image"), 0644); err != nil {
		t.Fatalf("write current image: %v", err)
	}
	if err := markCurrentProjectImageDirty("root-shell", "zaigr shell --root"); err != nil {
		t.Fatalf("mark project image dirty: %v", err)
	}

	promotion, promoted, err := promoteCleanAwaitingSetupsWithoutReplay(committed, append(committed, awaitingPath))
	if err != nil {
		t.Fatalf("promote clean awaiting setups: %v", err)
	}
	if promoted {
		t.Fatalf("promoted dirty image: %#v", promotion)
	}
	if _, err := os.Stat(oldImagePath); err != nil {
		t.Fatalf("current image should remain in place: %v", err)
	}
}
