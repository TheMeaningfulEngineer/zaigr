package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProjectImageDirtyMetadataMarkReadClear(t *testing.T) {
	store := projectStore{
		Hash: "test123",
		Path: t.TempDir(),
	}
	committedDir := store.setupStateDir(setupStateCommitted)
	if err := os.MkdirAll(committedDir, 0755); err != nil {
		t.Fatalf("create committed setup dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(committedDir, "001-python.sh"), []byte("apt-get install python3\n"), 0755); err != nil {
		t.Fatalf("write committed setup: %v", err)
	}

	if err := store.markProjectImageDirty("root-shell", "zaigr shell --root"); err != nil {
		t.Fatalf("mark dirty project image: %v", err)
	}

	info, ok, err := store.readProjectImageDirty()
	if err != nil {
		t.Fatalf("read dirty project image: %v", err)
	}
	if !ok {
		t.Fatalf("expected dirty project image metadata")
	}
	if info.Reason != "root-shell" {
		t.Fatalf("reason = %q, want root-shell", info.Reason)
	}
	if info.Source != "zaigr shell --root" {
		t.Fatalf("source = %q, want zaigr shell --root", info.Source)
	}
	if info.Time == "" {
		t.Fatalf("expected timestamp")
	}

	imagePath, err := store.imagePath()
	if err != nil {
		t.Fatalf("resolve project image path: %v", err)
	}
	if info.Image != filepath.Base(imagePath) {
		t.Fatalf("image = %q, want %q", info.Image, filepath.Base(imagePath))
	}
	if info.ImagePath != imagePath {
		t.Fatalf("image path = %q, want %q", info.ImagePath, imagePath)
	}

	data, err := os.ReadFile(store.projectImageDirtyPath())
	if err != nil {
		t.Fatalf("read metadata file: %v", err)
	}
	content := string(data)
	for _, want := range []string{
		"reason=root-shell\n",
		"source=zaigr shell --root\n",
		"image=" + filepath.Base(imagePath) + "\n",
		"image_path=" + imagePath + "\n",
		"time=",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("metadata content missing %q:\n%s", want, content)
		}
	}

	if err := store.clearProjectImageDirty(); err != nil {
		t.Fatalf("clear dirty project image: %v", err)
	}
	if _, ok, err := store.readProjectImageDirty(); err != nil || ok {
		t.Fatalf("dirty project image after clear: ok=%v err=%v", ok, err)
	}
}

func TestReadProjectImageDirtyMissingReturnsNotFound(t *testing.T) {
	store := projectStore{
		Hash: "test123",
		Path: t.TempDir(),
	}

	info, ok, err := store.readProjectImageDirty()
	if err != nil {
		t.Fatalf("read missing dirty project image: %v", err)
	}
	if ok {
		t.Fatalf("expected missing dirty metadata, got %#v", info)
	}
}

func TestReadProjectImageDirtyMalformedStillMarksDirty(t *testing.T) {
	store := projectStore{
		Hash: "test123",
		Path: t.TempDir(),
	}
	if err := os.WriteFile(store.projectImageDirtyPath(), []byte("not-key-value\nimage=image-test.qcow2\n"), 0644); err != nil {
		t.Fatalf("write malformed dirty metadata: %v", err)
	}

	info, ok, err := store.readProjectImageDirty()
	if err != nil {
		t.Fatalf("read malformed dirty project image: %v", err)
	}
	if !ok {
		t.Fatalf("expected dirty metadata to be present")
	}
	if info.Reason != "unknown" {
		t.Fatalf("reason = %q, want unknown", info.Reason)
	}
	if info.Source != "unknown" {
		t.Fatalf("source = %q, want unknown", info.Source)
	}
	if info.Image != "image-test.qcow2" {
		t.Fatalf("image = %q, want image-test.qcow2", info.Image)
	}
}
