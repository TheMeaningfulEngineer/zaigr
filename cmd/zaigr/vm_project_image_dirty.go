package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const projectImageDirtyFileName = "project-image-dirty"

type projectImageDirtyInfo struct {
	Reason    string
	Source    string
	Image     string
	ImagePath string
	Time      string
}

func (store projectStore) projectImageDirtyPath() string {
	return filepath.Join(store.Path, projectImageDirtyFileName)
}

func markCurrentProjectImageDirty(reason string, source string) error {
	return currentProjectStore().markProjectImageDirty(reason, source)
}

func (store projectStore) markProjectImageDirty(reason string, source string) error {
	imagePath := store.imagePath()
	if err := os.MkdirAll(store.Path, 0755); err != nil {
		return fmt.Errorf("create project store: %w", err)
	}

	lines := []string{
		"reason=" + reason,
		"source=" + source,
		"image=" + filepath.Base(imagePath),
		"image_path=" + imagePath,
		"time=" + time.Now().UTC().Format("20060102-150405Z"),
		"",
	}
	if err := writeFileAtomically(store.projectImageDirtyPath(), []byte(strings.Join(lines, "\n")), 0644); err != nil {
		return fmt.Errorf("write project image dirty metadata: %w", err)
	}
	return nil
}

func (store projectStore) readProjectImageDirty() (projectImageDirtyInfo, bool, error) {
	data, err := os.ReadFile(store.projectImageDirtyPath())
	if err != nil {
		if os.IsNotExist(err) {
			return projectImageDirtyInfo{}, false, nil
		}
		return projectImageDirtyInfo{}, false, fmt.Errorf("read project image dirty metadata: %w", err)
	}

	values := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		values[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}

	info := projectImageDirtyInfo{
		Reason:    values["reason"],
		Source:    values["source"],
		Image:     values["image"],
		ImagePath: values["image_path"],
		Time:      values["time"],
	}
	if info.Reason == "" {
		info.Reason = "unknown"
	}
	if info.Source == "" {
		info.Source = "unknown"
	}
	return info, true, nil
}

func (store projectStore) clearProjectImageDirty() error {
	if err := os.Remove(store.projectImageDirtyPath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove project image dirty metadata: %w", err)
	}
	return nil
}
