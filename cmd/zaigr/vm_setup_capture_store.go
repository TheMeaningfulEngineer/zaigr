package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const setupCaptureMetadataFile = "setup-capture.json"
const setupCaptureOverlayFile = "capture-overlay.qcow2"
const setupCaptureObservedEndpointsFile = "setup-capture-endpoints"
const setupCaptureCommandsFile = "setup-capture/commands.log"
const setupCaptureLegacyCommandsFile = "setup-capture/commands.history"

type setupCaptureMetadata struct {
	Name             string   `json:"name"`
	StartedAt        string   `json:"started_at"`
	BaseImagePath    string   `json:"base_image_path"`
	OverlayImagePath string   `json:"overlay_image_path"`
	ObservedFirewall []string `json:"observed_firewall_entries"`
}

func (store projectStore) setupCaptureMetadataPath() string {
	return filepath.Join(store.Path, setupCaptureMetadataFile)
}

func (store projectStore) setupCaptureOverlayPath() string {
	return filepath.Join(store.Path, setupCaptureOverlayFile)
}

func (store projectStore) setupCaptureObservedEndpointsPath() string {
	return filepath.Join(store.Path, setupCaptureObservedEndpointsFile)
}

func (store projectStore) setupCaptureCommandsPath() string {
	return filepath.Join(store.agentStateDir(), setupCaptureCommandsFile)
}

func (store projectStore) setupCaptureLegacyCommandsPath() string {
	return filepath.Join(store.agentStateDir(), setupCaptureLegacyCommandsFile)
}

func (store projectStore) readSetupCaptureMetadata() (setupCaptureMetadata, bool, error) {
	data, err := os.ReadFile(store.setupCaptureMetadataPath())
	if err != nil {
		if os.IsNotExist(err) {
			return setupCaptureMetadata{}, false, nil
		}
		return setupCaptureMetadata{}, false, fmt.Errorf("read setup capture metadata: %w", err)
	}
	var meta setupCaptureMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return setupCaptureMetadata{}, false, fmt.Errorf("parse setup capture metadata: %w", err)
	}
	if len(meta.ObservedFirewall) > 0 {
		normalized := make([]string, 0, len(meta.ObservedFirewall))
		seen := make(map[string]struct{}, len(meta.ObservedFirewall))
		for _, entry := range meta.ObservedFirewall {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			if _, ok := seen[entry]; ok {
				continue
			}
			seen[entry] = struct{}{}
			normalized = append(normalized, entry)
		}
		sort.Strings(normalized)
		meta.ObservedFirewall = normalized
	}
	return meta, true, nil
}

func (store projectStore) writeSetupCaptureMetadata(meta setupCaptureMetadata) error {
	if err := os.MkdirAll(store.Path, 0755); err != nil {
		return fmt.Errorf("create store dir: %w", err)
	}
	if meta.StartedAt == "" {
		meta.StartedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if len(meta.ObservedFirewall) > 0 {
		normalized := make([]string, 0, len(meta.ObservedFirewall))
		seen := make(map[string]struct{}, len(meta.ObservedFirewall))
		for _, entry := range meta.ObservedFirewall {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			if _, ok := seen[entry]; ok {
				continue
			}
			seen[entry] = struct{}{}
			normalized = append(normalized, entry)
		}
		sort.Strings(normalized)
		meta.ObservedFirewall = normalized
	}
	body, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("serialize setup capture metadata: %w", err)
	}
	if err := writeFileAtomically(store.setupCaptureMetadataPath(), append(body, '\n'), 0644); err != nil {
		return fmt.Errorf("write setup capture metadata: %w", err)
	}
	return nil
}

func (store projectStore) clearSetupCaptureMetadata() error {
	return removeSetupCaptureFile(store.setupCaptureMetadataPath(), "setup capture metadata")
}

func (store projectStore) clearSetupCaptureObservedEndpoints() error {
	return removeSetupCaptureFile(store.setupCaptureObservedEndpointsPath(), "setup capture observed endpoints")
}

func (store projectStore) clearSetupCaptureCommands() error {
	if err := removeSetupCaptureFile(store.setupCaptureCommandsPath(), "setup capture commands"); err != nil {
		return err
	}
	return removeSetupCaptureFile(store.setupCaptureLegacyCommandsPath(), "legacy setup capture commands")
}

func removeSetupCaptureFile(path string, label string) error {
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("remove %s: %w", label, err)
	}
	return syncDirectory(filepath.Dir(path))
}
