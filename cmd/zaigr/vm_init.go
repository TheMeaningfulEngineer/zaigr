package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func cmdInit(ram string, cpu string) error {
	cpuValue, cpuSource, err := resolveCPU(cpu)
	if err != nil {
		return err
	}
	ram, ramSource := resolveRAM(ram)
	disk, diskSource := resolveDisk("")
	return cmdInitWithValues(ram, ramSource, cpuValue, cpuSource, disk, diskSource)
}

func cmdInitWithValues(ram string, ramSource string, cpu string, cpuSource string, disk string, diskSource string) error {
	store := currentProjectStore()
	storePath := store.Path
	initialized, err := isProjectInitialized(storePath)
	if err != nil {
		return err
	}
	if initialized {
		return fmt.Errorf("project already initialized at %s", storePath)
	}

	if err := os.MkdirAll(storePath, 0755); err != nil {
		return fmt.Errorf("create project store: %w", err)
	}

	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(storePath)
		}
	}()

	if err := os.WriteFile(store.configPath(), []byte(fmt.Sprintf("disk=%s\n", disk)), 0644); err != nil {
		return fmt.Errorf("store default disk: %w", err)
	}
	if err := store.writeProjectPath(canonicalPath(".")); err != nil {
		return err
	}
	if err := os.WriteFile(store.ramPath(), []byte(fmt.Sprintf("%s\n", ram)), 0644); err != nil {
		return fmt.Errorf("store default ram: %w", err)
	}
	if err := os.WriteFile(store.cpusPath(), []byte(fmt.Sprintf("%s\n", cpu)), 0644); err != nil {
		return fmt.Errorf("store default cpus: %w", err)
	}

	imagePath := store.authoritativeImagePath()

	wipPath := imagePath + ".wip"
	_ = os.Remove(wipPath)

	fmt.Printf(":: Initializing project at %s\n", storePath)
	fmt.Printf(":: Defaults: ram=%sMB [%s], cpu=%s [%s], disk=%s [%s]\n",
		ram, ramSource, cpu, cpuSource, disk, diskSource)
	fmt.Printf(":: Creating project overlay %s from shared base ...\n", filepath.Base(imagePath))

	selection, err := createProjectOverlayFromCurrent(wipPath, disk, ram, cpu)
	if err != nil {
		_ = os.Remove(wipPath)
		return fmt.Errorf("create project overlay: %w", err)
	}

	if err := os.Rename(wipPath, imagePath); err != nil {
		return fmt.Errorf("rename initial image: %w", err)
	}
	if err := syncDirectory(storePath); err != nil {
		return fmt.Errorf("sync initial project image: %w", err)
	}

	if err := store.writeBaseImageVersion(baseRootfsVersion()); err != nil {
		return err
	}
	if err := store.writeBackingPin(selection.Pin); err != nil {
		return err
	}
	if err := store.writeAppliedSetups(selection.Applied); err != nil {
		return err
	}
	if err := store.writeFirewallEntries(selection.Firewall); err != nil {
		return err
	}
	if err := store.writeCurrentImageFormat(); err != nil {
		return err
	}

	cleanup = false
	fmt.Printf(":: Project initialized with image %s\n", filepath.Base(imagePath))
	return nil
}

func isProjectInitialized(storePath string) (bool, error) {
	entries, err := os.ReadDir(storePath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("read project store: %w", err)
	}
	return len(entries) > 0, nil
}
