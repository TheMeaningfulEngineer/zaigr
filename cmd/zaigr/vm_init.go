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
	return cmdInitWithValues(ram, ramSource, cpuValue, cpuSource, defaultDiskSize, "default")
}

func cmdInitWithValues(ram string, ramSource string, cpu string, cpuSource string, disk string, diskSource string) error {
	storePath := storeDir()
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

	if err := os.WriteFile(storeConfigPath(), []byte(fmt.Sprintf("disk=%s\n", disk)), 0644); err != nil {
		return fmt.Errorf("store default disk: %w", err)
	}
	if err := storeWriteCurrentProjectPath(); err != nil {
		return err
	}
	if err := os.WriteFile(storeRAMPath(), []byte(fmt.Sprintf("%s\n", ram)), 0644); err != nil {
		return fmt.Errorf("store default ram: %w", err)
	}
	if err := os.WriteFile(storeCPUsPath(), []byte(fmt.Sprintf("%s\n", cpu)), 0644); err != nil {
		return fmt.Errorf("store default cpus: %w", err)
	}

	imagePath, err := storeImagePathForSteps(nil)
	if err != nil {
		return err
	}

	wipPath := imagePath + ".wip"
	_ = os.Remove(wipPath)

	fmt.Printf(":: Initializing project at %s\n", storePath)
	fmt.Printf(":: Defaults: ram=%sMB [%s], cpu=%s [%s], disk=%s [%s]\n",
		ram, ramSource, cpu, cpuSource, disk, diskSource)
	fmt.Printf(":: Creating first project image %s from base ...\n", filepath.Base(imagePath))

	if err := buildImageFromBase(wipPath, disk); err != nil {
		_ = os.Remove(wipPath)
		return fmt.Errorf("build base image: %w", err)
	}

	if err := os.Rename(wipPath, imagePath); err != nil {
		return fmt.Errorf("rename initial image: %w", err)
	}

	if err := currentProjectStore().writeBaseImageVersion(baseRootfsVersion()); err != nil {
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
