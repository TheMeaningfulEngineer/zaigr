package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const projectLocalSetupSkeletonScript = "#!/bin/bash\nset -eu\n"

func cmdProjectSetupLocalSkeleton() error {
	root := filepath.Join(".zaigr", "setups", "local")
	if _, err := os.Lstat(root); err == nil {
		return fmt.Errorf("project-local setup already exists: %s", root)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect project-local setup path: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(root), 0755); err != nil {
		return fmt.Errorf("create project-local setups directory: %w", err)
	}
	if err := os.Mkdir(root, 0755); err != nil {
		return fmt.Errorf("create project-local setup directory: %w", err)
	}

	created := false
	defer func() {
		if !created {
			_ = os.RemoveAll(root)
		}
	}()
	if err := os.WriteFile(filepath.Join(root, "setup.script"), []byte(projectLocalSetupSkeletonScript), 0644); err != nil {
		return fmt.Errorf("create project-local setup script: %w", err)
	}
	if err := os.WriteFile(filepath.Join(root, "setup.firewall"), nil, 0644); err != nil {
		return fmt.Errorf("create project-local setup firewall: %w", err)
	}
	created = true

	fmt.Printf(":: Created project-local setup skeleton: %s\n", root)
	return nil
}

func loadProjectLocalSetupDefinitions() ([]setupDefinition, error) {
	root := filepath.Join(".zaigr", "setups")
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read project-local setups: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	definitions := make([]setupDefinition, 0, len(names))
	for _, name := range names {
		if !isValidResourceName(name) {
			return nil, fmt.Errorf("invalid setup name: %s", displaySetupName(name, true))
		}
		definition, err := loadSetupDefinitionAt(name, filepath.Join(root, name), true)
		if err != nil {
			return nil, err
		}
		definitions = append(definitions, definition)
	}
	return definitions, nil
}

func offerProjectLocalSetupsBeforeBoot(ram, cpu string) error {
	definitions, err := loadProjectLocalSetupDefinitions()
	if err != nil {
		return err
	}
	records, err := currentProjectStore().readAppliedSetups()
	if err != nil {
		return err
	}
	localByName := make(map[string]setupDefinition, len(definitions))
	for _, definition := range definitions {
		localByName[definition.Name] = definition
	}

	recordsChanged := false
	for i := 0; i < len(records); {
		record := records[i]
		if !record.ProjectLocal {
			i++
			continue
		}
		if _, present := localByName[record.Name]; present {
			if record.MissingAcknowledged {
				records[i].MissingAcknowledged = false
				recordsChanged = true
			}
			i++
			continue
		}
		if record.MissingAcknowledged {
			i++
			continue
		}
		action := promptMissingProjectLocalSetup(record.Name)
		switch action {
		case "c", "continue":
			records[i].MissingAcknowledged = true
			recordsChanged = true
			if err := currentProjectStore().writeAppliedSetups(records); err != nil {
				return err
			}
			i++
		case "r", "rebuild":
			records = removeAppliedSetupIdentity(records, record)
			if err := rebuildProjectFromRecords(false, records); err != nil {
				return err
			}
			records, err = currentProjectStore().readAppliedSetups()
			if err != nil {
				return err
			}
			recordsChanged = false
			i = 0
		case "a", "abort":
			return exitError(1)
		default:
			return exitError(1)
		}
	}
	if recordsChanged {
		if err := currentProjectStore().writeAppliedSetups(records); err != nil {
			return err
		}
	}

	applied := make(map[string]appliedSetup, len(records))
	for _, record := range records {
		if !record.ProjectLocal {
			continue
		}
		applied[record.Name] = record
	}
	toInstall := make([]setupDefinition, 0)
	for _, definition := range definitions {
		record, installed := applied[definition.Name]
		if installed && record.Version == definition.Version && record.ProjectLocal {
			continue
		}
		if !promptInstallProjectLocalSetup(definition, record, installed) {
			continue
		}
		toInstall = append(toInstall, definition)
	}
	if len(toInstall) == 0 {
		return nil
	}
	if err := resolveProjectImageForCommand(); err != nil {
		return err
	}
	return applySetupDefinitionsToImage(toInstall, ram, cpu)
}

func promptInstallProjectLocalSetup(def setupDefinition, installed appliedSetup, hasInstalled bool) bool {
	name := displaySetupName(def.Name, true)
	if !hasInstalled {
		fmt.Fprintf(os.Stderr, ":: %s is available.\n", name)
		fmt.Fprintf(os.Stderr, "Install %s? [y/N] ", name)
	} else {
		fmt.Fprintf(os.Stderr, ":: %s has changed.\n", name)
		fmt.Fprintf(os.Stderr, "   installed: %s\n", installed.Version)
		fmt.Fprintf(os.Stderr, "   current:   %s\n", def.Version)
		fmt.Fprint(os.Stderr, "Install the current version? [y/N] ")
	}
	var answer string
	_, _ = fmt.Scanln(&answer)
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes"
}

func promptMissingProjectLocalSetup(name string) string {
	display := displaySetupName(name, true)
	fmt.Fprintf(os.Stderr, ":: %s is installed, but its definition is no longer present.\n", display)
	fmt.Fprintln(os.Stderr, "   Its VM and firewall changes remain installed.")
	fmt.Fprintln(os.Stderr, "   [c] continue  Keep the existing VM and stop warning")
	fmt.Fprintf(os.Stderr, "   [r] rebuild   Rebuild without %s\n", name)
	fmt.Fprintln(os.Stderr, "   [a] abort     Exit without starting the VM")
	fmt.Fprint(os.Stderr, "Action [c/r/a]: ")
	var answer string
	_, _ = fmt.Scanln(&answer)
	return strings.ToLower(strings.TrimSpace(answer))
}
