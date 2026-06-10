package main

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const sshConnectTimeoutOption = "ConnectTimeout=5"

func sshManagedOptions() []string {
	return []string{
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "LogLevel=ERROR",
	}
}

func cmdVMApply(scriptPath string) error {
	fmt.Printf(":: zaigr %s (%s/%s) built %s\n", version, runtime.GOOS, runtime.GOARCH, buildTime)

	abs, err := filepath.Abs(scriptPath)
	if err != nil {
		return fmt.Errorf("resolve script path: %w", err)
	}
	info, _ := os.Stat(abs)
	if err != nil || info == nil {
		return fmt.Errorf("script not found: %s", abs)
	}
	if info.IsDir() {
		return fmt.Errorf("script is a directory: %s", abs)
	}
	content, err := os.ReadFile(abs)
	if err != nil {
		return fmt.Errorf("read script: %w", err)
	}
	baseName := filepath.Base(abs)
	baseName = strings.TrimSuffix(baseName, filepath.Ext(baseName))

	running, stale := detectRunningProjectVM()
	if stale {
		_ = storeClearRuntimeState()
	}
	if running != nil {
		return cmdApplyScriptToRunningVM(content, baseName, running.Port, false)
	}
	return cmdApplyScriptToImage(content, baseName, "", "", false)
}

func cmdApplyScriptToRunningVM(content []byte, baseName string, port string, rootFullNetwork bool) error {
	logInfo("applying script to running VM", "name", baseName, "port", port)

	awaitingCommitPath, err := storeSaveScript(setupStateAwaitingCommit, content, baseName)
	if err != nil {
		return fmt.Errorf("record setup awaiting image commit: %w", err)
	}
	awaitingCommitName := filepath.Base(awaitingCommitPath)
	fmt.Printf(":: Recorded setup awaiting image commit: %s\n", awaitingCommitName)

	rootKeyPath, _, err := ensureRootSSHKey()
	if err != nil {
		storeRemove(awaitingCommitPath)
		return fmt.Errorf("prepare root SSH key: %w", err)
	}

	command := fmt.Sprintf("set -e\n%s", string(content))
	runScript := func() error {
		return sshRunScript(port, rootKeyPath, command)
	}
	if rootFullNetwork {
		err = withTemporaryRootAllowAllFirewallRule(port, rootKeyPath, runScript)
	} else {
		err = runScript()
	}
	if err != nil {
		storeRemove(awaitingCommitPath)
		failedPath, saveErr := storeSaveScript(setupStateFailed, content, baseName)
		if saveErr != nil {
			return fmt.Errorf("setup failed: %w (save failed setup: %v)", err, saveErr)
		}
		fmt.Printf(":: Setup failed during VM execution and moved to failed setups: %s\n", filepath.Base(failedPath))
		fmt.Fprintf(os.Stderr, "   Resolve with:\n")
		fmt.Fprintf(os.Stderr, "     Resolve failed setup state by re-running setup commands via `zaigr project setup run`.\n")
		fmt.Fprintf(os.Stderr, "     If this persists, clean project metadata and rerun setup.\n")
		return fmt.Errorf("setup failed: %w", err)
	}

	if err := sshSync(port, rootKeyPath); err != nil {
		storeRemove(awaitingCommitPath)
		failedPath, saveErr := storeSaveScript(setupStateFailed, content, baseName)
		if saveErr != nil {
			return fmt.Errorf("setup sync failed: %w (save failed setup: %v)", err, saveErr)
		}
		fmt.Printf(":: Setup failed while syncing VM changes and moved to failed setups: %s\n", filepath.Base(failedPath))
		return fmt.Errorf("setup sync failed: %w", err)
	}

	fmt.Printf(":: Setup executed in the running VM and is awaiting image commit: %s\n", awaitingCommitName)
	return nil
}

func cmdApplyScriptToImage(content []byte, baseName string, ram string, cpus string, rootFullNetwork bool) error {
	return cmdApplyScriptToImageWithCommittedReplacement(content, baseName, ram, cpus, rootFullNetwork, false)
}

func cmdApplyScriptToImageReplacingCommitted(content []byte, baseName string, ram string, cpus string, rootFullNetwork bool) error {
	return cmdApplyScriptToImageWithCommittedReplacement(content, baseName, ram, cpus, rootFullNetwork, true)
}

func cmdApplyScriptToImageWithCommittedReplacement(content []byte, baseName string, ram string, cpus string, rootFullNetwork bool, replaceCommitted bool) error {
	logInfo("applying script to project image", "name", baseName)
	steps, err := storeCommittedSetups()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(storeCommittedSetupsDir(), 0755); err != nil {
		return fmt.Errorf("create committed setups dir: %w", err)
	}

	if replaceCommitted {
		replaced, err := replaceCommittedScriptInImage(content, baseName, steps, ram, cpus, rootFullNetwork)
		if err != nil {
			return err
		}
		if replaced {
			return nil
		}
	}

	stepPath := filepath.Join(storeCommittedSetupsDir(), fmt.Sprintf("%03d-%s.sh", len(steps)+1, baseName))
	if err := os.WriteFile(stepPath, content, 0755); err != nil {
		return fmt.Errorf("write candidate step: %w", err)
	}

	candidate := append(append([]string{}, steps...), stepPath)
	_, err = applyStepsToImage(candidate, ram, cpus, "", rootFullNetwork)
	if err != nil {
		storeRemove(stepPath)
		return err
	}

	fmt.Printf(":: Setup committed to project image: %s\n", filepath.Base(stepPath))
	return nil
}

func replaceCommittedScriptInImage(content []byte, baseName string, steps []string, ram string, cpus string, rootFullNetwork bool) (bool, error) {
	matchingIndex := -1
	for index, step := range steps {
		if storeScriptBaseNameFromPath(step) != baseName {
			continue
		}
		if matchingIndex != -1 {
			return false, fmt.Errorf(
				"cannot force rerun setup %q with multiple committed records (%s, %s); run `zaigr project status`",
				baseName,
				filepath.Base(steps[matchingIndex]),
				filepath.Base(step),
			)
		}
		matchingIndex = index
	}
	if matchingIndex == -1 {
		return false, nil
	}

	existingPath := steps[matchingIndex]
	stagingDir, err := os.MkdirTemp(storeDir(), "force-setup-")
	if err != nil {
		return false, fmt.Errorf("create force setup staging dir: %w", err)
	}
	defer os.RemoveAll(stagingDir)

	stagedPath := filepath.Join(stagingDir, filepath.Base(existingPath))
	if err := os.WriteFile(stagedPath, content, 0755); err != nil {
		return true, fmt.Errorf("stage force setup %s: %w", filepath.Base(existingPath), err)
	}
	if err := stampScriptVersionTime(stagedPath, content); err != nil {
		return true, err
	}

	candidate := append([]string{}, steps...)
	candidate[matchingIndex] = stagedPath
	options := applyStepsToImageOptions{
		forceRebuild:            true,
		limitIncrementalBase:    true,
		maxIncrementalBaseSteps: matchingIndex,
	}
	if _, err := applyStepsToImageWithOptions(candidate, ram, cpus, "", rootFullNetwork, options); err != nil {
		return true, err
	}

	info, err := os.Stat(existingPath)
	if err != nil {
		return true, err
	}
	backupContent, err := os.ReadFile(existingPath)
	if err != nil {
		return true, err
	}
	backupMode := info.Mode().Perm()
	backupModTime := info.ModTime()
	restoreCommittedScript := func() {
		if err := os.WriteFile(existingPath, backupContent, backupMode); err != nil {
			fmt.Fprintf(os.Stderr, ":: Could not restore committed setup %s: %v\n", filepath.Base(existingPath), err)
			return
		}
		_ = os.Chmod(existingPath, backupMode)
		_ = os.Chtimes(existingPath, backupModTime, backupModTime)
	}

	if err := os.WriteFile(existingPath, content, backupMode); err != nil {
		return true, fmt.Errorf("update committed setup %s: %w", filepath.Base(existingPath), err)
	}
	if err := stampScriptVersionTime(existingPath, content); err != nil {
		restoreCommittedScript()
		return true, err
	}

	fmt.Printf(":: Setup committed to project image: %s\n", filepath.Base(existingPath))
	return true, nil
}

func cmdModShow(showAll, showCommitted, showAwaitingCommit, showFailed bool) error {
	committed, err := storeCommittedSetups()
	if err != nil {
		return err
	}
	awaitingCommit, err := storeAwaitingCommitSetups()
	if err != nil {
		return err
	}
	failed, err := storeFailedSetups()
	if err != nil {
		return err
	}

	if len(committed) == 0 && len(awaitingCommit) == 0 && len(failed) == 0 {
		return fmt.Errorf("no setup state — run 'zaigr project setup run <setup>' first")
	}

	printModState := func(state string, paths []string) {
		if len(paths) == 0 {
			fmt.Printf("=== %s (0) ===\n", strings.ToUpper(state))
			return
		}
		fmt.Printf("=== %s (%d) ===\n", strings.ToUpper(state), len(paths))
		for i, step := range paths {
			if i > 0 {
				fmt.Println()
			}
			fmt.Printf("# --- %s ---\n\n", filepath.Base(step))
			if data, err := os.ReadFile(step); err == nil {
				fmt.Print(string(data))
			} else {
				fmt.Fprintf(os.Stderr, "   [read %s failed: %v]\n", filepath.Base(step), err)
			}
		}
	}

	if showAll {
		printModState("committed", committed)
		printModState("awaiting-commit", awaitingCommit)
		printModState("failed", failed)
		return nil
	}

	if showCommitted {
		printModState("committed", committed)
	}
	if showAwaitingCommit {
		printModState("awaiting-commit", awaitingCommit)
	}
	if showFailed {
		printModState("failed", failed)
	}
	return nil
}

func cmdModCommitAwaitingSetups() error {
	awaitingCommit, err := storeAwaitingCommitSetups()
	if err != nil {
		return err
	}
	if len(awaitingCommit) == 0 {
		return fmt.Errorf("no setups awaiting image commit — run 'zaigr project setup run <setup>' while a VM is running")
	}

	committed, err := storeCommittedSetups()
	if err != nil {
		return err
	}

	commitPlan, err := planAwaitingSetupCommit(committed, awaitingCommit)
	if err != nil {
		return err
	}

	promotion := cleanAwaitingSetupPromotion{}
	promoted := false
	if len(commitPlan.replacements) == 0 {
		promotion, promoted, err = promoteCleanAwaitingSetupsWithoutReplay(committed, commitPlan.steps)
		if err != nil {
			return err
		}
	}
	if !promoted {
		options := applyStepsToImageOptions{}
		if len(commitPlan.replacements) > 0 {
			options.forceRebuild = true
			options.limitIncrementalBase = true
			options.maxIncrementalBaseSteps = commitPlan.earliestReplacementIndex()
		}
		_, err = applyStepsToImageWithOptions(commitPlan.steps, "", "", "", true, options)
		if err != nil {
			return err
		}
	}

	moved, err := commitAwaitingSetupScripts(commitPlan)
	if err != nil {
		rollbackCleanAwaitingSetupPromotion(promotion)
		return err
	}
	if err := finishCleanAwaitingSetupPromotion(promotion); err != nil {
		return err
	}
	if promoted {
		fmt.Printf(":: Promoted current project image without reinstalling setups: %s\n", filepath.Base(promotion.newPath))
	}
	fmt.Printf(":: Committed %d setups to the project image\n", len(moved))
	for _, step := range moved {
		fmt.Printf(":: Committed: %s\n", filepath.Base(step))
	}

	return nil
}

type awaitingSetupReplacement struct {
	awaitingPath   string
	committedPath  string
	committedIndex int
}

type awaitingSetupCommitPlan struct {
	steps        []string
	replacements []awaitingSetupReplacement
	appends      []string
}

func planAwaitingSetupCommit(committed []string, awaitingCommit []string) (awaitingSetupCommitPlan, error) {
	plan := awaitingSetupCommitPlan{
		steps: append([]string{}, committed...),
	}
	seenAwaitingNames := make(map[string]string, len(awaitingCommit))

	for _, awaitingPath := range awaitingCommit {
		name := storeScriptBaseNameFromPath(awaitingPath)
		if firstPath, ok := seenAwaitingNames[name]; ok {
			return awaitingSetupCommitPlan{}, fmt.Errorf(
				"cannot commit multiple setups awaiting image commit with the same name %q (%s, %s); discard or retry one setup",
				name,
				filepath.Base(firstPath),
				filepath.Base(awaitingPath),
			)
		}
		seenAwaitingNames[name] = awaitingPath

		matchingIndex := -1
		for index, committedPath := range committed {
			if storeScriptBaseNameFromPath(committedPath) != name {
				continue
			}
			if matchingIndex != -1 {
				return awaitingSetupCommitPlan{}, fmt.Errorf(
					"cannot commit setup %q with multiple committed records (%s, %s); run `zaigr project status`",
					name,
					filepath.Base(committed[matchingIndex]),
					filepath.Base(committedPath),
				)
			}
			matchingIndex = index
		}

		if matchingIndex == -1 {
			plan.steps = append(plan.steps, awaitingPath)
			plan.appends = append(plan.appends, awaitingPath)
			continue
		}

		plan.steps[matchingIndex] = awaitingPath
		plan.replacements = append(plan.replacements, awaitingSetupReplacement{
			awaitingPath:   awaitingPath,
			committedPath:  committed[matchingIndex],
			committedIndex: matchingIndex,
		})
	}

	return plan, nil
}

func (plan awaitingSetupCommitPlan) earliestReplacementIndex() int {
	earliest := len(plan.steps)
	for _, replacement := range plan.replacements {
		if replacement.committedIndex < earliest {
			earliest = replacement.committedIndex
		}
	}
	return earliest
}

func commitAwaitingSetupScripts(plan awaitingSetupCommitPlan) ([]string, error) {
	moved := make([]string, 0, len(plan.replacements)+len(plan.appends))
	for _, replacement := range plan.replacements {
		if err := replaceCommittedSetupScriptFromAwaiting(replacement.awaitingPath, replacement.committedPath); err != nil {
			return moved, err
		}
		moved = append(moved, replacement.committedPath)
	}
	if len(plan.appends) == 0 {
		return moved, nil
	}

	appended, err := storeMoveScripts(setupStateAwaitingCommit, setupStateCommitted, plan.appends)
	if err != nil {
		return moved, err
	}
	moved = append(moved, appended...)
	return moved, nil
}

func replaceCommittedSetupScriptFromAwaiting(awaitingPath string, committedPath string) error {
	content, err := os.ReadFile(awaitingPath)
	if err != nil {
		return err
	}
	info, err := os.Stat(committedPath)
	if err != nil {
		return err
	}
	mode := info.Mode().Perm()
	if err := os.WriteFile(committedPath, content, mode); err != nil {
		return fmt.Errorf("replace committed setup %s: %w", filepath.Base(committedPath), err)
	}
	if err := stampScriptVersionTime(committedPath, content); err != nil {
		return err
	}
	if err := os.Remove(awaitingPath); err != nil {
		return err
	}
	return nil
}

type cleanAwaitingSetupPromotion struct {
	oldPath              string
	newPath              string
	renamed              bool
	removeOldAfterCommit bool
}

func promoteCleanAwaitingSetupsWithoutReplay(committed []string, all []string) (cleanAwaitingSetupPromotion, bool, error) {
	if _, hasDirtyImage, err := currentProjectStore().readProjectImageDirty(); err != nil {
		return cleanAwaitingSetupPromotion{}, false, err
	} else if hasDirtyImage {
		return cleanAwaitingSetupPromotion{}, false, nil
	}

	running, stale := detectRunningProjectVM()
	if stale {
		_ = storeClearRuntimeState()
	}
	if running != nil {
		return cleanAwaitingSetupPromotion{}, false, nil
	}

	oldPath, err := storeImagePathForSteps(committed)
	if err != nil {
		return cleanAwaitingSetupPromotion{}, false, err
	}
	newPath, err := storeImagePathForSteps(all)
	if err != nil {
		return cleanAwaitingSetupPromotion{}, false, err
	}
	promotion := cleanAwaitingSetupPromotion{
		oldPath: oldPath,
		newPath: newPath,
	}
	if oldPath == newPath {
		return promotion, true, nil
	}

	if _, err := os.Stat(oldPath); err != nil {
		if os.IsNotExist(err) {
			return cleanAwaitingSetupPromotion{}, false, nil
		}
		return cleanAwaitingSetupPromotion{}, false, fmt.Errorf("stat current project image: %w", err)
	}

	if _, err := os.Stat(newPath); err == nil {
		promotion.removeOldAfterCommit = true
		return promotion, true, nil
	} else if !os.IsNotExist(err) {
		return cleanAwaitingSetupPromotion{}, false, fmt.Errorf("stat promoted project image: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(newPath), 0755); err != nil {
		return cleanAwaitingSetupPromotion{}, false, fmt.Errorf("create promoted image parent: %w", err)
	}
	if err := os.Rename(oldPath, newPath); err != nil {
		return cleanAwaitingSetupPromotion{}, false, fmt.Errorf("promote current project image without reinstalling setups: %w", err)
	}
	promotion.renamed = true
	return promotion, true, nil
}

func rollbackCleanAwaitingSetupPromotion(promotion cleanAwaitingSetupPromotion) {
	if !promotion.renamed || promotion.oldPath == "" || promotion.newPath == "" {
		return
	}
	if _, err := os.Stat(promotion.oldPath); err == nil {
		return
	}
	_ = os.Rename(promotion.newPath, promotion.oldPath)
}

func finishCleanAwaitingSetupPromotion(promotion cleanAwaitingSetupPromotion) error {
	if !promotion.removeOldAfterCommit || promotion.oldPath == "" || promotion.oldPath == promotion.newPath {
		return nil
	}
	if err := os.Remove(promotion.oldPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove superseded project image: %w", err)
	}
	return nil
}

func cmdModRetryFailed() error {
	failed, err := storeFailedSetups()
	if err != nil {
		return err
	}
	if len(failed) == 0 {
		return fmt.Errorf("no failed setups to retry")
	}

	committed, err := storeCommittedSetups()
	if err != nil {
		return err
	}

	retried := 0
	for _, failedScript := range failed {
		candidate := append(append([]string{}, committed...), failedScript)
		if _, err := applyStepsToImage(candidate, "", "", "", true); err != nil {
			fmt.Fprintf(os.Stderr, ":: Retry failed for %s\n", filepath.Base(failedScript))
			continue
		}

		moved, moveErr := storeMoveScripts(setupStateFailed, setupStateCommitted, []string{failedScript})
		if moveErr != nil {
			return moveErr
		}
		if len(moved) == 0 {
			return fmt.Errorf("retry succeeded but no file was moved for %s", filepath.Base(failedScript))
		}
		committed = append(committed, moved...)
		retried++
		fmt.Printf(":: Retried and committed: %s\n", filepath.Base(moved[0]))
	}

	if retried == 0 {
		return fmt.Errorf("all failed setups are still failing")
	}

	return nil
}

func cmdModRemove(removeAwaitingCommit bool, removeFailed bool) error {
	var removed int
	if removeAwaitingCommit {
		paths, err := storeAwaitingCommitSetups()
		if err != nil {
			return err
		}
		removed += len(paths)
		storeRemoveAll(setupStateAwaitingCommit)
	}
	if removeFailed {
		paths, err := storeFailedSetups()
		if err != nil {
			return err
		}
		removed += len(paths)
		storeRemoveAll(setupStateFailed)
	}
	if removed == 0 {
		return fmt.Errorf("no matching setup state to remove")
	}

	fmt.Printf(":: Removed %d setup state entries\n", removed)
	return nil
}

type applyStepsToImageOptions struct {
	forceRebuild            bool
	limitIncrementalBase    bool
	maxIncrementalBaseSteps int
}

func applyStepsToImage(steps []string, ram string, cpus string, disk string, rootFullNetwork bool) (string, error) {
	return applyStepsToImageWithOptions(steps, ram, cpus, disk, rootFullNetwork, applyStepsToImageOptions{})
}

func applyStepsToImageWithOptions(steps []string, ram string, cpus string, disk string, rootFullNetwork bool, options applyStepsToImageOptions) (string, error) {
	logInfo("building project image from setup steps", "step_count", len(steps))
	if err := os.MkdirAll(storeDir(), 0755); err != nil {
		return "", fmt.Errorf("create store dir: %w", err)
	}

	ram, ramSource := resolveRAM(ram)
	if ramSource == "default" {
		ram = "4096"
	}
	cpus, cpusSource := resolveCPUs(cpus)
	disk, diskSource := resolveDisk(disk)
	fmt.Printf(":: Settings: ram=%sMB [%s], cpus=%s [%s], disk=%s [%s]\n",
		ram, ramSource, cpus, cpusSource, disk, diskSource)

	config := fmt.Sprintf("disk=%s\n", disk)
	if err := os.WriteFile(storeConfigPath(), []byte(config), 0644); err != nil {
		return "", fmt.Errorf("store config: %w", err)
	}

	outputPath, err := storeImagePathForSteps(steps)
	if err != nil {
		return "", err
	}

	if _, err := os.Stat(outputPath); err == nil && !options.forceRebuild {
		logDebug("project image already up to date", "image", outputPath)
		fmt.Printf(":: Image already up to date: %s\n", outputPath)
		return outputPath, nil
	}
	if err := requireKVMAccess(); err != nil {
		return "", err
	}

	var basePath string
	var applyFrom int
	if options.limitIncrementalBase {
		basePath, applyFrom = storeFindIncrementalBaseLimited(steps, options.maxIncrementalBaseSteps)
	} else {
		basePath, applyFrom = storeFindIncrementalBase(steps)
	}
	if basePath != "" {
		logInfo("using incremental image build", "base", basePath, "apply_from", applyFrom, "step_count", len(steps))
		fmt.Printf(":: Incremental build from step %d of %d\n", applyFrom, len(steps))
	} else {
		logInfo("using full image build from base", "step_count", len(steps))
		fmt.Printf(":: Full build — applying %d step(s) from base\n", len(steps))
	}

	wipPath := outputPath + ".wip"
	os.Remove(wipPath)

	if basePath != "" {
		if err := createQcow2Overlay(basePath, wipPath); err != nil {
			return "", fmt.Errorf("create overlay: %w", err)
		}
	} else {
		if err := buildImageFromBase(wipPath, disk); err != nil {
			os.Remove(wipPath)
			return "", fmt.Errorf("build base image: %w", err)
		}
	}

	sshPort, err := allocateEphemeralSSHPort()
	if err != nil {
		os.Remove(wipPath)
		return "", err
	}

	err = applyStepsViaSSH(wipPath, steps[applyFrom:], ram, cpus, sshPort, rootFullNetwork)
	if err != nil {
		os.Remove(wipPath)
		return "", err
	}

	if err := os.Rename(wipPath, outputPath); err != nil {
		os.Remove(wipPath)
		return "", fmt.Errorf("rename wip to final: %w", err)
	}
	removeGlob(filepath.Join(storeDir(), "image-*.qcow2.wip"))
	removeGlob(filepath.Join(storeDir(), "image-*.img"))

	diskUsage := "unknown"
	if out, err := exec.Command("du", "-h", outputPath).Output(); err == nil {
		parts := strings.Fields(string(out))
		if len(parts) > 0 {
			diskUsage = parts[0]
		}
	}

	os.WriteFile(storeRAMPath(), []byte(ram), 0644)
	os.WriteFile(storeCPUsPath(), []byte(cpus), 0644)
	if err := currentProjectStore().writeBaseImageVersion(baseRootfsVersion()); err != nil {
		return "", err
	}

	fmt.Printf(":: Image ready: %s (%s on disk)\n", outputPath, diskUsage)
	logInfo("project image build finished", "image", outputPath, "disk_usage", diskUsage)
	return outputPath, nil
}

func allocateEphemeralSSHPort() (string, error) {
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		return "", fmt.Errorf("allocate SSH port: %w", err)
	}
	port := fmt.Sprintf("%d", ln.Addr().(*net.TCPAddr).Port)
	_ = ln.Close()
	return port, nil
}

func applyStepsViaSSH(imagePath string, steps []string, ram string, cpus string, sshPort string, rootFullNetwork bool) error {
	logInfo("booting temporary VM to apply image steps", "image", imagePath, "step_count", len(steps), "port", sshPort)
	kernelPath, err := ensureKernel(false)
	if err != nil {
		return err
	}

	if ln, err := net.Listen("tcp", ":"+sshPort); err != nil {
		return fmt.Errorf("SSH port %s already in use — another VM is likely running", sshPort)
	} else {
		ln.Close()
	}

	_, rootPubKey, err := ensureRootSSHKey()
	if err != nil {
		return fmt.Errorf("ensure root SSH key: %w", err)
	}

	rootKeyPath := filepath.Join(zaigDir(), "root-ssh.key")

	if err := os.MkdirAll(storeDir(), 0755); err != nil {
		return fmt.Errorf("create store dir for image modification: %w", err)
	}
	if err := currentProjectStore().ensureAgentStateDir(); err != nil {
		return err
	}
	monitorSock := filepath.Join(storeDir(), "modify-vm.sock")
	_ = os.Remove(monitorSock)
	args := buildQEMUArgs(imagePath, kernelPath, "qcow2", false, ram, cpus, sshPort, rootPubKey, storeProjectHostname(), monitorSock)

	fmt.Println(":: Booting image for modification ...")
	logDebug("starting qemu for image modification", "kernel", kernelPath, "image", imagePath, "monitor_sock", monitorSock)
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = nil
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start QEMU: %w", err)
	}
	defer func() {
		_ = sshSync(sshPort, rootKeyPath)
		qmpQuit(monitorSock)
		_ = cmd.Wait()
		_ = os.Remove(monitorSock)
	}()

	fmt.Println(":: Waiting for SSH ...")
	logDebug("waiting for image-modification VM SSH readiness", "port", sshPort, "timeout_sec", 60)
	if !waitForSSH(sshPort, 60) {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = os.Remove(monitorSock)
		return fmt.Errorf("VM did not become reachable via SSH within 60s")
	}

	runSetupScripts := func() error {
		for i, step := range steps {
			stepName := filepath.Base(step)
			logInfo("applying image step", "index", i+1, "total", len(steps), "step", stepName)
			fmt.Printf(":: Applying step %d/%d: %s\n", i+1, len(steps), stepName)
			data, err := os.ReadFile(step)
			if err != nil {
				return fmt.Errorf("read step %s: %w", stepName, err)
			}
			if err := sshRunScript(sshPort, rootKeyPath, string(data)); err != nil {
				return fmt.Errorf("step %s failed: %w", stepName, err)
			}
		}

		fmt.Println(":: All scripts finished")
		return nil
	}

	if rootFullNetwork {
		fmt.Println(":: Setup execution has full network access")
		if err := withTemporaryRootAllowAllFirewallRule(sshPort, rootKeyPath, runSetupScripts); err != nil {
			return err
		}
		return nil
	}

	if err := runSetupScripts(); err != nil {
		return err
	}

	return nil
}

func waitForSSH(port string, timeoutSec int) bool {
	rootKeyPath := filepath.Join(zaigDir(), "root-ssh.key")
	logDebug("beginning SSH wait loop", "port", port, "timeout_sec", timeoutSec)
	for i := 0; i < timeoutSec; i++ {
		time.Sleep(time.Second)
		args := append(
			sshManagedOptions(),
			"-o", sshConnectTimeoutOption,
			"-i", rootKeyPath,
			"-p", port,
			"root@localhost", "true",
		)
		cmd := exec.Command("ssh", args...)
		if cmd.Run() == nil {
			logDebug("SSH wait loop succeeded", "port", port, "attempt", i+1)
			return true
		}
	}
	logWarn("SSH wait loop timed out", "port", port, "timeout_sec", timeoutSec)
	return false
}

func sshRunScript(port string, keyPath string, script string) error {
	cmd := sshRunScriptCommand(port, keyPath, "root", script)
	return cmd.Run()
}

func sshSync(port string, keyPath string) error {
	args := append(
		sshManagedOptions(),
		"-o", sshConnectTimeoutOption,
		"-i", keyPath,
		"-p", port,
		"root@localhost", "sync",
	)
	cmd := exec.Command("ssh", args...)
	return cmd.Run()
}

func sshRunScriptCommand(port string, keyPath string, user string, script string) *exec.Cmd {
	args := append(sshManagedOptions(), "-o", sshConnectTimeoutOption)
	if keyPath != "" {
		args = append(args, "-i", keyPath)
	}
	args = append(args, "-p", port, user+"@localhost", "bash", "-eu")

	cmd := exec.Command("ssh", args...)
	cmd.Stdin = strings.NewReader(script)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd
}

func sshRunCommand(port string, keyPath string, user string, command string) error {
	cmd := sshRunCommandCommand(port, keyPath, user, command)
	return cmd.Run()
}

func sshRunCommandWithExitStatus(port string, keyPath string, user string, command string) error {
	cmd := sshRunCommandCommand(port, keyPath, user, command)
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if code := exitErr.ExitCode(); code >= 0 {
				return exitError(code)
			}
		}
		return err
	}
	return nil
}

func sshRunCommandCommand(port string, keyPath string, user string, command string) *exec.Cmd {
	args := append(sshManagedOptions(), "-o", sshConnectTimeoutOption)
	if keyPath != "" {
		args = append(args, "-i", keyPath)
	}
	args = append(args, "-p", port, user+"@localhost", "bash -eu -c "+singleQuotedArg(command))

	cmd := exec.Command("ssh", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd
}

func sshReadCommand(port string, keyPath string, user string, command string) ([]byte, error) {
	args := append(sshManagedOptions(), "-o", sshConnectTimeoutOption)
	if keyPath != "" {
		args = append(args, "-i", keyPath)
	}
	ssArgs := append(args, "-p", port, user+"@localhost", "bash -eu -c "+singleQuotedArg(command))
	cmd := exec.Command("ssh", ssArgs...)
	return cmd.Output()
}

func sshRunPresetCommand(port string, keyPath string, user string, script string) error {
	args := []string{
		"-tt",
	}
	args = append(args, sshManagedOptions()...)
	args = append(args, "-o", sshConnectTimeoutOption)
	if keyPath != "" {
		args = append(args, "-i", keyPath)
	}
	args = append(args, "-p", port, user+"@localhost", "bash -eu -c "+singleQuotedArg(presetShellCommand(script)))

	cmd := exec.Command("ssh", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func presetShellCommand(script string) string {
	marker := presetShellMarker(script, "ZAIGR_PRESET")
	tmpScript := "/tmp/" + marker + ".sh"
	encoded := base64.StdEncoding.EncodeToString([]byte(script))
	return "" +
		"workspace=\"\"\n" +
		"for candidate in /home/user/workspace /workspace; do\n" +
		"  if [ -d \"$candidate\" ]; then\n" +
		"    workspace=\"$candidate\"\n" +
		"    break\n" +
		"  fi\n" +
		"done\n" +
		"if [ -z \"$workspace\" ]; then\n" +
		"  workspace=\"$(pwd)\"\n" +
		"fi\n" +
		"cd \"$workspace\"\n" +
		"export WORKSPACE=\"$workspace\"\n" +
		"tmp_script=\"" + tmpScript + "\"\n" +
		"printf '%s' '" + encoded + "' | base64 -d > \"$tmp_script\"\n" +
		"bash \"$tmp_script\"\n" +
		"status=$?\n" +
		"rm -f \"$tmp_script\"\n" +
		"exit \"$status\""
}

func singleQuotedArg(text string) string {
	return "'" + strings.ReplaceAll(text, "'", "'\"'\"'") + "'"
}

func presetShellMarker(script string, base string) string {
	for n := 0; ; n++ {
		marker := "__" + base + "_" + fmt.Sprintf("%d", n) + "__"
		if !strings.Contains(script, marker) {
			return marker
		}
	}
}

func qmpQuit(sockPath string) {
	conn, err := net.DialTimeout("unix", sockPath, 2*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	buf := make([]byte, 4096)
	conn.Read(buf)
	conn.Write([]byte(`{"execute":"qmp_capabilities"}` + "\n"))
	conn.Read(buf)
	conn.Write([]byte(`{"execute":"quit"}` + "\n"))
	conn.Read(buf)
}
