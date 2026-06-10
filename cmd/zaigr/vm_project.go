package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const maxSetupStateEntriesWithoutPrompt = 50
const setupStatePreviewEntries = 10

func cmdProjectShowVMConfig() error {
	if _, err := requireProject("project vm show-config"); err != nil {
		return err
	}

	ram := storeRAM()
	if ram == "" {
		ram = "unknown"
	}
	cpu := storeCPUs()
	if cpu == "" {
		cpu = "unknown"
	}
	fmt.Printf("cpu=%s\n", cpu)
	fmt.Printf("ram=%sMB\n", ram)
	return nil
}

func cmdProjectStartVM(ram string, cpu string) error {
	fmt.Printf(":: zaigr %s (%s/%s) built %s\n", version, runtime.GOOS, runtime.GOARCH, buildTime)
	logInfo("starting project vm start command", "ram", ram, "cpu", cpu)

	if err := requireNoActiveSetupCapture("zaigr project vm start"); err != nil {
		return err
	}

	running, err := prepareProjectForVMStart(ram, cpu)
	if err != nil {
		return err
	}
	if running != nil {
		logInfo("project VM already running", "port", running.Port)
		fmt.Printf(":: Project VM already running on port %s\n", running.Port)
		return nil
	}

	if _, err := resolveProjectImageForCommand(true, true); err != nil {
		return err
	}

	port, err := startPreparedProjectVM(ram, cpu)
	if err != nil {
		return err
	}
	logInfo("project vm start completed", "port", port)
	fmt.Printf(":: Project VM started on port %s\n", port)
	return nil
}

func cmdProjectSetVMConfig(ram string, cpu string) error {
	if _, err := requireProject("project vm set-config"); err != nil {
		return err
	}
	if ram == "" && cpu == "" {
		return fmt.Errorf("provide --ram and/or --cpu")
	}

	if ram != "" {
		if _, err := strconv.Atoi(ram); err != nil {
			return fmt.Errorf("invalid --ram value: %q", ram)
		}
		if err := os.WriteFile(storeRAMPath(), []byte(fmt.Sprintf("%s\n", ram)), 0644); err != nil {
			return fmt.Errorf("store default ram: %w", err)
		}
	}

	if cpu != "" {
		if _, err := strconv.Atoi(cpu); err != nil {
			return fmt.Errorf("invalid --cpu value: %q", cpu)
		}
		if err := os.WriteFile(storeCPUsPath(), []byte(fmt.Sprintf("%s\n", cpu)), 0644); err != nil {
			return fmt.Errorf("store default cpus: %w", err)
		}
	}

	fmt.Printf(":: Project defaults updated in %s\n", storeDir())
	running, stale := detectRunningProjectVM()
	switch {
	case stale:
		_ = storeClearRuntimeState()
		fmt.Fprintln(os.Stderr, ":: Existing stale VM marker detected; cleaned up")
	case running != nil:
		fmt.Fprintln(os.Stderr, ":: VM is running; defaults apply to future starts only")
	}
	return nil
}

func cmdProjectVMExec(commandArgs []string, root bool) error {
	if _, err := requireProject("project vm exec"); err != nil {
		return err
	}
	if err := requireNoActiveSetupCapture("zaigr project vm exec"); err != nil {
		return err
	}

	running, stale := detectRunningProjectVM()
	if stale {
		_ = storeClearRuntimeState()
		running = nil
	}
	if running == nil {
		return fmt.Errorf("project VM is not running; start it with 'zaigr project vm start' or 'zaigr shell'")
	}

	command := projectVMExecShellCommand(commandArgs)
	if !root {
		return sshRunCommandWithExitStatus(running.Port, "", "user", command)
	}

	if !confirmRootExecMarksDirtyProjectImage() {
		return exitError(1)
	}
	rootKeyPath, _, err := ensureRootSSHKey()
	if err != nil {
		return fmt.Errorf("prepare root SSH key: %w", err)
	}
	return withTemporaryRootAllowAllFirewallRule(running.Port, rootKeyPath, func() error {
		if err := markCurrentProjectImageDirty("root-exec", "zaigr project vm exec --root"); err != nil {
			return err
		}
		return sshRunCommandWithExitStatus(running.Port, rootKeyPath, "root", command)
	})
}

func projectVMExecShellCommand(commandArgs []string) string {
	return "" +
		"workspace=\"\"\n" +
		"for candidate in /home/user/workspace /workspace; do\n" +
		"  if [ -d \"$candidate\" ]; then\n" +
		"    workspace=\"$candidate\"\n" +
		"    break\n" +
		"  fi\n" +
		"done\n" +
		"if [ -n \"$workspace\" ]; then\n" +
		"  cd \"$workspace\"\n" +
		"  export WORKSPACE=\"$workspace\"\n" +
		"fi\n" +
		"exec " + shellJoinArgs(commandArgs)
}

func shellJoinArgs(args []string) string {
	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		quoted = append(quoted, singleQuotedArg(arg))
	}
	return strings.Join(quoted, " ")
}

func cmdProjectSetupList(committedFlag, awaitingCommitFlag, failedFlag bool) error {
	if _, err := requireProject("project setup list"); err != nil {
		return err
	}
	states := selectedProjectSetupStates(committedFlag, awaitingCommitFlag, failedFlag)
	for _, state := range states {
		paths, err := projectSetupStatePaths(state)
		if err != nil {
			return err
		}
		fmt.Printf("%s (%d):\n", projectSetupStateLabel(state), len(paths))
		if len(paths) == 0 {
			fmt.Printf("  (none)\n")
			continue
		}
		printSetupState(projectSetupStateLabel(state), paths)
	}
	return nil
}

func cmdProjectSetupShow(committedFlag, awaitingCommitFlag, failedFlag bool) error {
	if _, err := requireProject("project setup show"); err != nil {
		return err
	}
	states := selectedProjectSetupStates(committedFlag, awaitingCommitFlag, failedFlag)
	for _, state := range states {
		paths, err := projectSetupStatePaths(state)
		if err != nil {
			return err
		}
		fmt.Printf("setup scripts in %s (%d):\n", projectSetupStateLabel(state), len(paths))
		if len(paths) == 0 {
			fmt.Printf("  (none)\n")
			continue
		}
		for _, scriptPath := range paths {
			name := storeScriptBaseNameFromPath(scriptPath)
			fmt.Printf("--- %s: %s ---\n", projectSetupStateLabel(state), name)
			script, err := os.ReadFile(scriptPath)
			if err != nil {
				return fmt.Errorf("read %s setup script %s: %w", projectSetupStateLabel(state), filepath.Base(scriptPath), err)
			}
			fmt.Printf("%s\n", string(script))
		}
	}
	return nil
}

func selectedProjectSetupStates(committed bool, awaitingCommit bool, failed bool) []string {
	if !committed && !awaitingCommit && !failed {
		return []string{setupStateCommitted, setupStateAwaitingCommit, setupStateFailed}
	}
	states := make([]string, 0, 3)
	if committed {
		states = append(states, setupStateCommitted)
	}
	if awaitingCommit {
		states = append(states, setupStateAwaitingCommit)
	}
	if failed {
		states = append(states, setupStateFailed)
	}
	return states
}

func projectSetupStatePaths(state string) ([]string, error) {
	switch state {
	case setupStateCommitted:
		return storeCommittedSetups()
	case setupStateAwaitingCommit:
		return storeAwaitingCommitSetups()
	case setupStateFailed:
		return storeFailedSetups()
	default:
		return nil, fmt.Errorf("unknown setup state: %s", state)
	}
}

func projectSetupStateLabel(state string) string {
	switch state {
	case setupStateCommitted:
		return "committed"
	case setupStateAwaitingCommit:
		return "awaiting-commit"
	case setupStateFailed:
		return "failed"
	default:
		return state
	}
}

func cmdProjectStatus() error {
	logInfo("starting project status command", "store", storeDir())
	storePath, err := requireProject("project status")
	if err != nil {
		return err
	}
	logDebug("resolved project store", "store", storePath)
	projectImageDiagnosis, err := collectProjectImageMismatchesForStore(currentProjectStore())
	if err != nil {
		return err
	}

	logDebug("loading committed setup state", "store", storePath)
	committed, _ := storeCommittedSetups()
	logDebug("validating committed project image", "store", storePath)
	committedImagePath, committedImageMissing, err := validateCommittedProjectImage(committed)
	if err != nil {
		return err
	}
	logDebug("loading setups awaiting image commit", "store", storePath)
	awaitingCommit, _ := storeAwaitingCommitSetups()
	logDebug("loading failed setup state", "store", storePath)
	failed, _ := storeFailedSetups()
	logDebug("loaded project setup state", "committed", len(committed), "awaiting_commit", len(awaitingCommit), "failed", len(failed))

	logDebug("probing running VM metadata", "store", storePath)
	running, stale := detectRunningProjectVMWithMetadata()
	logDebug("reading preset selection", "store", storePath)
	presetSelection, hasPresetSelection, err := storeReadPresetSelection()
	if err != nil {
		return err
	}
	logDebug("loaded project status metadata", "running", running != nil, "stale", stale, "has_preset", hasPresetSelection)
	dirtyImage, hasDirtyImage, err := currentProjectStore().readProjectImageDirty()
	if err != nil {
		return err
	}

	logDebug("resolving project image path", "store", storePath)
	imagePath, imageErr := storeImagePath()
	printProjectStatus(projectStatusRender{
		StorePath:      storePath,
		CPU:            storeCPUs(),
		RAM:            storeRAM(),
		Image:          projectStatusImageFromPaths(committedImagePath, committedImageMissing, imagePath, imageErr),
		ImageMismatch:  projectImageDiagnosis,
		DirtyImage:     dirtyImage,
		HasDirtyImage:  hasDirtyImage,
		Running:        running,
		Stale:          stale,
		Preset:         presetSelection,
		HasPreset:      hasPresetSelection,
		Committed:      committed,
		AwaitingCommit: awaitingCommit,
		Failed:         failed,
	})
	return nil
}

func shouldPrintFullSetupState(label string, count int) bool {
	if count <= maxSetupStateEntriesWithoutPrompt {
		return true
	}
	info, err := os.Stdin.Stat()
	if err != nil || (info.Mode()&os.ModeCharDevice) == 0 {
		fmt.Fprintf(os.Stderr, ":: %s has %d entries; showing first %d only in non-interactive mode\n", label, count, setupStatePreviewEntries)
		return false
	}
	fmt.Fprintf(os.Stderr, ":: %s has %d entries. Print the remaining %d? [y/N] ", label, count, count-setupStatePreviewEntries)
	var answer string
	_, _ = fmt.Scanln(&answer)
	return strings.EqualFold(strings.TrimSpace(answer), "y") || strings.EqualFold(strings.TrimSpace(answer), "yes")
}

func printSetupState(label string, paths []string) {
	if len(paths) == 0 {
		fmt.Printf("  (none)\n")
		return
	}

	type setupStateEntry struct {
		Name    string
		Version string
	}

	entries := make([]setupStateEntry, 0, len(paths))
	maxNameWidth := 0
	for _, step := range paths {
		name := storeScriptBaseNameFromPath(step)
		version := "unknown"
		hash, hashErr := contentVersionFromPath(step)
		if hashErr == nil {
			info, statErr := os.Stat(step)
			if statErr == nil {
				version = resourceDisplayVersion(hash, info.ModTime())
			}
		}
		if len(name) > maxNameWidth {
			maxNameWidth = len(name)
		}
		entries = append(entries, setupStateEntry{
			Name:    name,
			Version: version,
		})
	}

	limit := len(entries)
	if len(entries) > maxSetupStateEntriesWithoutPrompt {
		limit = setupStatePreviewEntries
	}

	for _, entry := range entries[:limit] {
		if entry.Version == "" {
			fmt.Printf("  %s\n", entry.Name)
			continue
		}
		fmt.Printf("  %-*s  %s\n", maxNameWidth, entry.Name, entry.Version)
	}

	if len(entries) <= maxSetupStateEntriesWithoutPrompt {
		return
	}
	if !shouldPrintFullSetupState(label, len(entries)) {
		fmt.Printf("  ... (%d more omitted)\n", len(entries)-limit)
		return
	}
	for _, entry := range entries[limit:] {
		if entry.Version == "" {
			fmt.Printf("  %s\n", entry.Name)
			continue
		}
		fmt.Printf("  %-*s  %s\n", maxNameWidth, entry.Name, entry.Version)
	}
}

func cmdProjectFirewallShow() error {
	logInfo("starting project firewall show command", "store", storeDir())
	if _, err := requireProject("project firewall show"); err != nil {
		return err
	}

	running, stale := detectRunningProjectVMWithMetadata()
	if stale {
		_ = storeClearRuntimeState()
		running = nil
	}

	if running != nil {
		if err := projectShowFirewallFromVM(running.Port); err != nil {
			return err
		}
		return nil
	}

	return projectShowFirewallFromTemporaryVM()
}

func cmdProjectClean() error {
	logInfo("starting project clean command", "store", storeDir())
	if _, err := requireProject("project clean"); err != nil {
		return err
	}

	running, stale := detectRunningProjectVM()
	if stale {
		_ = storeClearRuntimeState()
		running = nil
	}
	if running != nil {
		return fmt.Errorf("project VM is running; stop it with 'zaigr project vm stop' before running project clean")
	}
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

	imagePath, err := rebuildProjectImageToBase()
	if err != nil {
		return err
	}

	storeRemoveAll(setupStateCommitted)
	storeRemoveAll(setupStateAwaitingCommit)
	storeRemoveAll(setupStateFailed)
	if err := storeClearPresetSelection(); err != nil {
		return err
	}
	if err := storeWriteFirewallEntries([]string{}); err != nil {
		return fmt.Errorf("clear project firewall rules: %w", err)
	}
	if err := currentProjectStore().clearProjectImageDirty(); err != nil {
		return err
	}

	fmt.Printf(
		":: Removed setup state (%d committed to project image, %d awaiting image commit, %d failed)\n",
		len(committed),
		len(awaitingCommit),
		len(failed),
	)
	fmt.Printf(":: Rebuilt project image to base: %s\n", filepath.Base(imagePath))
	return nil
}

func cmdProjectRebuild(force bool) error {
	logInfo("starting project rebuild command", "store", storeDir(), "force", force)
	if _, err := requireProject("project rebuild"); err != nil {
		return err
	}

	running, stale := detectRunningProjectVM()
	if stale {
		_ = storeClearRuntimeState()
		running = nil
	}
	if running != nil {
		return fmt.Errorf("project VM is running; stop it with 'zaigr project vm stop' before running project rebuild")
	}

	if !force {
		dirty, hasDirty, err := currentProjectStore().readProjectImageDirty()
		if err != nil {
			return err
		}
		if hasDirty {
			source := dirty.Source
			if source == "" {
				source = dirty.Reason
			}
			return fmt.Errorf("project image has unsaved changes from %s; rerun with --force to rebuild anyway", source)
		}
	}

	if err := rebuildProjectImageFromCommittedState(); err != nil {
		return err
	}
	imagePath, err := storeImagePath()
	if err != nil {
		return err
	}
	fmt.Printf(":: Rebuilt project image from committed state: %s\n", filepath.Base(imagePath))
	fmt.Printf(":: Recorded base image version: %s\n", baseRootfsVersion())
	return nil
}

func cmdProjectDelete(force bool) error {
	logInfo("starting project delete command", "store", storeDir(), "force", force)
	storePath, err := requireProject("project delete")
	if err != nil {
		return err
	}

	running, stale := detectRunningProjectVM()
	if stale {
		_ = storeClearRuntimeState()
		running = nil
	}
	if running != nil {
		return fmt.Errorf("project VM is running; stop it with 'zaigr project vm stop' before running project delete")
	}

	if !force && !confirmProjectDelete(storePath) {
		fmt.Fprintf(os.Stderr, ":: Project delete cancelled\n")
		return nil
	}

	if err := os.RemoveAll(storePath); err != nil {
		return fmt.Errorf("delete project store %s: %w", storePath, err)
	}
	fmt.Printf(":: Deleted project store: %s\n", storePath)
	return nil
}

func confirmProjectDelete(storePath string) bool {
	fmt.Fprintf(os.Stderr, "Delete project store %s? This will remove project metadata and images. [y/N] ", storePath)
	var answer string
	_, _ = fmt.Scanln(&answer)
	return strings.EqualFold(strings.TrimSpace(answer), "y") || strings.EqualFold(strings.TrimSpace(answer), "yes")
}

func cmdProjectStopVM(abrupt bool) error {
	if _, err := requireProject("project vm stop"); err != nil {
		return err
	}

	result, err := stopProjectVMInStore(currentProjectStore(), abrupt)
	if err != nil {
		return err
	}
	switch result.State {
	case projectVMStopStateStopped:
		fmt.Printf(":: Project VM stopped\n")
		return nil
	case projectVMStopStateStale, projectVMStopStateOff:
		return fmt.Errorf("project VM is not running")
	default:
		return fmt.Errorf("unknown project VM stop result: %s", result.State)
	}
}

type projectVMStopState string

const (
	projectVMStopStateStopped projectVMStopState = "stopped"
	projectVMStopStateOff     projectVMStopState = "off"
	projectVMStopStateStale   projectVMStopState = "stale"
)

type projectVMStopResult struct {
	State projectVMStopState
}

func stopProjectVMInStore(store projectStore, abrupt bool) (projectVMStopResult, error) {
	sockPath := store.monitorSockPath()
	running, stale := detectRunningProjectVMInStore(store)
	if stale {
		_ = store.clearRuntimeState()
		return projectVMStopResult{State: projectVMStopStateStale}, nil
	}
	if running == nil {
		return projectVMStopResult{State: projectVMStopStateOff}, nil
	}

	if abrupt {
		pids, err := findQemuProcessesForSocket(sockPath)
		if err != nil {
			return projectVMStopResult{}, err
		}
		if len(pids) == 0 {
			qmpQuit(sockPath)
			if waitForProjectVMStopInStore(store, stopVMSignalTimeout()) {
				_ = os.Remove(sockPath)
				return projectVMStopResult{State: projectVMStopStateStopped}, nil
			}
			return projectVMStopResult{}, fmt.Errorf("project VM is running but no matching qemu process was found")
		}
		if err := killQemuProcesses(pids); err != nil {
			return projectVMStopResult{}, err
		}
		if !waitForProjectVMStopInStore(store, stopVMAbruptTimeout()) {
			return projectVMStopResult{}, fmt.Errorf("could not stop project VM in %s; remove %s manually", stopVMAbruptTimeout(), sockPath)
		}
	} else {
		qmpQuit(sockPath)
		if !waitForProjectVMStopInStore(store, stopVMGracefulTimeout()) {
			return projectVMStopResult{}, fmt.Errorf("project VM did not stop within %s; use --abrupt to force", stopVMGracefulTimeout())
		}
	}

	_ = store.clearRuntimeState()
	return projectVMStopResult{State: projectVMStopStateStopped}, nil
}

func stopVMGracefulTimeout() time.Duration {
	return 30 * time.Second
}

func stopVMAbruptTimeout() time.Duration {
	return 10 * time.Second
}

func stopVMSignalTimeout() time.Duration {
	return 5 * time.Second
}

func findQemuProcessesForSocket(sockPath string) ([]int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("read /proc: %w", err)
	}

	marker := "unix:" + sockPath
	var pids []int
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if name == "" || name[0] < '0' || name[0] > '9' {
			continue
		}

		pid, err := strconv.Atoi(name)
		if err != nil {
			continue
		}

		cmdlinePath := filepath.Join("/proc", name, "cmdline")
		cmdlineBytes, err := os.ReadFile(cmdlinePath)
		if err != nil {
			continue
		}
		cmdline := string(cmdlineBytes)
		if strings.Contains(cmdline, "qemu-system-x86_64") && strings.Contains(cmdline, marker) {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

func killQemuProcesses(pids []int) error {
	for _, pid := range pids {
		process, err := os.FindProcess(pid)
		if err != nil {
			return fmt.Errorf("locate vm process %d: %w", pid, err)
		}
		if err := process.Kill(); err != nil && !isProcessGone(pid) {
			return fmt.Errorf("kill vm process %d: %w", pid, err)
		}
	}
	return nil
}

func waitForProjectVMStop(timeout time.Duration) bool {
	return waitForProjectVMStopInStore(currentProjectStore(), timeout)
}

func waitForProjectVMStopInStore(store projectStore, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		running, stale := detectRunningProjectVMInStore(store)
		if stale || running == nil {
			return true
		}
		time.Sleep(250 * time.Millisecond)
	}
	return false
}

func isProcessGone(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return true
	}
	return process.Signal(syscall.Signal(0)) != nil
}

func rebuildProjectImageToBase() (string, error) {
	disk, _ := resolveDisk("")
	if err := os.MkdirAll(storeDir(), 0755); err != nil {
		return "", fmt.Errorf("create store dir: %w", err)
	}

	configPath := storeConfigPath()
	if err := os.WriteFile(configPath, []byte(fmt.Sprintf("disk=%s\n", disk)), 0644); err != nil {
		return "", fmt.Errorf("store config: %w", err)
	}

	imagePath, err := storeImagePathForSteps(nil)
	if err != nil {
		return "", err
	}

	wipPath := imagePath + ".wip"
	_ = os.Remove(wipPath)

	if err := buildImageFromBase(wipPath, disk); err != nil {
		_ = os.Remove(wipPath)
		return "", fmt.Errorf("build base image: %w", err)
	}

	if err := os.Remove(imagePath); err != nil && !os.IsNotExist(err) {
		_ = os.Remove(wipPath)
		return "", fmt.Errorf("remove previous image: %w", err)
	}
	if err := os.Rename(wipPath, imagePath); err != nil {
		_ = os.Remove(wipPath)
		return "", fmt.Errorf("rename base image: %w", err)
	}

	if err := currentProjectStore().writeBaseImageVersion(baseRootfsVersion()); err != nil {
		return "", err
	}

	removeGlob(filepath.Join(storeDir(), "image-*.qcow2.wip"))
	removeGlob(filepath.Join(storeDir(), "image-*.img"))
	return imagePath, nil
}

func projectFirewallEntriesFromVM(port string) (map[string]struct{}, []string, error) {
	rootKeyPath, _, err := ensureRootSSHKey()
	if err != nil {
		return nil, nil, err
	}
	command := "if [ -f /etc/opensnitchd/lists/domains/allowed.txt ]; then " +
		"cat /etc/opensnitchd/lists/domains/allowed.txt; else " +
		"printf 'allowed domain list not found\\n'; fi"
	out, err := sshReadCommand(port, rootKeyPath, "root", command)
	if err != nil {
		return nil, nil, fmt.Errorf("read VM firewall: %w", err)
	}
	active, ordered := parseFirewallEntries(string(out))
	return active, ordered, nil
}

func projectShowFirewallFromVM(port string) error {
	active, ordered, err := projectFirewallEntriesFromVM(port)
	if err != nil {
		return err
	}
	return projectShowFirewallEntries(active, ordered)
}

func projectShowFirewallFromTemporaryVM() error {
	if err := requireKVMAccess(); err != nil {
		return err
	}

	imagePath, err := storeImagePath()
	if err != nil {
		return err
	}
	if _, err := os.Stat(imagePath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("project image not found; run 'zaigr project vm start' first")
		}
		return fmt.Errorf("stat project image: %w", err)
	}

	kernelPath, err := ensureKernelQuiet(false)
	if err != nil {
		return err
	}
	sshPort, err := allocateEphemeralSSHPort()
	if err != nil {
		return err
	}
	_, rootPubKey, err := ensureRootSSHKey()
	if err != nil {
		return fmt.Errorf("ensure root SSH key: %w", err)
	}
	qemuPath, err := exec.LookPath("qemu-system-x86_64")
	if err != nil {
		return fmt.Errorf("qemu not found: %w", err)
	}
	if err := currentProjectStore().ensureAgentStateDir(); err != nil {
		return err
	}

	monitorSock := filepath.Join(storeDir(), "project-firewall-show-vm.sock")
	_ = os.Remove(monitorSock)
	args := buildQEMUArgs(
		imagePath,
		kernelPath,
		"qcow2",
		true,
		defaultVMRam,
		defaultVMCPUs,
		sshPort,
		rootPubKey,
		storeProjectHostname(),
		monitorSock,
	)

	fmt.Fprintf(os.Stderr, ":: Project VM is not running; booting temporary VM to read firewall\n")
	logInfo("starting temporary VM for firewall inspection", "image", imagePath, "port", sshPort, "monitor_sock", monitorSock)

	serialLog, err := os.OpenFile(storeSerialLogPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("open VM serial log: %w", err)
	}
	defer serialLog.Close()

	devNull, err := os.Open(os.DevNull)
	if err != nil {
		return fmt.Errorf("open %s: %w", os.DevNull, err)
	}
	defer devNull.Close()

	cmd := exec.Command(qemuPath, args[1:]...)
	cmd.Stdin = devNull
	cmd.Stdout = serialLog
	cmd.Stderr = serialLog
	if err := cmd.Start(); err != nil {
		_ = os.Remove(monitorSock)
		return fmt.Errorf("start temporary qemu: %w", err)
	}
	defer stopTemporaryQEMU(cmd, monitorSock)

	if !waitForSSH(sshPort, 60) {
		return fmt.Errorf("temporary VM did not become reachable via SSH within 60s")
	}

	active, ordered, err := projectFirewallEntriesFromVM(sshPort)
	if err != nil {
		return fmt.Errorf("read VM firewall: %w", err)
	}
	return projectShowFirewallEntries(active, ordered)
}

func stopTemporaryQEMU(cmd *exec.Cmd, monitorSock string) {
	qmpQuit(monitorSock)
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		<-done
	}
	_ = os.Remove(monitorSock)
}

func syncCommittedSetupFirewallToVM(port string) error {
	groups, err := loadCommittedSetupFirewallGroups()
	if err != nil {
		return err
	}
	setupEntries := make([]string, 0)
	for _, group := range groups {
		setupEntries = appendUniqueFirewallEntries(setupEntries, group.Entries)
	}
	globalEntries, err := globalFirewallEntries()
	if err != nil {
		return err
	}
	previousGlobalEntries, err := storeAppliedGlobalFirewallEntries()
	if err != nil {
		return err
	}
	syncGroups := append([]setupFirewallGroup{}, groups...)
	if len(globalEntries) > 0 {
		syncGroups = append(syncGroups, setupFirewallGroup{
			Name:    "global",
			Entries: globalEntries,
		})
	}
	staleGlobalEntries := staleGlobalFirewallEntries(previousGlobalEntries, setupEntries, globalEntries)
	if len(syncGroups) == 0 && len(staleGlobalEntries) == 0 {
		return nil
	}
	digest := committedSetupFirewallDigest(syncGroups)
	if syncedDigest, err := storeReadCommittedFirewallSyncMarker(); err == nil && syncedDigest == digest && len(staleGlobalEntries) == 0 {
		logInfo("skipping committed setup firewall sync; already synced this VM boot", "digest", digest)
		return nil
	}
	if len(setupEntries) > 0 {
		if err := storeAppendFirewallEntries(setupEntries); err != nil {
			return err
		}
	}
	if len(globalEntries) > 0 {
		fmt.Fprintln(os.Stderr, "warning: applying global firewall allowlist entries:")
		for _, entry := range globalEntries {
			fmt.Fprintf(os.Stderr, "  %s\n", entry)
		}
	}
	rootKeyPath, _, err := ensureRootSSHKey()
	if err != nil {
		return err
	}
	if err := sshRunScript(port, rootKeyPath, firewallSyncCommands(syncGroups, staleGlobalEntries)); err != nil {
		return fmt.Errorf("sync committed setup firewall to VM: %w", err)
	}
	if err := storeWriteCommittedFirewallSyncMarker(digest); err != nil {
		return err
	}
	if err := storeWriteAppliedGlobalFirewallEntries(globalEntries); err != nil {
		return err
	}
	return nil
}

func staleGlobalFirewallEntries(previousGlobalEntries []string, setupEntries []string, globalEntries []string) []string {
	allowed := make(map[string]struct{}, len(setupEntries)+len(globalEntries))
	for _, entry := range setupEntries {
		allowed[entry] = struct{}{}
	}
	for _, entry := range globalEntries {
		allowed[entry] = struct{}{}
	}
	stale := make([]string, 0)
	for _, entry := range previousGlobalEntries {
		if _, ok := allowed[entry]; ok {
			continue
		}
		stale = append(stale, entry)
	}
	return stale
}

func committedSetupFirewallDigest(groups []setupFirewallGroup) string {
	entriesByName := make(map[string][]string, len(groups))
	for _, group := range groups {
		if group.Name == "" {
			continue
		}
		entriesByName[group.Name] = appendUniqueFirewallEntries(entriesByName[group.Name], group.Entries)
	}
	names := make([]string, 0, len(entriesByName))
	for name := range entriesByName {
		names = append(names, name)
	}
	sort.Strings(names)

	var payload strings.Builder
	for _, name := range names {
		payload.WriteString(name)
		payload.WriteByte('\n')
		entries := make([]string, len(entriesByName[name]))
		copy(entries, entriesByName[name])
		sort.Strings(entries)
		for _, entry := range entries {
			payload.WriteString(entry)
			payload.WriteByte('\n')
		}
	}
	sum := sha256.Sum256([]byte(payload.String()))
	return fmt.Sprintf("%x", sum)
}

func projectShowFirewallEntries(entries map[string]struct{}, ordered []string) error {
	groups, err := loadCommittedSetupFirewallGroups()
	if err != nil {
		return err
	}
	globalEntries, err := globalFirewallEntries()
	if err != nil {
		return err
	}

	covered := make(map[string]struct{})
	totalPrinted := 0
	activeGlobal := make([]string, 0, len(globalEntries))
	for _, entry := range globalEntries {
		if _, ok := entries[entry]; ok {
			activeGlobal = append(activeGlobal, entry)
		}
	}
	if len(activeGlobal) > 0 {
		totalPrinted++
		fmt.Println("# global")
		for _, entry := range activeGlobal {
			fmt.Println(entry)
			covered[entry] = struct{}{}
		}
	}
	for _, group := range groups {
		active := make([]string, 0, len(group.Entries))
		for _, entry := range group.Entries {
			if _, ok := entries[entry]; ok {
				active = append(active, entry)
			}
		}
		if len(active) == 0 {
			continue
		}
		totalPrinted++
		fmt.Printf("# %s\n", group.Name)
		for _, entry := range active {
			fmt.Println(entry)
			covered[entry] = struct{}{}
		}
	}

	extras := make([]string, 0, len(entries))
	for _, entry := range ordered {
		if _, ok := covered[entry]; !ok {
			extras = append(extras, entry)
		}
	}

	if totalPrinted == 0 && len(extras) == 0 {
		fmt.Println("No project-specific firewall entries have been recorded.")
		return nil
	}
	if len(extras) > 0 {
		fmt.Println("# other entries")
		for _, entry := range extras {
			fmt.Println(entry)
		}
	}
	return nil
}

type setupFirewallGroup struct {
	Name    string
	Entries []string
}

func setupFirewallCommands(groups []setupFirewallGroup) string {
	var script strings.Builder
	for _, group := range groups {
		if len(group.Entries) == 0 {
			continue
		}
		script.WriteString(setupFirewallCommand(group.Name, group.Entries))
		script.WriteByte('\n')
	}
	return script.String()
}

func firewallSyncCommands(groups []setupFirewallGroup, removeEntries []string) string {
	var script strings.Builder
	if len(removeEntries) > 0 {
		script.WriteString(`allowed_file=/etc/opensnitchd/lists/domains/allowed.txt
if [ -f "$allowed_file" ]; then
  tmp=$(mktemp "${allowed_file}.XXXXXX")
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
`)
		for _, entry := range removeEntries {
			script.WriteString("      ")
			script.WriteString(entry)
			script.WriteString(")\n        continue\n        ;;\n")
		}
		script.WriteString(`    esac
    printf '%s\n' "$line" >> "$tmp"
  done < "$allowed_file"
  chmod 0644 "$tmp"
  mv "$tmp" "$allowed_file"
fi
`)
	}
	script.WriteString(setupFirewallCommands(groups))
	return script.String()
}

func loadCommittedSetupFirewallGroups() ([]setupFirewallGroup, error) {
	steps, err := storeCommittedSetups()
	if err != nil {
		return nil, err
	}
	groups := make([]setupFirewallGroup, 0, len(steps))
	byName := make(map[string]int, len(steps))
	for _, step := range steps {
		name := storeScriptBaseNameFromPath(step)
		if name == "" {
			continue
		}
		root := filepath.Join(zaigDir(), "setups", name)
		paths, err := setupFirewallPaths(root)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		if len(paths) == 0 {
			continue
		}
		entries := make([]string, 0)
		for _, path := range paths {
			extra, err := readFirewallEntries(path)
			if err != nil {
				return nil, err
			}
			entries = append(entries, extra...)
		}
		if len(entries) == 0 {
			continue
		}
		if index, ok := byName[name]; ok {
			groups[index].Entries = appendUniqueFirewallEntries(groups[index].Entries, entries)
			continue
		}
		byName[name] = len(groups)
		groups = append(groups, setupFirewallGroup{
			Name:    name,
			Entries: entries,
		})
	}
	return groups, nil
}

func appendUniqueFirewallEntries(current []string, additions []string) []string {
	seen := make(map[string]struct{}, len(current)+len(additions))
	for _, entry := range current {
		seen[entry] = struct{}{}
	}
	for _, entry := range additions {
		if _, ok := seen[entry]; ok {
			continue
		}
		current = append(current, entry)
		seen[entry] = struct{}{}
	}
	return current
}

func parseFirewallEntries(raw string) (map[string]struct{}, []string) {
	lines := strings.Split(raw, "\n")
	active := make(map[string]struct{}, len(lines))
	ordered := make([]string, 0, len(lines))
	for _, line := range lines {
		entry := strings.TrimSpace(line)
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		if _, exists := active[entry]; !exists {
			active[entry] = struct{}{}
			ordered = append(ordered, entry)
		}
	}
	return active, ordered
}

func normalizeFirewallEntries(entries []string) (map[string]struct{}, []string) {
	set := make(map[string]struct{}, len(entries))
	ordered := make([]string, 0, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if _, ok := set[entry]; !ok {
			ordered = append(ordered, entry)
		}
		set[entry] = struct{}{}
	}
	return set, ordered
}

func coalesce(value string, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
