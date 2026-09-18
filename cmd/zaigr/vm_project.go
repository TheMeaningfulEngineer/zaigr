package main

import (
	"crypto/sha256"
	"errors"
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

func cmdProjectShowVMConfig() error {
	lock, err := lockCurrentProject("project vm show-config")
	if err != nil {
		return err
	}
	defer lock.releaseWithWarning()
	if _, err := requireProject("project vm show-config"); err != nil {
		return err
	}

	store := currentProjectStore()
	ram := store.ram()
	if ram == "" {
		ram = "unknown"
	}
	cpu := store.cpus()
	if cpu == "" {
		cpu = "unknown"
	}
	fmt.Printf("cpu=%s\n", cpu)
	fmt.Printf("ram=%sMB\n", ram)
	return nil
}

func cmdProjectStartVM(ram string, cpu string) error {
	lock, err := lockCurrentProjectExclusive("project vm start")
	if err != nil {
		return err
	}
	defer lock.releaseWithWarning()
	if err := lock.recover(currentProjectStore(), "project vm start"); err != nil {
		return err
	}
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

	port, err := startPreparedProjectVM(ram, cpu)
	if err != nil {
		return err
	}
	logInfo("project vm start completed", "port", port)
	fmt.Printf(":: Project VM started on port %s\n", port)
	return nil
}

func cmdProjectSetVMConfig(ram string, cpu string) error {
	lock, err := lockCurrentProject("project vm set-config")
	if err != nil {
		return err
	}
	defer lock.releaseWithWarning()
	if _, err := requireProject("project vm set-config"); err != nil {
		return err
	}
	store := currentProjectStore()
	if ram == "" && cpu == "" {
		return fmt.Errorf("provide --ram and/or --cpu")
	}
	running, stale := detectRunningProjectVM()
	if stale {
		_ = store.clearRuntimeState()
		running = nil
	}
	if running != nil {
		return fmt.Errorf("project VM is running; stop it with 'zaigr project vm stop' before running project vm set-config")
	}

	if ram != "" {
		if _, err := strconv.Atoi(ram); err != nil {
			return fmt.Errorf("invalid --ram value: %q", ram)
		}
		if err := os.WriteFile(store.ramPath(), []byte(fmt.Sprintf("%s\n", ram)), 0644); err != nil {
			return fmt.Errorf("store default ram: %w", err)
		}
	}

	if cpu != "" {
		if _, err := strconv.Atoi(cpu); err != nil {
			return fmt.Errorf("invalid --cpu value: %q", cpu)
		}
		if err := os.WriteFile(store.cpusPath(), []byte(fmt.Sprintf("%s\n", cpu)), 0644); err != nil {
			return fmt.Errorf("store default cpus: %w", err)
		}
	}

	fmt.Printf(":: Project defaults updated in %s\n", store.Path)
	return nil
}

func cmdProjectVMExec(commandArgs []string, root bool) error {
	lock, err := lockCurrentProject("project vm exec")
	if err != nil {
		return err
	}
	defer lock.releaseWithWarning()
	if _, err := requireProject("project vm exec"); err != nil {
		return err
	}
	if err := requireNoActiveSetupCapture("zaigr project vm exec"); err != nil {
		return err
	}
	if err := resolveProjectImageForCommand(); err != nil {
		return err
	}

	running, stale := detectRunningProjectVM()
	if stale {
		_ = currentProjectStore().clearRuntimeState()
		running = nil
	}
	if running == nil {
		return fmt.Errorf("project VM is not running; start it with 'zaigr project vm start' or 'zaigr shell'")
	}

	command := projectVMExecShellCommand(commandArgs)
	if !root {
		if err := reconcileSavedProjectFirewallIPsToVM(running.Port); err != nil {
			return fmt.Errorf("reconcile project firewall before project vm exec: %w", err)
		}
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

func cmdProjectSetupList(appliedFlag bool) error {
	lock, err := lockCurrentProject("project setup list")
	if err != nil {
		return err
	}
	defer lock.releaseWithWarning()
	_ = appliedFlag
	if _, err := requireProject("project setup list"); err != nil {
		return err
	}
	records, err := currentProjectStore().readAppliedSetups()
	if err != nil {
		return err
	}
	fmt.Printf("applied (%d):\n", len(records))
	if len(records) == 0 {
		fmt.Println("  (none)")
		return nil
	}
	for _, record := range records {
		fmt.Printf("  %s  %s\n", displaySetupName(record.Name, record.ProjectLocal), record.Version)
	}
	return nil
}

func cmdProjectStatus() error {
	lock, err := lockCurrentProject("project status")
	if err != nil {
		return err
	}
	defer lock.releaseWithWarning()
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

	applied, err := currentProjectStore().readAppliedSetups()
	if err != nil {
		return err
	}
	projectImagePath := currentProjectStore().authoritativeImagePath()
	_, imageErr := os.Stat(projectImagePath)
	projectImageMissing := os.IsNotExist(imageErr)
	if imageErr != nil && !projectImageMissing {
		return imageErr
	}
	hasSetupFailure, err := currentProjectStore().hasSetupFailureMarker()
	if err != nil {
		return err
	}

	logDebug("probing running VM metadata", "store", storePath)
	running, stale := detectRunningProjectVMWithMetadata()
	logDebug("reading preset selection", "store", storePath)
	presetSelection, hasPresetSelection, err := currentProjectStore().readPresetSelection()
	if err != nil {
		return err
	}
	logDebug("loaded project status metadata", "running", running != nil, "stale", stale, "has_preset", hasPresetSelection)
	dirtyImage, hasDirtyImage, err := currentProjectStore().readProjectImageDirty()
	if err != nil {
		return err
	}

	printProjectStatus(projectStatusRender{
		StorePath:       storePath,
		CPU:             currentProjectStore().cpus(),
		RAM:             currentProjectStore().ram(),
		Image:           projectStatusImageFromPaths(projectImagePath, projectImageMissing, projectImagePath, imageErr),
		ImageMismatch:   projectImageDiagnosis,
		DirtyImage:      dirtyImage,
		HasDirtyImage:   hasDirtyImage,
		Running:         running,
		Stale:           stale,
		Preset:          presetSelection,
		HasPreset:       hasPresetSelection,
		Applied:         applied,
		SetupFailedOnce: hasSetupFailure,
	})
	return nil
}

func cmdProjectFirewallShow() error {
	lock, err := lockCurrentProject("project firewall show")
	if err != nil {
		return err
	}
	defer lock.releaseWithWarning()
	logInfo("starting project firewall show command", "store", storeDir())
	if _, err := requireProject("project firewall show"); err != nil {
		return err
	}
	addresses, err := currentProjectStore().firewallIPs()
	if err != nil {
		return err
	}

	running, stale := detectRunningProjectVMWithMetadata()
	if stale {
		_ = currentProjectStore().clearRuntimeState()
		running = nil
	}

	if running != nil {
		printProjectFirewallIPs(addresses, true)
		if err := projectShowFirewallFromVM(running.Port); err != nil {
			return err
		}
		return nil
	}

	printProjectFirewallIPs(addresses, false)
	return projectShowFirewallFromTemporaryVM()
}

func cmdProjectClean() error {
	lock, err := lockCurrentProjectExclusive("project clean")
	if err != nil {
		return err
	}
	defer lock.releaseWithWarning()
	logInfo("starting project clean command", "store", storeDir())
	if _, err := requireProject("project clean"); err != nil {
		return err
	}
	if err := requireNoActiveSetupCapture("zaigr project clean"); err != nil {
		return err
	}

	running, stale := detectRunningProjectVM()
	if running == nil {
		if err := requireNoRunningProjectQemu(currentProjectStore(), "project clean"); err != nil {
			return err
		}
	}
	if stale {
		_ = currentProjectStore().clearRuntimeState()
		running = nil
	}
	if running != nil {
		return fmt.Errorf("project VM is running; stop it with 'zaigr project vm stop' before running project clean")
	}
	if err := requireNoActiveProjectShells(currentProjectStore(), "project clean"); err != nil {
		return err
	}
	if err := lock.recover(currentProjectStore(), "project clean"); err != nil {
		return err
	}
	return cleanProjectToCurrentBase()
}

func cmdProjectRebuild(force bool) error {
	lock, err := lockCurrentProjectExclusive("project rebuild")
	if err != nil {
		return err
	}
	defer lock.releaseWithWarning()
	logInfo("starting project rebuild command", "store", storeDir(), "force", force)
	if _, err := requireProject("project rebuild"); err != nil {
		return err
	}
	if err := requireNoActiveSetupCapture("zaigr project rebuild"); err != nil {
		return err
	}

	running, stale := detectRunningProjectVM()
	if running == nil {
		if err := requireNoRunningProjectQemu(currentProjectStore(), "project rebuild"); err != nil {
			return err
		}
	}
	if stale {
		_ = currentProjectStore().clearRuntimeState()
		running = nil
	}
	if running != nil {
		versions := projectBaseRuntimeVersionsForStore(currentProjectStore())
		rootKeyPath, _, keyErr := ensureRootSSHKey()
		if keyErr == nil {
			versions = projectBaseRuntimeVersionsForRunningVM(
				currentProjectStore(), running.Port, rootKeyPath,
			)
		} else {
			logDebug("could not prepare root key for running VM base runtime check", "err", keyErr)
		}
		if versions.upgradeRequired() {
			return fmt.Errorf(
				"this version of zaigr cannot replace the project's outdated base runtime while the VM is running\n"+
					"  running VM base runtime: %s\n"+
					"  required base runtime: %s\n"+
					"Stop it with 'zaigr project vm stop' before running project rebuild",
				versions.runningLabel(),
				versions.requiredLabel(),
			)
		}
		return fmt.Errorf("project VM is running; stop it with 'zaigr project vm stop' before running project rebuild")
	}
	if err := requireNoActiveProjectShells(currentProjectStore(), "project rebuild"); err != nil {
		return err
	}
	if err := lock.recover(currentProjectStore(), "project rebuild"); err != nil {
		return err
	}

	return rebuildProjectFromAppliedState(force)
}

func cmdProjectDelete(force bool) error {
	lock, err := lockCurrentProjectExclusive("project delete")
	if err != nil {
		return err
	}
	defer lock.releaseWithWarning()
	logInfo("starting project delete command", "store", storeDir(), "force", force)
	storePath, err := requireProject("project delete")
	if err != nil {
		return err
	}

	running, stale := detectRunningProjectVM()
	if running == nil {
		if err := requireNoRunningProjectQemu(currentProjectStore(), "project delete"); err != nil {
			return err
		}
	}
	if stale {
		_ = currentProjectStore().clearRuntimeState()
		running = nil
	}
	if running != nil {
		return fmt.Errorf("project VM is running; stop it with 'zaigr project vm stop' before running project delete")
	}
	if err := requireNoActiveProjectShells(currentProjectStore(), "project delete"); err != nil {
		return err
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
	lock, err := lockCurrentProjectExclusive("project vm stop")
	if err != nil {
		return err
	}
	defer lock.releaseWithWarning()
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
	processes, err := openQemuProcessesForSocket(sockPath)
	if err != nil {
		return projectVMStopResult{}, err
	}
	defer releaseQemuProcesses(processes)

	running, stale := detectRunningProjectVMInStore(store)
	if len(processes) == 0 {
		if running != nil {
			return projectVMStopResult{}, fmt.Errorf("project VM is running but no matching qemu process was found")
		}
		if stale {
			_ = store.clearRuntimeState()
			return projectVMStopResult{State: projectVMStopStateStale}, nil
		}
		return projectVMStopResult{State: projectVMStopStateOff}, nil
	}

	if abrupt {
		if err := killQemuProcesses(processes); err != nil {
			return projectVMStopResult{}, err
		}
	} else {
		if running == nil || running.Port == "" {
			return projectVMStopResult{}, fmt.Errorf("QEMU is running but its monitor or SSH port is unavailable; use --abrupt to force")
		}
		rootKeyPath, _, keyErr := ensureRootSSHKey()
		if keyErr != nil {
			return projectVMStopResult{}, fmt.Errorf("prepare graceful VM shutdown: %w", keyErr)
		}
		if err := sshSync(running.Port, rootKeyPath); err != nil {
			return projectVMStopResult{}, fmt.Errorf("flush project VM before shutdown: %w; use 'zaigr project vm stop --abrupt' only if recovery is required", err)
		}
		qmpQuit(sockPath)
		if err := waitForQemuProcessesExit(processes, stopVMGracefulTimeout()); err != nil {
			return projectVMStopResult{}, fmt.Errorf("could not confirm project VM shutdown: %w; use --abrupt to force", err)
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

func findQemuProcessesForSocket(sockPath string) ([]int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("read /proc: %w", err)
	}

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
		args := strings.Split(strings.TrimRight(string(cmdlineBytes), "\x00"), "\x00")
		if len(args) == 0 || filepath.Base(args[0]) != "qemu-system-x86_64" {
			continue
		}
		for index := 1; index+1 < len(args); index++ {
			if args[index] == "-qmp" && strings.SplitN(args[index+1], ",", 2)[0] == "unix:"+sockPath {
				pids = append(pids, pid)
				break
			}
		}
	}
	return pids, nil
}

// qemuProcessIdentity retains a signal handle and the Linux process start time.
type qemuProcessIdentity struct {
	process   *os.Process
	startTime uint64
}

// Call under the project lock before deleting runtime state or disk images.
func requireNoRunningProjectQemu(store projectStore, operation string) error {
	processes, err := openQemuProcessesForSocket(store.monitorSockPath())
	if err != nil {
		return err
	}
	defer releaseQemuProcesses(processes)
	if len(processes) != 0 {
		return fmt.Errorf("project VM is running; stop it with 'zaigr project vm stop --abrupt' before running %s", operation)
	}
	return nil
}

// openQemuProcessesForSocket captures process identities before shutdown begins.
// The caller must release the returned handles, including after a failed stop.
func openQemuProcessesForSocket(sockPath string) ([]qemuProcessIdentity, error) {
	pids, err := findQemuProcessesForSocket(sockPath)
	if err != nil {
		return nil, err
	}
	var processes []qemuProcessIdentity
	for _, pid := range pids {
		_, startTime, _, err := readQemuProcessState(pid)
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
			continue
		}
		if err != nil {
			releaseQemuProcesses(processes)
			return nil, fmt.Errorf("inspect VM process %d: %w", pid, err)
		}
		process, err := os.FindProcess(pid)
		if err != nil {
			releaseQemuProcesses(processes)
			return nil, fmt.Errorf("locate VM process %d: %w", pid, err)
		}
		identity := qemuProcessIdentity{process: process, startTime: startTime}
		exited, err := identity.exited()
		if err != nil || exited {
			_ = process.Release()
			if err != nil {
				releaseQemuProcesses(processes)
				return nil, err
			}
			continue
		}
		processes = append(processes, identity)
	}
	return processes, nil
}

func releaseQemuProcesses(processes []qemuProcessIdentity) {
	for _, identity := range processes {
		_ = identity.process.Release()
	}
}

// readQemuProcessState reads fields that remain available after cmdline vanishes.
// A reaped process can cause ENOENT at open or ESRCH at read; both mean it is gone.
func readQemuProcessState(pid int) (byte, uint64, uint64, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, 0, 0, err
	}
	// The parenthesized comm field can itself contain spaces and parentheses.
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 {
		return 0, 0, 0, fmt.Errorf("invalid process stat for PID %d", pid)
	}
	fields := strings.Fields(string(data[end+1:]))
	if len(fields) < 20 || len(fields[0]) != 1 {
		return 0, 0, 0, fmt.Errorf("invalid process stat for PID %d", pid)
	}
	// After comm, state is field 3, num_threads is field 20, and starttime is field 22.
	startTime, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid process start time for PID %d: %w", pid, err)
	}
	threads, err := strconv.ParseUint(fields[17], 10, 64)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid process thread count for PID %d: %w", pid, err)
	}
	return fields[0][0], startTime, threads, nil
}

// exited checks the captured process, not monitor availability or a new scan.
func (identity qemuProcessIdentity) exited() (bool, error) {
	state, startTime, threads, err := readQemuProcessState(identity.process.Pid)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect VM process %d: %w", identity.process.Pid, err)
	}
	// A zombie leader can still have live workers. The kernel samples state
	// before num_threads, so a terminal leader with no other tasks cannot
	// subsequently create a new worker.
	return startTime != identity.startTime || ((state == 'Z' || state == 'X') && threads <= 1), nil
}

// killQemuProcesses reports success only after the captured processes exit.
func killQemuProcesses(processes []qemuProcessIdentity) error {
	for _, identity := range processes {
		exited, err := identity.exited()
		if err != nil {
			return err
		}
		if exited {
			continue
		}
		if err := identity.process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return fmt.Errorf("kill VM process %d: %w", identity.process.Pid, err)
		}
	}
	return waitForQemuProcessesExit(processes, stopVMAbruptTimeout())
}

func waitForQemuProcessesExit(processes []qemuProcessIdentity, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		var remaining []int
		for _, identity := range processes {
			exited, err := identity.exited()
			if err != nil {
				return err
			}
			if !exited {
				remaining = append(remaining, identity.process.Pid)
			}
		}
		if len(remaining) == 0 {
			return nil
		}
		left := time.Until(deadline)
		if left <= 0 {
			return fmt.Errorf("QEMU processes %v did not exit within %s", remaining, timeout)
		}
		time.Sleep(min(left, 50*time.Millisecond))
	}
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

	store := currentProjectStore()
	imagePath := store.authoritativeImagePath()
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
	_, userPubKey, err := ensureUserSSHKey()
	if err != nil {
		return fmt.Errorf("ensure user SSH key: %w", err)
	}
	qemuPath, err := exec.LookPath("qemu-system-x86_64")
	if err != nil {
		return fmt.Errorf("qemu not found: %w", err)
	}
	if err := store.ensureAgentStateDir(); err != nil {
		return err
	}

	monitorSock := filepath.Join(store.Path, "project-firewall-show-vm.sock")
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
		userPubKey,
		store.hostname(),
		monitorSock,
	)

	fmt.Fprintf(os.Stderr, ":: Project VM is not running; booting temporary VM to read firewall\n")
	logInfo("starting temporary VM for firewall inspection", "image", imagePath, "port", sshPort, "monitor_sock", monitorSock)

	serialLog, err := os.OpenFile(store.serialLogPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("open VM serial log: %w", err)
	}
	defer func() { _ = serialLog.Close() }()

	devNull, err := os.Open(os.DevNull)
	if err != nil {
		return fmt.Errorf("open %s: %w", os.DevNull, err)
	}
	defer func() { _ = devNull.Close() }()

	cmd := exec.Command(qemuPath, args[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
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

func syncAppliedSetupFirewallToVM(port string) error {
	if err := syncSavedProjectFirewallIPsToVM(port); err != nil {
		return err
	}
	groups, err := loadAppliedSetupFirewallGroups()
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
	store := currentProjectStore()
	previousGlobalEntries, err := store.appliedGlobalFirewallEntries()
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
	digest := appliedSetupFirewallDigest(syncGroups)
	if syncedDigest, err := store.readAppliedFirewallSyncMarker(); err == nil && syncedDigest == digest && len(staleGlobalEntries) == 0 {
		logInfo("skipping applied setup firewall sync; already synced this VM boot", "digest", digest)
		return nil
	}
	if len(setupEntries) > 0 {
		if err := store.appendFirewallEntries(setupEntries); err != nil {
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
	if err := sshRunControlScript(port, rootKeyPath, firewallSyncCommands(syncGroups, staleGlobalEntries)); err != nil {
		return fmt.Errorf("sync applied setup firewall to VM: %w", err)
	}
	if !waitForStableSSH(port, 30, 3) {
		return fmt.Errorf("VM did not become stably reachable via SSH after syncing applied setup firewall")
	}
	if err := store.writeAppliedFirewallSyncMarker(digest); err != nil {
		return err
	}
	if err := store.writeAppliedGlobalFirewallEntries(globalEntries); err != nil {
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

func appliedSetupFirewallDigest(groups []setupFirewallGroup) string {
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
	groups, err := loadAppliedSetupFirewallGroups()
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

func loadAppliedSetupFirewallGroups() ([]setupFirewallGroup, error) {
	entries, err := currentProjectStore().firewallEntries()
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, nil
	}
	return []setupFirewallGroup{{Name: "project setups", Entries: entries}}, nil
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

func coalesce(value string, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
