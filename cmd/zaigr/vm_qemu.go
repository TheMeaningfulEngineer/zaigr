package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const defaultVMRam = "512"
const defaultVMCPUs = "1"
const defaultDiskSize = "100G"

var projectImagePathOverrideForNextBoot string

type parentProjectStartupAction int

const (
	parentProjectStartupCancel parentProjectStartupAction = iota
	parentProjectStartupUseParent
	parentProjectStartupNewProject
)

// resolveRAM returns the RAM value and its source (flag, env, store, or default).
func resolveRAM(flagValue string) (string, string) {
	if flagValue != "" {
		return flagValue, "cli"
	}
	if env := os.Getenv("ZAIGR_VM_RAM"); env != "" {
		return env, "env"
	}
	if stored := storeRAM(); stored != "" {
		return stored, "project"
	}
	return defaultVMRam, "default"
}

// resolveCPU returns the CPU value and its source (flag, env, store, or default).
func resolveCPU(flagValue string) (string, string, error) {
	if flagValue != "" {
		return flagValue, "cli", nil
	}
	if env := os.Getenv("ZAIGR_VM_CPU"); env != "" {
		return env, "env", nil
	}
	if stored := storeCPUs(); stored != "" {
		return stored, "project", nil
	}
	return defaultVMCPUs, "default", nil
}

// resolveCPUs returns the CPU value and its source (flag, store, or default).
func resolveCPUs(flagValue string) (string, string) {
	if flagValue != "" {
		return flagValue, "cli"
	}
	if stored := storeCPUs(); stored != "" {
		return stored, "project"
	}
	return defaultVMCPUs, "default"
}

// resolveDisk returns the disk size and its source (flag, env, store, or default).
func resolveDisk(flagValue string) (string, string) {
	if flagValue != "" {
		return flagValue, "cli"
	}
	if env := os.Getenv("ZAIGR_DISK_SIZE"); env != "" {
		return env, "env"
	}
	if stored := storeDisk(); stored != "unknown" {
		return stored, "project"
	}
	return defaultDiskSize, "default"
}

// sshHostname returns the hostname of the running VM via SSH, or "" if unreachable.
func sshHostname(port string) string {
	logDebug("probing VM hostname over SSH", "port", port)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	args := append(sshManagedOptions(),
		"-o", "AddressFamily=inet",
		"-o", sshConnectTimeoutOption,
		"-o", "PasswordAuthentication=no",
		"-o", "PubkeyAuthentication=yes",
		"-o", "PreferredAuthentications=publickey",
		"-o", "KbdInteractiveAuthentication=no",
		"-o", "ChallengeResponseAuthentication=no",
		"-p", port,
		"user@localhost", "hostname",
	)
	out, err := exec.CommandContext(ctx, "ssh", args...).Output()
	if ctx.Err() != nil {
		logWarn("VM hostname probe timed out", "port", port)
		return ""
	}
	if err != nil {
		logDebug("VM hostname probe failed", "port", port, "err", err)
		return ""
	}
	hostname := strings.TrimSpace(string(out))
	logDebug("VM hostname probe succeeded", "port", port, "hostname", hostname)
	return hostname
}

// queryQMPImagePath connects to a running QEMU QMP socket and returns the
// image path of the root block device, or "" if it cannot be determined.
func queryQMPImagePath(conn net.Conn) string {
	logDebug("querying QMP image path", "sock", storeMonitorSockPath())
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 8192)

	if _, err := conn.Read(buf); err != nil {
		logDebug("QMP greeting read failed", "err", err)
		return ""
	}
	if _, err := conn.Write([]byte(`{"execute":"qmp_capabilities"}` + "\n")); err != nil {
		logDebug("QMP capabilities request failed", "err", err)
		return ""
	}
	if _, err := conn.Read(buf); err != nil {
		logDebug("QMP capabilities response failed", "err", err)
		return ""
	}
	if _, err := conn.Write([]byte(`{"execute":"query-block"}` + "\n")); err != nil {
		logDebug("QMP query-block request failed", "err", err)
		return ""
	}

	var resp strings.Builder
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			resp.Write(buf[:n])
		}
		if strings.Contains(resp.String(), `"return"`) || err != nil {
			break
		}
	}

	var result struct {
		Return []struct {
			Inserted struct {
				File string `json:"file"`
			} `json:"inserted"`
		} `json:"return"`
	}
	if err := json.Unmarshal([]byte(resp.String()), &result); err != nil {
		logDebug("QMP query-block response parse failed", "err", err)
		return ""
	}
	if len(result.Return) > 0 {
		imagePath := result.Return[0].Inserted.File
		logDebug("QMP image path resolved", "image", imagePath)
		return imagePath
	}
	logDebug("QMP image path unavailable")
	return ""
}

type runningVMInfo struct {
	Port      string
	Hostname  string
	ImagePath string
}

func detectRunningProjectVM() (*runningVMInfo, bool) {
	return detectRunningProjectVMInStore(currentProjectStore())
}

func detectRunningProjectVMInStore(store projectStore) (*runningVMInfo, bool) {
	sockPath := store.monitorSockPath()
	logDebug("probing project VM monitor socket", "sock", sockPath)
	conn, err := net.DialTimeout("unix", sockPath, time.Second)
	if err == nil {
		conn.Close()
		port, _ := store.sshPort()
		if port == "" {
			logWarn("project VM runtime state missing SSH port", "runtime_dir", store.runtimeDir())
		}
		logDebug("project VM monitor responded", "sock", sockPath, "port", port)
		return &runningVMInfo{Port: port}, false
	}

	if _, statErr := os.Stat(sockPath); statErr == nil {
		logDebug("project VM monitor socket exists but did not respond", "store", store.Hash, "sock", sockPath)
		return nil, true
	}

	logDebug("project VM monitor socket not present", "sock", sockPath)
	return nil, false
}

func detectRunningProjectVMWithMetadata() (*runningVMInfo, bool) {
	return detectRunningProjectVMWithMetadataInStore(currentProjectStore())
}

func detectRunningProjectVMWithMetadataInStore(store projectStore) (*runningVMInfo, bool) {
	logDebug("collecting project VM metadata")
	info, stale := detectRunningProjectVMInStore(store)
	if info == nil || stale {
		return info, stale
	}
	info.Hostname = sshHostname(info.Port)

	conn, err := net.DialTimeout("unix", store.monitorSockPath(), time.Second)
	if err == nil {
		info.ImagePath = queryQMPImagePath(conn)
		conn.Close()
	}
	logDebug("project VM metadata collected", "port", info.Port, "hostname", info.Hostname, "image", info.ImagePath)
	return info, false
}

func ensureProjectInitializedForVM(ram string, cpu string) error {
	storePath := storeDir()
	initialized, err := isProjectInitialized(storePath)
	if err != nil {
		return err
	}
	if initialized {
		if err := storeWriteCurrentProjectPath(); err != nil {
			return err
		}
		logDebug("project already initialized", "store", storePath)
		return nil
	}

	logInfo("project is not initialized; prompting to create project metadata", "store", storePath)
	proposedRAM, proposedRAMSource := resolveRAM(ram)
	proposedCPU, proposedCPUSource, err := resolveCPU(cpu)
	if err != nil {
		return err
	}
	if err := requireKVMAccess(); err != nil {
		return err
	}
	if !confirmProjectDefaultsAndCreate(proposedRAM, proposedRAMSource, proposedCPU, proposedCPUSource) {
		return exitError(1)
	}
	if err := cmdInit(proposedRAM, proposedCPU); err != nil {
		return err
	}
	logInfo("project initialized", "store", storePath, "ram", proposedRAM, "cpu", proposedCPU)
	return nil
}

func prepareProjectForVMStart(ram string, cpu string) (*runningVMInfo, error) {
	logDebug("preparing project for VM start", "ram", ram, "cpu", cpu)
	if err := ensureProjectInitializedForVM(ram, cpu); err != nil {
		return nil, err
	}

	running, stale := detectRunningProjectVM()
	if stale {
		_ = storeClearRuntimeState()
		logWarn("removed stale project VM monitor marker", "runtime_dir", storeRuntimeDir())
		running = nil
	}

	hasOverrides := (ram != "") || (cpu != "")
	if running != nil {
		if hasOverrides {
			return nil, fmt.Errorf("project VM is already running; --ram and --cpu cannot be changed on a running VM")
		}
		logInfo("reusing running project VM", "port", running.Port)
		if err := syncCommittedSetupFirewallToVM(running.Port); err != nil {
			return nil, err
		}
		return running, nil
	}

	awaitingCommit, err := storeAwaitingCommitSetups()
	if err != nil {
		return nil, err
	}
	if len(awaitingCommit) > 0 {
		logDebug("project has setups awaiting image commit", "count", len(awaitingCommit))
		if err := resolveAwaitingCommitSetupsOnStartup(awaitingCommit); err != nil {
			return nil, err
		}
	}

	failed, err := storeFailedSetups()
	if err != nil {
		return nil, err
	}
	if len(failed) > 0 {
		latest := filepath.Base(failed[len(failed)-1])
		logWarn("project has failed setup state", "latest", latest, "count", len(failed))
		fmt.Fprintf(os.Stderr, ":: A setup is in failed state: %s\n", latest)
		fmt.Fprintf(os.Stderr, "   Discard failed setups and continue? [y/N] ")
		var answer string
		_, _ = fmt.Scanln(&answer)
		if strings.EqualFold(strings.TrimSpace(answer), "y") {
			storeRemoveAll("failed")
			fmt.Fprintf(os.Stderr, ":: Discarded failed setups\n")
		} else {
			fmt.Fprintf(os.Stderr, "   Resolve with:\n")
			fmt.Fprintf(os.Stderr, "     Re-run with --setup to retry applying setup dependencies manually\n")
			fmt.Fprintf(os.Stderr, "     Or discard failed setups and retry by rerunning this command\n")
			return nil, exitError(1)
		}
	}

	return nil, nil
}

func startPreparedProjectVM(ram string, cpu string) (string, error) {
	ramValue, _ := resolveRAM(ram)
	cpuValue, _, err := resolveCPU(cpu)
	if err != nil {
		return "", err
	}
	logInfo("starting prepared project VM", "ram", ramValue, "cpu", cpuValue)
	imagePort, err := bootProjectVM(ramValue, cpuValue)
	if err != nil {
		return "", err
	}
	logDebug("waiting for project VM SSH readiness", "port", imagePort, "timeout_sec", 90)
	if !waitForSSH(imagePort, 90) {
		return "", fmt.Errorf("VM did not become reachable via SSH within 90s")
	}
	logInfo("project VM is reachable over SSH", "port", imagePort)
	if err := syncCommittedSetupFirewallToVM(imagePort); err != nil {
		return "", err
	}
	return imagePort, nil
}

func cmdVMShell(ram string, cpu string, preset string, setups []string, root bool) error {
	fmt.Printf(":: zaigr %s (%s/%s) built %s\n", version, runtime.GOOS, runtime.GOARCH, buildTime)
	logInfo("starting shell command", "preset", preset, "setup_count", len(setups), "root", root)

	if root && (preset != "" || len(setups) > 0) {
		if preset != "" {
			return fmt.Errorf("--root cannot be used with --preset")
		}
		return fmt.Errorf("--root cannot be used with --setup")
	}

	if err := resolveParentProjectForShell(); err != nil {
		return err
	}

	if err := requireNoActiveSetupCapture("zaigr shell"); err != nil {
		return err
	}

	presetDef, runScript, setupDefs, err := loadPresetPlan(preset, setups)
	if err != nil {
		return err
	}
	running, err := prepareProjectForVMStart(ram, cpu)
	if err != nil {
		return err
	}

	projectImageDiagnosis, err := resolveProjectImageForCommand(true, running == nil)
	if err != nil {
		return err
	}
	var stale bool
	running, stale = detectRunningProjectVM()
	if stale {
		_ = storeClearRuntimeState()
		running = nil
	}

	if root && !confirmRootShellMarksDirtyProjectImage() {
		return exitError(1)
	}

	if running != nil {
		logDebug("shell will attach to existing project VM", "port", running.Port)
		filteredSetupDefs, skippedCommitted, skippedAwaitingCommit, err := filterSetupDefinitionsByStoredState(setupDefs, true)
		if err != nil {
			return err
		}
		filteredSetupDefs = filterSetupsByKeep(filteredSetupDefs, projectImageDiagnosis)
		printSkippedSetupStates(skippedCommitted, skippedAwaitingCommit)
		return cmdVMShellRunning(running.Port, presetDef, runScript, filteredSetupDefs, root)
	}

	filteredSetupDefs, skippedCommitted, skippedAwaitingCommit, err := filterSetupDefinitionsByStoredState(setupDefs, true)
	if err != nil {
		return err
	}
	filteredSetupDefs = filterSetupsByKeep(filteredSetupDefs, projectImageDiagnosis)
	printSkippedSetupStates(skippedCommitted, skippedAwaitingCommit)
	if len(filteredSetupDefs) > 0 {
		logInfo("applying setup definitions to image before boot", "count", len(filteredSetupDefs))
		if err := applySetupDefinitionsToImage(filteredSetupDefs, ram, cpu, false); err != nil {
			return err
		}
	}

	imagePort, err := startPreparedProjectVM(ram, cpu)
	if err != nil {
		return err
	}
	if err := syncPresetSelection(presetDef); err != nil {
		return err
	}
	if len(runScript) > 0 {
		logDebug("running preset script in project VM", "root", root)
		return runPresetInVM(imagePort, runScript, root)
	}
	return execProjectShell(imagePort, root)
}

func resolveParentProjectForShell() error {
	currentPath := canonicalPath(".")
	initialized, err := isProjectInitialized(storeDirForPath(currentPath))
	if err != nil {
		return err
	}
	if initialized {
		return nil
	}

	parentPath, ok, err := nearestInitializedParentProject(currentPath)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}

	switch promptParentProjectStartupAction(parentPath, currentPath) {
	case parentProjectStartupCancel:
		fmt.Fprintln(os.Stderr, ":: Shell cancelled")
		return exitError(1)
	case parentProjectStartupUseParent:
		if err := os.Chdir(parentPath); err != nil {
			return fmt.Errorf("switch to parent project %s: %w", parentPath, err)
		}
		logInfo("using initialized parent project for shell", "parent", parentPath, "current", currentPath)
		return nil
	case parentProjectStartupNewProject:
		return nil
	default:
		return fmt.Errorf("unknown parent project startup action")
	}
}

func nearestInitializedParentProject(path string) (string, bool, error) {
	for parent := filepath.Dir(path); parent != path; parent = filepath.Dir(parent) {
		initialized, err := isProjectInitialized(storeDirForPath(parent))
		if err != nil {
			return "", false, err
		}
		if initialized {
			return parent, true, nil
		}
		path = parent
	}
	return "", false, nil
}

func promptParentProjectStartupAction(parentPath string, currentPath string) parentProjectStartupAction {
	for {
		printParentProjectStartupPrompt(parentPath, currentPath)

		var answer string
		n, err := fmt.Scanln(&answer)
		if err != nil && n == 0 {
			return parentProjectStartupCancel
		}

		switch strings.ToLower(strings.TrimSpace(answer)) {
		case "cancel", "c":
			return parentProjectStartupCancel
		case "parent", "p":
			return parentProjectStartupUseParent
		case "new", "new project", "n":
			return parentProjectStartupNewProject
		default:
			fmt.Fprintf(os.Stderr, "\nInvalid choice. Enter c, p, or n.\n")
		}
	}
}

func printParentProjectStartupPrompt(parentPath string, currentPath string) {
	fmt.Fprintln(os.Stderr, ":: A zaigr project is already initialized for a parent directory.")
	fmt.Fprintf(os.Stderr, "   parent project: %s\n", parentPath)
	fmt.Fprintf(os.Stderr, "   current directory: %s\n", currentPath)
	fmt.Fprintln(os.Stderr, "   [c] cancel       Exit without starting a shell")
	fmt.Fprintln(os.Stderr, "   [p] parent       Run the parent project")
	fmt.Fprintln(os.Stderr, "   [n] new project  Proceed with a new project here")
	fmt.Fprint(os.Stderr, "Action [c/p/n]: ")
}

func confirmProjectDefaultsAndCreate(ram string, ramSource string, cpu string, cpuSource string) bool {
	fmt.Fprintf(os.Stderr, "No project metadata found for this directory.\n")
	fmt.Fprintf(os.Stderr, "Proposed project defaults: ram=%sMB [%s], cpu=%s [%s]\n", ram, ramSource, cpu, cpuSource)
	fmt.Fprintf(os.Stderr, "Initialize project and continue? [y/N] ")
	var answer string
	_, _ = fmt.Scanln(&answer)
	return strings.EqualFold(strings.TrimSpace(answer), "y") || strings.EqualFold(strings.TrimSpace(answer), "yes")
}

func confirmRootShellMarksDirtyProjectImage() bool {
	return confirmRootAccessMarksDirtyProjectImage("root shell")
}

func confirmRootExecMarksDirtyProjectImage() bool {
	return confirmRootAccessMarksDirtyProjectImage("root exec")
}

func confirmRootAccessMarksDirtyProjectImage(action string) bool {
	fmt.Fprintln(os.Stderr, ":: Accessing this VM as root automatically marks the project image dirty.")
	fmt.Fprintln(os.Stderr, "   Dirty means zaigr cannot recreate ad-hoc root changes from committed setups.")
	fmt.Fprintf(os.Stderr, "Continue with %s? [y/N] ", action)
	var answer string
	_, _ = fmt.Scanln(&answer)
	return strings.EqualFold(strings.TrimSpace(answer), "y") || strings.EqualFold(strings.TrimSpace(answer), "yes")
}

func resolveAwaitingCommitSetupsOnStartup(awaitingCommit []string) error {
	if len(awaitingCommit) == 0 {
		return nil
	}

	imageIssue, err := awaitingCommitImageIssue()
	if err != nil {
		return err
	}
	if imageIssue != nil {
		return resolveAwaitingCommitImageIssueOnStartup(awaitingCommit, *imageIssue)
	}

	logDebug("prompting to resolve setups awaiting image commit on startup", "count", len(awaitingCommit))
	for {
		printAwaitingCommitStartupPrompt(awaitingCommit)
		showAvailable := awaitingCommitShowAvailable(awaitingCommit)

		var answer string
		n, err := fmt.Scanln(&answer)
		if err != nil && n == 0 {
			fmt.Fprintf(os.Stderr, "\nCancelled.\n")
			return exitError(1)
		}

		switch strings.ToLower(strings.TrimSpace(answer)) {
		case "commit", "c":
			return cmdModCommitAwaitingSetups()
		case "discard", "d":
			storeRemoveAll(setupStateAwaitingCommit)
			fmt.Fprintf(os.Stderr, ":: Discarded setups awaiting image commit\n")
			return nil
		case "show", "s":
			if showAvailable {
				fmt.Fprintln(os.Stderr, "\nSetups awaiting image commit:")
				printAwaitingCommitPreview(awaitingCommit, len(awaitingCommit))
				fmt.Fprintln(os.Stderr)
			} else {
				fmt.Fprintf(os.Stderr, "\nInvalid choice. Enter c, d, or press Enter to cancel.\n")
			}
		case "":
			fmt.Fprintf(os.Stderr, "\nCancelled.\n")
			return exitError(1)
		default:
			if showAvailable {
				fmt.Fprintf(os.Stderr, "\nInvalid choice. Enter c, s, d, or press Enter to cancel.\n")
			} else {
				fmt.Fprintf(os.Stderr, "\nInvalid choice. Enter c, d, or press Enter to cancel.\n")
			}
		}
	}
}

type awaitingCommitProjectImageIssue struct {
	ExpectedProjectImage string
}

func awaitingCommitImageIssue() (*awaitingCommitProjectImageIssue, error) {
	committed, err := storeCommittedSetups()
	if err != nil {
		return nil, err
	}
	expected, missing, err := validateCommittedProjectImage(committed)
	if err != nil {
		return nil, err
	}
	if !missing {
		return nil, nil
	}

	return &awaitingCommitProjectImageIssue{
		ExpectedProjectImage: filepath.Base(expected),
	}, nil
}

func resolveAwaitingCommitImageIssueOnStartup(awaitingCommit []string, issue awaitingCommitProjectImageIssue) error {
	logDebug("prompting to resolve setups awaiting image commit with missing expected image", "count", len(awaitingCommit), "expected", issue.ExpectedProjectImage)
	for {
		printAwaitingCommitImageIssueStartupPrompt(awaitingCommit, issue)
		showAvailable := awaitingCommitShowAvailable(awaitingCommit)

		var answer string
		n, err := fmt.Scanln(&answer)
		if err != nil && n == 0 {
			return nil
		}

		switch strings.ToLower(strings.TrimSpace(answer)) {
		case "rebuild", "r":
			return cmdModCommitAwaitingSetups()
		case "discard", "d":
			storeRemoveAll(setupStateAwaitingCommit)
			fmt.Fprintf(os.Stderr, ":: Discarded setups awaiting image commit\n")
			return nil
		case "cancel", "c", "":
			fmt.Fprintf(os.Stderr, "\nCancelled.\n")
			return exitError(1)
		case "show", "s":
			if showAvailable {
				fmt.Fprintln(os.Stderr, "\nSetups awaiting image commit:")
				printAwaitingCommitPreview(awaitingCommit, len(awaitingCommit))
				fmt.Fprintln(os.Stderr)
			} else {
				fmt.Fprintf(os.Stderr, "\nInvalid choice. Enter r, d, or press Enter to cancel.\n")
			}
		default:
			if showAvailable {
				fmt.Fprintf(os.Stderr, "\nInvalid choice. Enter r, d, s, or press Enter to cancel.\n")
			} else {
				fmt.Fprintf(os.Stderr, "\nInvalid choice. Enter r, d, or press Enter to cancel.\n")
			}
		}
	}
}

const awaitingCommitPromptPreviewLimit = 4

func awaitingCommitShowAvailable(awaitingCommit []string) bool {
	return len(awaitingCommit) > awaitingCommitPromptPreviewLimit
}

func printAwaitingCommitStartupPrompt(awaitingCommit []string) {
	count := len(awaitingCommit)
	setupWord := "setups"
	verb := "are"
	questionSetup := "these setups"
	if count == 1 {
		setupWord = "setup"
		verb = "is"
		questionSetup = "this setup"
	}

	fmt.Fprintf(os.Stderr, ":: %d %s %s awaiting image commit:\n", count, setupWord, verb)
	printAwaitingCommitPreview(awaitingCommit, awaitingCommitPromptPreviewLimit)
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "   Save %s to the project image before starting this VM?\n\n", questionSetup)
	fmt.Fprintf(os.Stderr, "   [c] commit   Save and continue\n")
	if awaitingCommitShowAvailable(awaitingCommit) {
		fmt.Fprintf(os.Stderr, "   [s] show     Show all\n")
	}
	fmt.Fprintf(os.Stderr, "   [d] discard  Forget %s awaiting image commit and continue\n", questionSetup)
	fmt.Fprintf(os.Stderr, "   [Enter] cancel\n\n")
	if awaitingCommitShowAvailable(awaitingCommit) {
		fmt.Fprintf(os.Stderr, "Action [c/s/d]: ")
	} else {
		fmt.Fprintf(os.Stderr, "Action [c/d]: ")
	}
}

func printAwaitingCommitImageIssueStartupPrompt(awaitingCommit []string, issue awaitingCommitProjectImageIssue) {
	count := len(awaitingCommit)
	setupWord := "setups"
	verb := "are"
	theseSetups := "these setups"
	if count == 1 {
		setupWord = "setup"
		verb = "is"
		theseSetups = "this setup"
	}

	fmt.Fprintf(os.Stderr, ":: %d %s %s awaiting image commit:\n", count, setupWord, verb)
	printAwaitingCommitPreview(awaitingCommit, awaitingCommitPromptPreviewLimit)
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "warning: the project image cannot be found.\n")
	fmt.Fprintf(os.Stderr, "  expected image: %s\n", issue.ExpectedProjectImage)
	fmt.Fprintf(os.Stderr, "  %s cannot be saved without rebuilding the project image\n\n", theseSetups)
	fmt.Fprintf(os.Stderr, "   [r] rebuild & commit  Rebuild from current base image and commit %s\n", theseSetups)
	fmt.Fprintf(os.Stderr, "   [d] discard           Forget %s awaiting image commit and continue\n", theseSetups)
	if awaitingCommitShowAvailable(awaitingCommit) {
		fmt.Fprintf(os.Stderr, "   [s] show              Show all\n")
	}
	fmt.Fprintf(os.Stderr, "   [Enter] cancel\n\n")
	if awaitingCommitShowAvailable(awaitingCommit) {
		fmt.Fprintf(os.Stderr, "Action [r/d/s]: ")
	} else {
		fmt.Fprintf(os.Stderr, "Action [r/d]: ")
	}
}

func printAwaitingCommitPreview(awaitingCommit []string, limit int) {
	if limit > len(awaitingCommit) {
		limit = len(awaitingCommit)
	}
	for _, setup := range awaitingCommit[:limit] {
		fmt.Fprintf(os.Stderr, "   - %s\n", storeScriptBaseNameFromPath(setup))
	}
	if remaining := len(awaitingCommit) - limit; remaining > 0 {
		fmt.Fprintf(os.Stderr, "   ... %d more\n", remaining)
	}
}

func cmdVMShellRunning(port string, presetDef *presetDefinition, runScript []byte, setupDefs []setupDefinition, root bool) error {
	if len(setupDefs) > 0 {
		if err := applySetupDefinitionsToVM(port, setupDefs); err != nil {
			return err
		}
	}
	if err := syncPresetSelection(presetDef); err != nil {
		return err
	}

	if len(runScript) > 0 {
		return runPresetInVM(port, runScript, root)
	}
	return execProjectShell(port, root)
}

func execProjectShell(port string, root bool) error {
	if !root {
		return execProjectSSH(port, false)
	}

	rootKeyPath, _, err := ensureRootSSHKey()
	if err != nil {
		return fmt.Errorf("prepare root SSH key: %w", err)
	}
	return withTemporaryRootAllowAllFirewallRule(port, rootKeyPath, func() error {
		if err := markCurrentProjectImageDirty("root-shell", "zaigr shell --root"); err != nil {
			return err
		}
		return runProjectSSH(port, true)
	})
}

func syncPresetSelection(presetDef *presetDefinition) error {
	if presetDef == nil {
		return nil
	}
	return storeWritePresetSelection(presetDef.Name, presetDef.Version)
}

func bootProjectVM(ram string, cpu string) (string, error) {
	logDebug("booting project VM", "store", storeDir(), "ram", ram, "cpu", cpu)
	if err := requireKVMAccess(); err != nil {
		return "", err
	}

	kernelPath, err := ensureKernel(false)
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(storeDir(), 0755); err != nil {
		return "", fmt.Errorf("create store dir: %w", err)
	}

	disk := storeDisk()
	if disk == "unknown" {
		disk = defaultDiskSize
	}
	if err := os.WriteFile(storeConfigPath(), []byte(fmt.Sprintf("disk=%s\n", disk)), 0644); err != nil {
		return "", fmt.Errorf("store default disk: %w", err)
	}

	imgPath, err := storeImagePath()
	if err != nil {
		return "", err
	}
	if projectImagePathOverrideForNextBoot != "" {
		if _, overrideErr := os.Stat(projectImagePathOverrideForNextBoot); overrideErr == nil {
			logInfo("using project image override for VM boot", "expected", imgPath, "image", projectImagePathOverrideForNextBoot)
			imgPath = projectImagePathOverrideForNextBoot
		} else if !os.IsNotExist(overrideErr) {
			return "", fmt.Errorf("stat project image override: %w", overrideErr)
		}
	}
	if _, err := os.Stat(imgPath); err != nil {
		steps, _ := storeCommittedSetups()
		failed, _ := storeFailedSetups()
		if len(failed) > 0 {
			return "", fmt.Errorf("project image not found; resolve failed setups and try again")
		}
		if len(steps) > 0 {
			return "", fmt.Errorf("project image cannot be found: %s", filepath.Base(imgPath))
		}
		fmt.Printf(":: No project image — creating from base (disk=%s) ...\n", disk)
		logInfo("building new project image from base", "image", imgPath, "disk", disk)
		wipPath := imgPath + ".wip"
		_ = os.Remove(wipPath)
		if err := buildImageFromBase(wipPath, disk); err != nil {
			_ = os.Remove(wipPath)
			return "", err
		}
		if err := os.Rename(wipPath, imgPath); err != nil {
			_ = os.Remove(wipPath)
			return "", fmt.Errorf("rename project image: %w", err)
		}
	}

	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		return "", fmt.Errorf("allocate SSH port: %w", err)
	}
	sshPort := fmt.Sprintf("%d", ln.Addr().(*net.TCPAddr).Port)
	_ = ln.Close()
	logDebug("project VM SSH port is available", "port", sshPort)
	if err := storeClearRuntimeState(); err != nil {
		return "", err
	}
	if err := storeEnsureRuntimeDir(); err != nil {
		return "", fmt.Errorf("create runtime dir: %w", err)
	}
	if err := currentProjectStore().ensureAgentStateDir(); err != nil {
		return "", err
	}
	if err := os.WriteFile(storeSSHPortPath(), []byte(sshPort), 0644); err != nil {
		return "", fmt.Errorf("store runtime ssh port: %w", err)
	}

	_, rootPubKey, err := ensureRootSSHKey()
	if err != nil {
		return "", fmt.Errorf("ensure root SSH key: %w", err)
	}

	qemuPath, err := exec.LookPath("qemu-system-x86_64")
	if err != nil {
		return "", fmt.Errorf("qemu not found: %w", err)
	}

	format := "qcow2"
	args := buildQEMUArgs(imgPath, kernelPath, format, false, ram, cpu, sshPort, rootPubKey, storeProjectHostname(), storeMonitorSockPath())
	diskSize := storeDisk()

	fmt.Printf(":: Booting VM (kernel=%s, rootfs=%s, ram=%sMB, cpu=%s, disk=%s)\n",
		filepath.Base(kernelPath), filepath.Base(imgPath), ram, cpu, diskSize)
	fmt.Printf(":: SSH: ssh -p %s user@localhost\n", sshPort)
	logInfo("starting qemu", "kernel", kernelPath, "image", imgPath, "port", sshPort, "monitor_sock", storeMonitorSockPath())

	serialLog, err := os.OpenFile(storeSerialLogPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return "", fmt.Errorf("open VM serial log: %w", err)
	}
	defer serialLog.Close()

	devNull, err := os.Open(os.DevNull)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", os.DevNull, err)
	}
	defer devNull.Close()

	cmd := exec.Command(qemuPath, args[1:]...)
	cmd.Stdin = devNull
	cmd.Stdout = serialLog
	cmd.Stderr = serialLog
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		_ = storeClearRuntimeState()
		return "", fmt.Errorf("start qemu: %w", err)
	}
	logInfo("qemu started", "pid", cmd.Process.Pid, "port", sshPort)

	return sshPort, nil
}

// execProjectSSH connects to the running VM over SSH.
func execProjectSSH(port string, root bool) error {
	args, err := projectSSHArgs(port, root)
	if err != nil {
		return err
	}
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		return fmt.Errorf("ssh not found: %w", err)
	}
	cleanup, err := writeShellSessionMarker(currentProjectStore(), os.Getpid(), root, port)
	if err != nil {
		return fmt.Errorf("track shell session: %w", err)
	}
	if err := syscall.Exec(sshPath, args, os.Environ()); err != nil {
		cleanup()
		return err
	}
	return nil
}

func runProjectSSH(port string, root bool) error {
	args, err := projectSSHArgs(port, root)
	if err != nil {
		return err
	}

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	cleanup, err := writeShellSessionMarker(currentProjectStore(), cmd.Process.Pid, root, port)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("track shell session: %w", err)
	}
	defer cleanup()
	return cmd.Wait()
}

func projectSSHArgs(port string, root bool) ([]string, error) {
	user := "user"
	keyPath := ""
	if root {
		user = "root"
		keyPath = filepath.Join(zaigDir(), "root-ssh.key")
		if _, err := os.Stat(keyPath); err != nil {
			return nil, fmt.Errorf("root SSH key not found: %s", keyPath)
		}
	}
	logInfo("executing interactive SSH session", "port", port, "user", user)

	args := append([]string{"ssh"},
		sshManagedOptions()...,
	)
	args = append(args,
		"-o", "AddressFamily=inet",
		"-o", sshConnectTimeoutOption,
		"-o", "PasswordAuthentication=no",
		"-o", "PubkeyAuthentication=yes",
		"-o", "PreferredAuthentications=publickey",
		"-o", "KbdInteractiveAuthentication=no",
		"-o", "ChallengeResponseAuthentication=no",
	)
	if keyPath != "" {
		args = append(args, "-i", keyPath)
	}
	args = append(args, "-p", port, fmt.Sprintf("%s@localhost", user))
	return args, nil
}

func buildQEMUArgs(imagePath, kernelPath, format string, snapshot bool, ram string, cpus string, sshPort string, rootPubKey string, vmHostname string, monitorSock string) []string {
	hostLaunchEpoch := time.Now().Unix()
	appendParts := []string{
		"console=ttyS0",
		"root=/dev/vda",
		"rw",
		"init=/usr/lib/systemd/systemd",
		"systemd.unit=multi-user.target",
		"panic=-1",
		"quiet",
		fmt.Sprintf("zaigr.host-epoch=%d", hostLaunchEpoch),
	}

	if rootPubKey != "" {
		encoded := base64.StdEncoding.EncodeToString([]byte(rootPubKey))
		appendParts = append(appendParts, fmt.Sprintf("zaigr.root-pubkey=%s", encoded))
	}

	if vmHostname != "" {
		appendParts = append(appendParts, fmt.Sprintf("zaigr.hostname=%s", vmHostname))
	}

	workspace, _ := os.Getwd()

	args := []string{
		"qemu-system-x86_64",
		"-M", "microvm,acpi=off,auto-kernel-cmdline=on,isa-serial=on",
		"-nodefaults",
		"-nographic",
		"-no-reboot",
		"-m", ram,
		"-smp", cpus,
		"-serial", "file:" + storeSerialLogPath(),
		"-kernel", kernelPath,
		"-drive", fmt.Sprintf("id=root,file=%s,format=%s,if=none", imagePath, format),
		"-device", "virtio-blk-device,drive=root",
		"-fsdev", fmt.Sprintf("local,id=workspace_dev,path=%s,security_model=none", workspace),
		"-device", "virtio-9p-device,fsdev=workspace_dev,mount_tag=workspace",
		"-fsdev", fmt.Sprintf("local,id=agent_state_dev,path=%s,security_model=none", currentProjectStore().agentStateDir()),
		"-device", "virtio-9p-device,fsdev=agent_state_dev,mount_tag=zaigr_agent_state",
		"-append", strings.Join(appendParts, " "),
		"-netdev", fmt.Sprintf("user,id=net0,ipv6=off,hostfwd=tcp::%s-:22", sshPort),
		"-device", "virtio-net-device,netdev=net0",
	}

	if snapshot {
		args = append(args, "-snapshot")
	}
	args = append(args, "-accel", "kvm", "-cpu", "host")
	args = append(args, "-qmp", "unix:"+monitorSock+",server,nowait")
	return args
}
