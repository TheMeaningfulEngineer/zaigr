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
	if stored := currentProjectStore().ram(); stored != "" {
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
	if stored := currentProjectStore().cpus(); stored != "" {
		return stored, "project", nil
	}
	return defaultVMCPUs, "default", nil
}

// resolveCPUs returns the CPU value and its source (flag, store, or default).
func resolveCPUs(flagValue string) (string, string) {
	if flagValue != "" {
		return flagValue, "cli"
	}
	if stored := currentProjectStore().cpus(); stored != "" {
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
	if stored := currentProjectStore().disk(); stored != "unknown" {
		return stored, "project"
	}
	return defaultDiskSize, "default"
}

// sshHostname returns the hostname of the running VM via SSH, or "" if unreachable.
func sshHostname(port string) string {
	logDebug("probing VM hostname over SSH", "port", port)
	if err := ensureUserSSHAccess(port); err != nil {
		logDebug("VM user SSH access preparation failed", "port", port, "err", err)
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	keyPath := userSSHKeyPath()
	args := append(sshManagedOptions(),
		"-o", "AddressFamily=inet",
		"-o", sshConnectTimeoutOption,
		"-o", "PasswordAuthentication=no",
		"-o", "PubkeyAuthentication=yes",
		"-o", "PreferredAuthentications=publickey",
		"-o", "KbdInteractiveAuthentication=no",
		"-o", "ChallengeResponseAuthentication=no",
		"-o", "IdentitiesOnly=yes",
		"-i", keyPath,
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
	logDebug("querying QMP image path", "sock", currentProjectStore().monitorSockPath())
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		logDebug("QMP deadline setup failed", "err", err)
		return ""
	}
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
		_ = conn.Close()
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
		_ = conn.Close()
	}
	logDebug("project VM metadata collected", "port", info.Port, "hostname", info.Hostname, "image", info.ImagePath)
	return info, false
}

func ensureProjectInitializedForVM(ram string, cpu string) error {
	store := currentProjectStore()
	storePath := store.Path
	initialized, err := isProjectInitialized(storePath)
	if err != nil {
		return err
	}
	if initialized {
		if _, err := store.firewallIPs(); err != nil {
			return err
		}
		if err := store.requireCurrentImageFormat("project VM startup"); err != nil {
			return err
		}
		if err := store.writeProjectPath(canonicalPath(".")); err != nil {
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
	if err := resolveProjectImageForCommand(); err != nil {
		return nil, err
	}

	running, stale := detectRunningProjectVM()
	if stale {
		store := currentProjectStore()
		_ = store.clearRuntimeState()
		logWarn("removed stale project VM monitor marker", "runtime_dir", store.runtimeDir())
		running = nil
	}

	hasOverrides := (ram != "") || (cpu != "")
	if running != nil {
		if hasOverrides {
			return nil, fmt.Errorf("project VM is already running; --ram and --cpu cannot be changed on a running VM")
		}
		logInfo("reusing running project VM", "port", running.Port)
		if err := syncAppliedSetupFirewallToVM(running.Port); err != nil {
			return nil, err
		}
		return running, nil
	}
	if err := offerProjectLocalSetupsBeforeBoot(ram, cpu); err != nil {
		return nil, err
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
	if err := ensureUserSSHAccess(imagePort); err != nil {
		return "", err
	}
	if err := syncAppliedSetupFirewallToVM(imagePort); err != nil {
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
	lock, err := lockCurrentProject("shell")
	if err != nil {
		return err
	}
	defer lock.releaseWithWarning()

	if err := requireNoActiveSetupCapture("zaigr shell"); err != nil {
		return err
	}

	presetDef, runScript, setupDefs, err := loadPresetPlan(preset, setups)
	if err != nil {
		return err
	}
	_, err = prepareProjectForVMStart(ram, cpu)
	if err != nil {
		return err
	}
	running, stale := detectRunningProjectVM()
	if stale {
		_ = currentProjectStore().clearRuntimeState()
		running = nil
	}

	if root && !confirmRootShellMarksDirtyProjectImage() {
		return exitError(1)
	}

	if running != nil {
		logDebug("shell will attach to existing project VM", "port", running.Port)
		filteredSetupDefs, skippedApplied, err := filterSetupDefinitionsByStoredState(setupDefs)
		if err != nil {
			return err
		}
		printSkippedAppliedSetups(skippedApplied)
		return cmdVMShellRunning(running.Port, presetDef, runScript, filteredSetupDefs, root)
	}

	filteredSetupDefs, skippedApplied, err := filterSetupDefinitionsByStoredState(setupDefs)
	if err != nil {
		return err
	}
	printSkippedAppliedSetups(skippedApplied)
	if len(filteredSetupDefs) > 0 {
		logInfo("applying setup definitions to image before boot", "count", len(filteredSetupDefs))
		if err := applySetupDefinitionsToImage(filteredSetupDefs, ram, cpu); err != nil {
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
		return runPresetInVM(imagePort, presetDef.Name, runScript)
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
	fmt.Fprintln(os.Stderr, "   Dirty means zaigr cannot recreate ad-hoc root changes from applied setups.")
	fmt.Fprintf(os.Stderr, "Continue with %s? [y/N] ", action)
	var answer string
	_, _ = fmt.Scanln(&answer)
	return strings.EqualFold(strings.TrimSpace(answer), "y") || strings.EqualFold(strings.TrimSpace(answer), "yes")
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
		return runPresetInVM(port, presetDef.Name, runScript)
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
	return currentProjectStore().writePresetSelection(presetDef.Name, presetDef.Version)
}

func bootProjectVM(ram string, cpu string) (string, error) {
	store := currentProjectStore()
	logDebug("booting project VM", "store", store.Path, "ram", ram, "cpu", cpu)
	if err := requireKVMAccess(); err != nil {
		return "", err
	}

	kernelPath, err := ensureKernel(false)
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(store.Path, 0755); err != nil {
		return "", fmt.Errorf("create store dir: %w", err)
	}

	disk := store.disk()
	if disk == "unknown" {
		disk = defaultDiskSize
	}
	if err := os.WriteFile(store.configPath(), []byte(fmt.Sprintf("disk=%s\n", disk)), 0644); err != nil {
		return "", fmt.Errorf("store default disk: %w", err)
	}

	imgPath := store.authoritativeImagePath()
	if projectImagePathOverrideForNextBoot != "" {
		if _, overrideErr := os.Stat(projectImagePathOverrideForNextBoot); overrideErr == nil {
			logInfo("using project image override for VM boot", "expected", imgPath, "image", projectImagePathOverrideForNextBoot)
			imgPath = projectImagePathOverrideForNextBoot
		} else if !os.IsNotExist(overrideErr) {
			return "", fmt.Errorf("stat project image override: %w", overrideErr)
		}
	}
	if _, err := os.Stat(imgPath); err != nil {
		return "", fmt.Errorf("project image cannot be found: %s", filepath.Base(imgPath))
	}

	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		return "", fmt.Errorf("allocate SSH port: %w", err)
	}
	sshPort := fmt.Sprintf("%d", ln.Addr().(*net.TCPAddr).Port)
	_ = ln.Close()
	logDebug("project VM SSH port is available", "port", sshPort)
	if err := store.clearRuntimeState(); err != nil {
		return "", err
	}
	if err := store.ensureRuntimeDir(); err != nil {
		return "", fmt.Errorf("create runtime dir: %w", err)
	}
	if err := store.ensureAgentStateDir(); err != nil {
		return "", err
	}
	if err := os.WriteFile(store.sshPortPath(), []byte(sshPort), 0644); err != nil {
		return "", fmt.Errorf("store runtime ssh port: %w", err)
	}

	_, rootPubKey, err := ensureRootSSHKey()
	if err != nil {
		return "", fmt.Errorf("ensure root SSH key: %w", err)
	}
	userKeyPath, userPubKey, err := ensureUserSSHKey()
	if err != nil {
		return "", fmt.Errorf("ensure user SSH key: %w", err)
	}

	qemuPath, err := exec.LookPath("qemu-system-x86_64")
	if err != nil {
		return "", fmt.Errorf("qemu not found: %w", err)
	}

	format := "qcow2"
	args := buildQEMUArgs(imgPath, kernelPath, format, false, ram, cpu, sshPort, rootPubKey, userPubKey, store.hostname(), store.monitorSockPath())
	diskSize := store.disk()

	fmt.Printf(":: Booting VM (kernel=%s, rootfs=%s, ram=%sMB, cpu=%s, disk=%s)\n",
		filepath.Base(kernelPath), filepath.Base(imgPath), ram, cpu, diskSize)
	fmt.Printf(":: SSH: ssh -i %s -p %s user@localhost\n", userKeyPath, sshPort)
	logInfo("starting qemu", "kernel", kernelPath, "image", imgPath, "port", sshPort, "monitor_sock", store.monitorSockPath())

	serialLog, err := os.OpenFile(store.serialLogPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return "", fmt.Errorf("open VM serial log: %w", err)
	}
	defer func() { _ = serialLog.Close() }()

	devNull, err := os.Open(os.DevNull)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", os.DevNull, err)
	}
	defer func() { _ = devNull.Close() }()

	cmd := exec.Command(qemuPath, args[1:]...)
	cmd.Stdin = devNull
	cmd.Stdout = serialLog
	cmd.Stderr = serialLog
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		_ = store.clearRuntimeState()
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
	keyPath := userSSHKeyPath()
	if root {
		user = "root"
		keyPath = rootSSHKeyPath()
	} else if err := ensureUserSSHAccess(port); err != nil {
		return nil, err
	}
	if _, err := os.Stat(keyPath); err != nil {
		return nil, fmt.Errorf("%s SSH key not found: %s", user, keyPath)
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
		"-o", "IdentitiesOnly=yes",
		"-i", keyPath,
	)
	args = append(args, "-p", port, fmt.Sprintf("%s@localhost", user))
	return args, nil
}

func buildQEMUArgs(imagePath, kernelPath, format string, snapshot bool, ram string, cpus string, sshPort string, rootPubKey string, userPubKey string, vmHostname string, monitorSock string) []string {
	return buildQEMUArgsWithAgentState(
		imagePath,
		kernelPath,
		format,
		snapshot,
		ram,
		cpus,
		sshPort,
		rootPubKey,
		userPubKey,
		vmHostname,
		monitorSock,
		currentProjectStore().agentStateDir(),
	)
}

func buildQEMUArgsWithAgentState(imagePath, kernelPath, format string, snapshot bool, ram string, cpus string, sshPort string, rootPubKey string, userPubKey string, vmHostname string, monitorSock string, agentStateDir string) []string {
	workspace, _ := os.Getwd()
	return buildQEMUArgsWithContext(imagePath, kernelPath, format, snapshot, ram, cpus, sshPort, rootPubKey, userPubKey, vmHostname, monitorSock, agentStateDir, workspace, currentProjectStore().serialLogPath())
}

func buildQEMUArgsWithContext(imagePath, kernelPath, format string, snapshot bool, ram string, cpus string, sshPort string, rootPubKey string, userPubKey string, vmHostname string, monitorSock string, agentStateDir string, workspace string, serialLog string) []string {
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
	if userPubKey != "" {
		encoded := base64.StdEncoding.EncodeToString([]byte(userPubKey))
		appendParts = append(appendParts, fmt.Sprintf("zaigr.user-pubkey=%s", encoded))
	}

	if vmHostname != "" {
		appendParts = append(appendParts, fmt.Sprintf("zaigr.hostname=%s", vmHostname))
	}

	args := []string{
		"qemu-system-x86_64",
		"-M", "microvm,acpi=off,auto-kernel-cmdline=on,isa-serial=on",
		"-nodefaults",
		"-nographic",
		"-no-reboot",
		"-m", ram,
		"-smp", cpus,
		"-serial", "file:" + serialLog,
		"-kernel", kernelPath,
		"-drive", fmt.Sprintf("id=root,file=%s,format=%s,if=none", imagePath, format),
		"-device", "virtio-blk-device,drive=root",
		"-fsdev", fmt.Sprintf("local,id=workspace_dev,path=%s,security_model=none", workspace),
		"-device", "virtio-9p-device,fsdev=workspace_dev,mount_tag=workspace",
		"-fsdev", fmt.Sprintf("local,id=agent_state_dev,path=%s,security_model=none", agentStateDir),
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
