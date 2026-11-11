package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"zaigr/cmd/zaigr/vmssh"
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

// sshHostname returns the hostname of the running VM via its supervisor broker.
func sshHostname(endpoint vmControlEndpoint) string {
	logDebug("probing VM hostname over vsock broker", "vsock_cid", endpoint.VsockCID, "launch_id", endpoint.LaunchID)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var output strings.Builder
	err := vmssh.Run(ctx, endpoint.SocketPath, vmssh.Request{User: "user", Command: "hostname"}, nil, &output, io.Discard)
	if ctx.Err() != nil {
		logWarn("VM hostname probe timed out", "vsock_cid", endpoint.VsockCID)
		return ""
	}
	if err != nil {
		logDebug("VM hostname probe failed", "vsock_cid", endpoint.VsockCID, "err", err)
		return ""
	}
	hostname := strings.TrimSpace(output.String())
	logDebug("VM hostname probe succeeded", "vsock_cid", endpoint.VsockCID, "hostname", hostname)
	return hostname
}

// bootedImagePath asks the running QEMU which image it booted, or returns "".
func bootedImagePath(monitorSock string) string {
	conn, err := net.DialTimeout("unix", monitorSock, time.Second)
	if err != nil {
		return ""
	}
	defer func() { _ = conn.Close() }()
	return queryQMPImagePath(conn)
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
	Endpoint  vmControlEndpoint
	Hostname  string
	ImagePath string
}

// vmControlEndpoint identifies the guest control broker for one VM launch.
// The launch-specific socket name prevents an old endpoint from attaching to
// a later VM that reuses the same project runtime directory.
type vmControlEndpoint struct {
	SocketPath string
	LaunchID   string
	VsockCID   uint32
}

func vmControlSocketPath(socketDir, launchID string) string {
	if socketDir == "" {
		socketDir = vmSocketDir(launchID)
	}
	return filepath.Join(socketDir, "ssh.sock")
}

func vmControlEndpointForRecord(record vmSupervisorRecord) (vmControlEndpoint, error) {
	if record.LaunchID == "" || record.VsockCID < 3 || record.RuntimeDir == "" {
		return vmControlEndpoint{}, errors.New("VM supervisor record lacks control endpoint identity")
	}
	endpoint := vmControlEndpoint{
		SocketPath: vmControlSocketPath(record.SocketDir, record.LaunchID),
		LaunchID:   record.LaunchID,
		VsockCID:   record.VsockCID,
	}
	if len(endpoint.SocketPath) > 107 {
		return vmControlEndpoint{}, fmt.Errorf("VM control socket path exceeds Linux's 107-byte limit: %s", endpoint.SocketPath)
	}
	return endpoint, nil
}

func vmControlEndpointForStore(store projectStore) (vmControlEndpoint, error) {
	record, err := readVMSupervisorRecord(store)
	if err != nil {
		return vmControlEndpoint{}, fmt.Errorf("read VM control endpoint identity: %w", err)
	}
	if filepath.Clean(record.RuntimeDir) != filepath.Clean(store.runtimeDir()) {
		return vmControlEndpoint{}, errors.New("VM control endpoint runtime directory does not match project store")
	}
	return vmControlEndpointForRecord(record)
}

func detectRunningProjectVM() (*runningVMInfo, bool) {
	return detectRunningProjectVMInStore(currentProjectStore())
}

func detectRunningProjectVMInStore(store projectStore) (*runningVMInfo, bool) {
	sockPath := store.monitorSockPath()
	var endpoint vmControlEndpoint
	if record, err := readVMSupervisorRecord(store); err == nil {
		if !vmProcessIsLive(record.Supervisor) || !vmProcessIsLive(record.QEMU) {
			return nil, true
		}
		endpoint, err = vmControlEndpointForRecord(record)
		if err != nil {
			logWarn("project VM control endpoint is invalid", "err", err)
			return nil, true
		}
	} else if err != nil && !os.IsNotExist(err) {
		return nil, true
	}
	logDebug("probing project VM monitor socket", "sock", sockPath)
	conn, err := dialQMPMonitor(sockPath, time.Second)
	if err == nil {
		_ = conn.Close()
		if endpoint.SocketPath == "" {
			logWarn("project VM runtime state missing control endpoint", "runtime_dir", store.runtimeDir())
			return nil, true
		}
		logDebug("project VM monitor responded", "sock", sockPath, "vsock_cid", endpoint.VsockCID, "launch_id", endpoint.LaunchID)
		return &runningVMInfo{Endpoint: endpoint}, false
	}

	if _, statErr := os.Stat(sockPath); statErr == nil {
		logDebug("project VM monitor socket exists but did not respond", "store", store.Hash, "sock", sockPath, "err", err)
		return nil, true
	}

	logDebug("project VM monitor socket not present", "sock", sockPath)
	return nil, false
}

// dialQMPMonitor retries only EAGAIN from a full Unix-socket accept queue.
// Keep the original total probe bound so a paused or unresponsive QEMU does
// not make status checks wait longer than before.
func dialQMPMonitor(sockPath string, timeout time.Duration) (net.Conn, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, os.ErrDeadlineExceeded
		}
		conn, err := net.DialTimeout("unix", sockPath, remaining)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, err
		}
		pause := 10 * time.Millisecond
		remaining = time.Until(deadline)
		if remaining <= 0 {
			return nil, lastErr
		}
		if remaining < pause {
			pause = remaining
		}
		time.Sleep(pause)
	}
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
	info.Hostname = sshHostname(info.Endpoint)

	conn, err := net.DialTimeout("unix", store.monitorSockPath(), time.Second)
	if err == nil {
		info.ImagePath = queryQMPImagePath(conn)
		_ = conn.Close()
	}
	logDebug("project VM metadata collected", "vsock_cid", info.Endpoint.VsockCID, "hostname", info.Hostname, "image", info.ImagePath)
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
	if running, _ := detectRunningProjectVM(); running == nil {
		if err := requireHostPreflight("project VM start"); err != nil {
			return nil, err
		}
	}
	if err := ensureProjectInitializedForVM(ram, cpu); err != nil {
		return nil, err
	}
	if err := resolveProjectImageForCommand(); err != nil {
		return nil, err
	}

	running, stale := detectRunningProjectVM()
	if stale {
		store := currentProjectStore()
		if err := store.clearRuntimeState(); err != nil {
			return nil, err
		}
		logWarn("removed stale project VM monitor marker", "runtime_dir", store.runtimeDir())
		running = nil
	}
	if running != nil {
		record, readErr := readVMSupervisorRecord(currentProjectStore())
		if readErr != nil {
			return nil, readErr
		}
		stored := record.NetworkBackend
		if stored == "" {
			stored = vmNetworkBackendUser
		}
		if _, selectErr := selectVMNetworkBackend(vmNetworkBackendHost, stored); selectErr != nil {
			return nil, selectErr
		}
	}

	hasOverrides := (ram != "") || (cpu != "")
	if running != nil {
		if hasOverrides {
			return nil, fmt.Errorf("project VM is already running; --ram and --cpu cannot be changed on a running VM")
		}
		logInfo("reusing running project VM", "vsock_cid", running.Endpoint.VsockCID, "launch_id", running.Endpoint.LaunchID)
		if err := syncAppliedSetupFirewallToVM(running.Endpoint); err != nil {
			return nil, err
		}
		return running, nil
	}
	if err := offerProjectLocalSetupsBeforeBoot(ram, cpu); err != nil {
		return nil, err
	}

	return nil, nil
}

func projectHasPendingLocalSetups() (bool, error) {
	definitions, err := loadProjectLocalSetupDefinitions()
	if err != nil {
		return false, err
	}
	records, err := currentProjectStore().readAppliedSetups()
	if err != nil {
		return false, err
	}
	installed := make(map[string]appliedSetup, len(records))
	for _, r := range records {
		if r.ProjectLocal {
			installed[r.Name] = r
		}
	}
	for _, d := range definitions {
		r, ok := installed[d.Name]
		if !ok || r.Version != d.Version {
			return true, nil
		}
	}
	for _, r := range records {
		if !r.ProjectLocal || r.MissingAcknowledged {
			continue
		}
		found := false
		for _, d := range definitions {
			if d.Name == r.Name {
				found = true
				break
			}
		}
		if !found {
			return true, nil
		}
	}
	return false, nil
}

func runningHostNetworkRecord(store projectStore) (bool, vmSupervisorRecord, error) {
	record, err := readVMSupervisorRecord(store)
	if err != nil {
		return false, record, err
	}
	if record.NetworkBackend == "" {
		record.NetworkBackend = vmNetworkBackendUser
	}
	return record.NetworkBackend == vmNetworkBackendHost, record, nil
}

func startPreparedProjectVM(ram string, cpu string) (endpoint vmControlEndpoint, returnErr error) {
	store := currentProjectStore()
	hostLock := &projectMutationLock{}
	defer hostLock.releaseWithWarning()
	grants := hostAccessGrants{Version: hostAccessVersion, Ports: []hostAccessPort{}, Devices: []hostAccessDevice{}}
	// Capture-only VMs use an image override and must not receive project grants.
	if projectImagePathOverrideForNextBoot == "" {
		if err := hostLock.lockHostAccess(store, "project host-access startup"); err != nil {
			return vmControlEndpoint{}, err
		}
		var err error
		grants, err = store.hostAccess()
		if err != nil {
			return vmControlEndpoint{}, err
		}
	}
	ramValue, _ := resolveRAM(ram)
	cpuValue, _, err := resolveCPU(cpu)
	if err != nil {
		return vmControlEndpoint{}, err
	}
	logInfo("starting prepared project VM", "ram", ramValue, "cpu", cpuValue)
	backend := vmNetworkBackendHost
	var launch *vmLaunchHandle
	endpoint, launch, err = bootProjectVM(ramValue, cpuValue, grants)
	if err != nil {
		return vmControlEndpoint{}, err
	}
	committed := false
	defer func() {
		if !committed {
			returnErr = errors.Join(returnErr, launch.cancel())
		}
	}()
	logDebug("waiting for project VM guest readiness", "vsock_cid", endpoint.VsockCID, "timeout_sec", 90)
	if err := waitForVMGuestReady(launch, 90*time.Second); err != nil {
		return vmControlEndpoint{}, err
	}
	startupCtx, cancelStartup := launch.precommitContext()
	defer cancelStartup()
	logInfo("project VM control broker is ready", "vsock_cid", endpoint.VsockCID, "launch_id", endpoint.LaunchID)
	if backend == vmNetworkBackendHost {
		if err := applyHostNetworkGuestTransition(startupCtx, endpoint); err != nil {
			return vmControlEndpoint{}, hostTransitionError(err)
		}
	}
	if err := ensureUserSSHAccessContext(startupCtx, endpoint); err != nil {
		return vmControlEndpoint{}, err
	}
	if err := syncAppliedSetupFirewallToVMContext(startupCtx, endpoint); err != nil {
		return vmControlEndpoint{}, err
	}
	if err := startupCtx.Err(); err != nil {
		return vmControlEndpoint{}, fmt.Errorf("VM precommit startup deadline or supervisor exit: %w", err)
	}
	if err := launch.commit(); err != nil {
		return vmControlEndpoint{}, err
	}
	committed = true
	if projectImagePathOverrideForNextBoot == "" {
		if err := activateHostAccess(store, endpoint, grants, hostLock); err != nil {
			fmt.Fprintf(os.Stderr, "warning: VM started, but saved host-access activation is incomplete: %v; inspect with 'zaigr project host-access show'\n", err)
		}
	}
	return endpoint, nil
}

func cmdVMShell(ram string, cpu string, preset string, setups []string, root bool, fullNetwork bool) error {
	fmt.Printf(":: zaigr %s (%s/%s) built %s\n", version, runtime.GOOS, runtime.GOARCH, buildTime)
	logInfo("starting shell command", "preset", preset, "setup_count", len(setups), "root", root)
	if fullNetwork && !root {
		return fmt.Errorf("--full-network requires --root; network access is isolated to a root maintenance shell")
	}
	if fullNetwork && (preset != "" || len(setups) > 0) {
		return fmt.Errorf("--full-network cannot be combined with --preset or --setup")
	}

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
	showVMStopNotice(currentProjectStore())

	presetDef, runScript, setupDefs, err := loadPresetPlan(preset, setups)
	if err != nil {
		return err
	}
	_, err = prepareProjectForVMStart(ram, cpu)
	if err != nil {
		return err
	}
	if fullNetwork {
		if err := ensureMaintenanceNetworkProjectSafe(currentProjectStore()); err != nil {
			return err
		}
	}
	running, stale := detectRunningProjectVM()
	if stale {
		if err := currentProjectStore().clearRuntimeState(); err != nil {
			return err
		}
		running = nil
	}

	if root && !confirmRootShellMarksDirtyProjectImage() {
		return exitError(1)
	}

	if running != nil {
		logDebug("shell will attach to existing project VM", "vsock_cid", running.Endpoint.VsockCID, "launch_id", running.Endpoint.LaunchID)
		filteredSetupDefs, skippedApplied, err := filterSetupDefinitionsByStoredState(setupDefs)
		if err != nil {
			return err
		}
		printSkippedAppliedSetups(skippedApplied)
		run := func() error {
			return cmdVMShellRunning(running.Endpoint, presetDef, runScript, filteredSetupDefs, root, lock)
		}
		if fullNetwork {
			if err := markCurrentProjectImageDirty("root-shell", "zaigr shell --root --full-network"); err != nil {
				return err
			}
			return withMaintenanceNetworkSession(currentProjectStore(), running.Endpoint, "zaigr shell --root --full-network", func(namespace string) error {
				if err := lock.release(); err != nil {
					return fmt.Errorf("release project lock before maintenance shell: %w", err)
				}
				return runMaintenanceProjectSSH(running.Endpoint, namespace)
			})
		}
		return run()
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

	endpoint, err := startPreparedProjectVM(ram, cpu)
	if err != nil {
		return err
	}
	if err := syncPresetSelection(presetDef); err != nil {
		return err
	}
	run := func() error {
		if len(runScript) > 0 {
			logDebug("running preset script in project VM", "root", root)
			return runPresetInVM(endpoint, presetDef.Name, runScript)
		}
		if err := lock.release(); err != nil {
			return fmt.Errorf("release project startup lock before interactive shell: %w", err)
		}
		return execProjectShell(endpoint, root)
	}
	if fullNetwork {
		if err := markCurrentProjectImageDirty("root-shell", "zaigr shell --root --full-network"); err != nil {
			return err
		}
		return withMaintenanceNetworkSession(currentProjectStore(), endpoint, "zaigr shell --root --full-network", func(namespace string) error {
			if err := lock.release(); err != nil {
				return fmt.Errorf("release project lock before maintenance shell: %w", err)
			}
			return runMaintenanceProjectSSH(endpoint, namespace)
		})
	}
	return run()
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

func cmdVMShellRunning(endpoint vmControlEndpoint, presetDef *presetDefinition, runScript []byte, setupDefs []setupDefinition, root bool, lock *projectMutationLock) error {
	if len(setupDefs) > 0 {
		if err := applySetupDefinitionsToVM(endpoint, setupDefs); err != nil {
			return err
		}
	}
	if err := syncPresetSelection(presetDef); err != nil {
		return err
	}

	if len(runScript) > 0 {
		return runPresetInVM(endpoint, presetDef.Name, runScript)
	}
	if lock != nil {
		if err := lock.release(); err != nil {
			return fmt.Errorf("release project startup lock before interactive shell: %w", err)
		}
	}
	return execProjectShell(endpoint, root)
}

func execProjectShell(endpoint vmControlEndpoint, root bool) error {
	if !root {
		return runProjectSSH(endpoint, false)
	}

	_, _, err := ensureRootSSHKey()
	if err != nil {
		return fmt.Errorf("prepare root SSH key: %w", err)
	}
	if host, _, err := runningHostNetworkRecord(currentProjectStore()); err != nil {
		return err
	} else if host {
		if err := markCurrentProjectImageDirty("root-shell", "zaigr shell --root"); err != nil {
			return err
		}
		return runProjectSSH(endpoint, true)
	}
	if err := markCurrentProjectImageDirty("root-shell", "zaigr shell --root"); err != nil {
		return err
	}
	return runProjectSSH(endpoint, true)
}

func syncPresetSelection(presetDef *presetDefinition) error {
	if presetDef == nil {
		return nil
	}
	return currentProjectStore().writePresetSelection(presetDef.Name, presetDef.Version)
}

func bootProjectVM(ram string, cpu string, grants hostAccessGrants) (vmControlEndpoint, *vmLaunchHandle, error) {
	store := currentProjectStore()
	logDebug("booting project VM", "store", store.Path, "ram", ram, "cpu", cpu)
	if err := requireKVMAccess(); err != nil {
		return vmControlEndpoint{}, nil, err
	}

	kernelPath, err := ensureKernel(false)
	if err != nil {
		return vmControlEndpoint{}, nil, err
	}

	if err := os.MkdirAll(store.Path, 0755); err != nil {
		return vmControlEndpoint{}, nil, fmt.Errorf("create store dir: %w", err)
	}

	disk := store.disk()
	if disk == "unknown" {
		disk = defaultDiskSize
	}
	if err := os.WriteFile(store.configPath(), []byte(fmt.Sprintf("disk=%s\n", disk)), 0644); err != nil {
		return vmControlEndpoint{}, nil, fmt.Errorf("store default disk: %w", err)
	}

	imgPath := store.authoritativeImagePath()
	if projectImagePathOverrideForNextBoot != "" {
		if _, overrideErr := os.Stat(projectImagePathOverrideForNextBoot); overrideErr == nil {
			logInfo("using project image override for VM boot", "expected", imgPath, "image", projectImagePathOverrideForNextBoot)
			imgPath = projectImagePathOverrideForNextBoot
		} else if !os.IsNotExist(overrideErr) {
			return vmControlEndpoint{}, nil, fmt.Errorf("stat project image override: %w", overrideErr)
		}
	}
	if _, err := os.Stat(imgPath); err != nil {
		return vmControlEndpoint{}, nil, fmt.Errorf("project image cannot be found: %s", filepath.Base(imgPath))
	}
	if err := store.ensureAgentStateDir(); err != nil {
		return vmControlEndpoint{}, nil, err
	}

	_, rootPubKey, err := ensureRootSSHKey()
	if err != nil {
		return vmControlEndpoint{}, nil, fmt.Errorf("ensure root SSH key: %w", err)
	}
	_, userPubKey, err := ensureUserSSHKey()
	if err != nil {
		return vmControlEndpoint{}, nil, fmt.Errorf("ensure user SSH key: %w", err)
	}

	qemuPath, err := exec.LookPath("qemu-system-x86_64")
	if err != nil {
		return vmControlEndpoint{}, nil, fmt.Errorf("qemu not found: %w", err)
	}
	virtiofsdPath, err := ensureVirtiofsdWithWriter(false, io.Discard)
	if err != nil {
		return vmControlEndpoint{}, nil, fmt.Errorf("extract virtiofsd: %w", err)
	}
	workspace, err := os.Getwd()
	if err != nil {
		return vmControlEndpoint{}, nil, fmt.Errorf("resolve workspace export: %w", err)
	}
	launchID, err := newVMLaunchID()
	if err != nil {
		return vmControlEndpoint{}, nil, err
	}

	format := "qcow2"
	socketDir := vmSocketDir(launchID)
	workspaceSock := filepath.Join(socketDir, "workspace.sock")
	agentStateSock := filepath.Join(socketDir, "agent-state.sock")
	if err := validateHostNetworkExport(workspace, store.agentStateDir(), store.Path, zaigDir(), store.runtimeDir()); err != nil {
		return vmControlEndpoint{}, nil, err
	}
	diskSize := store.disk()

	guestUID, guestGID, err := readGuestIdentityFromImage(imgPath)
	if err != nil {
		return vmControlEndpoint{}, nil, err
	}
	spec := vmLaunchSpec{
		Store: store.Path, LogRoot: store.Path, RuntimeDir: store.runtimeDir(),
		MonitorSock: store.monitorSockPath(),
		// Virtiofs sockets bind in a short /tmp dir to stay under the kernel's
		// 108-byte sun_path limit regardless of how deep the store runtime
		// path is. The store runtime dir carries symlinks pointing at them so
		// `ls -la <store>/runtime/` keeps showing both sockets for debugging.
		WorkspaceSock:       workspaceSock,
		AgentStateSock:      agentStateSock,
		WorkspaceSockAlias:  store.workspaceVirtiofsSockPath(),
		AgentStateSockAlias: store.agentStateVirtiofsSockPath(),
		SocketDir:           socketDir,
		Workspace:           workspace,
		AgentState:          store.agentStateDir(), Virtiofsd: virtiofsdPath,
		SerialLog: store.serialLogPath(), RootSSHKeyPath: rootSSHKeyPath(), UserSSHKeyPath: userSSHKeyPath(), Mode: "detached",
		LaunchID: launchID, NetworkBackend: vmNetworkBackendHost, GuestUID: guestUID, GuestGID: guestGID,
		QEMUPath: qemuPath,
	}
	args := buildQEMUArgsWithContext(imgPath, kernelPath, format, false, ram, cpu, 3, rootPubKey, userPubKey, store.hostname(), store.monitorSockPath(), store.agentStateDir(), workspace, store.serialLogPath(), workspaceSock, agentStateSock)
	args = append(args, hostAccessQEMUDevices(grants)...)
	spec.QEMUArgs = args[1:]
	endpoint, launch, err := launchSupervisedVMWithCIDRetry(spec)
	if err != nil {
		return vmControlEndpoint{}, nil, err
	}
	fmt.Printf(":: Booting VM (kernel=%s, rootfs=%s, ram=%sMB, cpu=%s, disk=%s)\n",
		filepath.Base(kernelPath), filepath.Base(imgPath), ram, cpu, diskSize)
	logInfo("starting qemu", "kernel", kernelPath, "image", imgPath, "vsock_cid", endpoint.VsockCID, "launch_id", launchID, "monitor_sock", store.monitorSockPath())
	return endpoint, launch, nil
}

// execProjectSSH attaches an interactive shell through the launch-owned broker.
func execProjectSSH(endpoint vmControlEndpoint, root bool) error {
	return runProjectSSH(endpoint, root)
}

func runProjectSSH(endpoint vmControlEndpoint, root bool) error {
	user := "user"
	if root {
		user = "root"
	}
	cleanup, err := writeShellSessionMarker(currentProjectStore(), os.Getpid(), root, endpoint)
	if err != nil {
		return fmt.Errorf("track shell session: %w", err)
	}
	defer cleanup()
	err = vmssh.RunInteractive(context.Background(), endpoint.SocketPath, user, "", os.Stdin, os.Stdout, os.Stderr)
	showVMStopAfterSession(currentProjectStore(), err)
	return err
}

func runMaintenanceProjectSSH(endpoint vmControlEndpoint, namespace string) error {
	if !validHostPolicyScopeID(strings.TrimPrefix(namespace, "zaigr-maint-")) {
		return errors.New("invalid maintenance network namespace")
	}
	cleanup, err := writeShellSessionMarker(currentProjectStore(), os.Getpid(), true, endpoint)
	if err != nil {
		return fmt.Errorf("track maintenance shell session: %w", err)
	}
	defer cleanup()
	command := "ip netns exec " + singleQuotedArg(namespace) + " bash --login"
	err = vmssh.RunInteractive(context.Background(), endpoint.SocketPath, "root", command, os.Stdin, os.Stdout, os.Stderr)
	showVMStopAfterSession(currentProjectStore(), err)
	return err
}

func buildQEMUArgsWithContext(imagePath, kernelPath, format string, snapshot bool, ram string, cpus string, vsockCID uint32, rootPubKey string, userPubKey string, vmHostname string, monitorSock string, agentStateDir string, workspace string, serialLog string, workspaceSock string, agentStateSock string) []string {
	hostLaunchEpoch := time.Now().Unix()
	appendParts := []string{
		"console=ttyS0",
		"root=/dev/vda",
		"rw",
		"init=/usr/lib/systemd/systemd",
		"systemd.unit=multi-user.target",
		"systemd.ssh_auto=no",
		// The VM has no screen or keyboard and zaigr logs in over vsock, so
		// skip the console login prompts: getty@tty1, getty-static's tty2-6
		// and the generated serial-getty@ttyS0, which never starts here.
		"systemd.mask=getty.target",
		// The kernel has no module support and the image no modprobe, so
		// these always fail. e2scrub needs LVM, and root has no network for
		// apt outside maintenance sessions.
		"systemd.mask=modprobe@.service",
		"systemd.mask=systemd-modules-load.service",
		"systemd.mask=e2scrub_reap.service",
		"systemd.mask=e2scrub_all.timer",
		"systemd.mask=apt-daily.timer",
		"systemd.mask=apt-daily-upgrade.timer",
		"systemd.mask=dpkg-db-backup.timer",
		// Prepare the guest runtime during boot. Otherwise it waits for the
		// first vsock connection, which can't arrive until sysinit is done.
		"systemd.wants=zaigr-runtime-ready.service",
		// Keep the guest journal in memory. Flushing it to the project disk
		// held up every boot, and each boot's clock jump left a new 8 MB file
		// behind. zaigr's own VM logs stay on the host.
		"systemd.set_credential=journal.storage:volatile",
		// microvm has no ACPI or keyboard controller, so the kernel's default
		// restart methods hang. A triple fault resets the CPU at once, and
		// -no-reboot turns that reset into a QEMU exit, for both a guest
		// reboot and a panic.
		"reboot=t",
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

	netdev := "tap,id=net0,fd=3"
	maintenanceNetdev := "tap,id=maintenance,fd=4"
	args := []string{
		"qemu-system-x86_64",
		"-M", "microvm,acpi=off,auto-kernel-cmdline=on,isa-serial=on",
		"-nodefaults",
		"-nographic",
		"-no-reboot",
		"-m", ram,
		"-object", fmt.Sprintf("memory-backend-memfd,id=mem,size=%sM,share=on", ram),
		"-machine", "memory-backend=mem",
		"-smp", cpus,
		"-serial", "file:" + serialLog,
		"-kernel", kernelPath,
		"-drive", fmt.Sprintf("id=root,file=%s,format=%s,if=none", qemuOptionPath(imagePath), format),
		"-device", "virtio-blk-device,drive=root",
		"-chardev", fmt.Sprintf("socket,id=workspace_fs,path=%s,server=off", qemuOptionPath(workspaceSock)),
		"-device", "vhost-user-fs-device,chardev=workspace_fs,tag=workspace",
		"-chardev", fmt.Sprintf("socket,id=agent_state_fs,path=%s,server=off", qemuOptionPath(agentStateSock)),
		"-device", "vhost-user-fs-device,chardev=agent_state_fs,tag=zaigr_agent_state",
		"-append", strings.Join(appendParts, " "),
		"-netdev", netdev,
		"-device", "virtio-net-device,netdev=net0",
		"-netdev", maintenanceNetdev,
		"-device", "virtio-net-device,netdev=maintenance,mac=52:54:00:5a:47:52",
		"-device", fmt.Sprintf("vhost-vsock-device,guest-cid=%d", vsockCID),
	}

	if snapshot {
		args = append(args, "-snapshot")
	}
	args = append(args, "-accel", "kvm", "-cpu", "host")
	args = append(args, "-qmp", "unix:"+qemuOptionPath(monitorSock)+",server,nowait")
	return args
}

func qemuOptionPath(path string) string { return strings.ReplaceAll(path, ",", ",,") }
