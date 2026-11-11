package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"zaigr/cmd/zaigr/vmssh"
)

const setupExecutionTimeout = 30 * time.Minute
const setupExecutionStartedMarker = "__ZAIGR_SETUP_EXECUTION_STARTED__\n"

type guestSetupExecutionError struct {
	stepName string
	err      error
}

func (e *guestSetupExecutionError) Error() string { return e.err.Error() }
func (e *guestSetupExecutionError) Unwrap() error { return e.err }

func isGuestSetupExecutionError(err error) bool {
	var executionErr *guestSetupExecutionError
	return errors.As(err, &executionErr)
}

func guestSetupExecutionStep(err error) string {
	var executionErr *guestSetupExecutionError
	if errors.As(err, &executionErr) {
		return executionErr.stepName
	}
	return ""
}

func applyStepsViaSSHWithIntent(imagePath string, steps []string, ram string, cpus string, rootFullNetwork bool, intent *directSetupExecutionIntent) error {
	return applyStepsViaSSHWithIntentAndAgentState(imagePath, steps, ram, cpus, rootFullNetwork, intent, "")
}

func applyStepsViaSSHWithIntentAndAgentState(imagePath string, steps []string, ram string, cpus string, rootFullNetwork bool, intent *directSetupExecutionIntent, agentStateDir string) error {
	store := currentProjectStore()
	workspace, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("resolve workspace for image modification: %w", err)
	}
	return applyStepsViaSSHInContextWithIntent(imagePath, steps, ram, cpus, rootFullNetwork, intent, agentStateDir, workspace, store, store.Path)
}

func applyStepsViaSSHInContext(imagePath string, steps []string, ram string, cpus string, rootFullNetwork bool, agentStateDir string, workspace string, store projectStore, logRoot string) error {
	return applyStepsViaSSHInContextWithIntent(imagePath, steps, ram, cpus, rootFullNetwork, nil, agentStateDir, workspace, store, logRoot)
}

func applyStepsViaSSHInContextWithIntent(imagePath string, steps []string, ram string, cpus string, rootFullNetwork bool, intent *directSetupExecutionIntent, agentStateDir string, workspace string, store projectStore, logRoot string) (returnErr error) {
	logInfo("booting temporary VM to apply image steps", "image", imagePath, "step_count", len(steps))
	kernelPath, err := ensureKernel(false)
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

	rootKeyPath := filepath.Join(zaigDir(), "root-ssh.key")

	if err := os.MkdirAll(store.Path, 0755); err != nil {
		return fmt.Errorf("create store dir for image modification: %w", err)
	}
	if agentStateDir == "" {
		if err := store.ensureAgentStateDir(); err != nil {
			return err
		}
		agentStateDir = store.agentStateDir()
	} else {
		info, err := os.Lstat(agentStateDir)
		if err != nil {
			return fmt.Errorf("inspect staged agent state: %w", err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("staged agent state is not a directory: %s", agentStateDir)
		}
	}
	runtimeDir, err := os.MkdirTemp("", "zaigr-vm-*")
	if err != nil {
		return fmt.Errorf("create temporary VM runtime: %w", err)
	}
	defer func() {
		if returnErr == nil {
			_ = os.RemoveAll(runtimeDir)
		}
	}()
	runtimeStore := store
	var stagedStoreDir string
	stagedAgentStateSource := agentStateDir
	defer func() {
		if stagedStoreDir == "" {
			return
		}
		if guardErr := requireNoActiveVMSupervisor(runtimeStore, "temporary host policy store cleanup"); guardErr != nil {
			returnErr = errors.Join(returnErr, guardErr)
			return
		}
		if cleanupErr := os.RemoveAll(stagedStoreDir); cleanupErr != nil {
			returnErr = errors.Join(returnErr, cleanupErr)
		}
	}()
	if agentStateDir != "" && filepath.Clean(agentStateDir) != filepath.Clean(store.agentStateDir()) {
		stagedStoreDir, err = os.MkdirTemp("", "zaigr-vm-policy-store-*")
		if err != nil {
			return fmt.Errorf("create staged host policy store: %w", err)
		}
		runtimeStore = projectStore{Hash: "temporary-build", Path: stagedStoreDir}
		for _, name := range []string{"firewall", "firewall-ips", projectFirewallDomainsFile} {
			data, readErr := readProtectedHostPolicyFile(store.Path, name)
			if readErr != nil {
				return readErr
			}
			if len(data) > 0 {
				if err := writeProtectedHostPolicyFile(stagedStoreDir, name, data); err != nil {
					return err
				}
			}
		}
		agentStateDir = runtimeStore.agentStateDir()
		if err := copyRebuildAgentState(stagedAgentStateSource, agentStateDir); err != nil {
			return err
		}
	}
	monitorSock := filepath.Join(runtimeDir, "vm.sock")
	var workspaceSock string
	var agentStateSock string
	serialLog := filepath.Join(logRoot, "vm-serial.log")
	vsockCID := uint32(3) // launchSupervisedVMWithCIDRetry selects the actual CID.
	qemuPath, err := exec.LookPath("qemu-system-x86_64")
	if err != nil {
		return fmt.Errorf("qemu not found: %w", err)
	}
	virtiofsdPath, err := ensureVirtiofsdWithWriter(false, io.Discard)
	if err != nil {
		return err
	}
	launchID, err := newVMLaunchID()
	if err != nil {
		return err
	}
	socketDir := vmSocketDir(launchID)
	workspaceSock = filepath.Join(socketDir, "workspace.sock")
	agentStateSock = filepath.Join(socketDir, "agent-state.sock")
	args := buildQEMUArgsWithContext(imagePath, kernelPath, "qcow2", false, ram, cpus, vsockCID, rootPubKey, userPubKey, store.hostname(), monitorSock, agentStateDir, workspace, serialLog, workspaceSock, agentStateSock)
	guestUID, guestGID, err := readGuestIdentityFromImage(imagePath)
	if err != nil {
		return err
	}
	spec := vmLaunchSpec{
		Store: runtimeStore.Path, LogRoot: logRoot, RuntimeDir: runtimeDir, SocketDir: socketDir,
		MonitorSock: monitorSock, WorkspaceSock: workspaceSock, AgentStateSock: agentStateSock,
		Workspace: workspace, AgentState: agentStateDir, Virtiofsd: virtiofsdPath,
		SerialLog: serialLog, VsockCID: vsockCID, RootSSHKeyPath: rootKeyPath, UserSSHKeyPath: userSSHKeyPath(), Mode: "attached", LaunchID: launchID,
		NetworkBackend: vmNetworkBackendHost, GuestUID: guestUID, GuestGID: guestGID, QEMUPath: qemuPath, QEMUArgs: args[1:],
	}

	fmt.Println(":: Booting image for modification ...")
	logDebug("starting qemu for image modification", "kernel", kernelPath, "image", imagePath, "monitor_sock", monitorSock)
	var endpoint vmControlEndpoint
	var launch *vmLaunchHandle
	endpoint, launch, err = launchSupervisedVMWithCIDRetry(spec)
	if err != nil {
		return err
	}
	interrupts := make(chan os.Signal, 1)
	var interrupted atomic.Bool
	signal.Notify(interrupts, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(interrupts)
	done := make(chan struct{})
	interruptCleanup := make(chan error, 1)
	defer close(done)
	go func() {
		select {
		case <-interrupts:
			interrupted.Store(true)
			interruptCleanup <- launch.cancel()
		case <-done:
		}
	}()
	committed := false
	defer func() {
		if committed {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			returnErr = errors.Join(returnErr, sshSyncContext(ctx, endpoint))
			cancel()
			exited := shutDownGuest(endpoint, func(timeout time.Duration) bool {
				select {
				case <-launch.exited:
					return true
				case <-time.After(timeout):
					return false
				}
			})
			if !exited {
				qmpQuit(monitorSock)
			}
			returnErr = errors.Join(returnErr, launch.stop())
		} else {
			returnErr = errors.Join(returnErr, launch.cancel())
		}
		if interrupted.Load() {
			returnErr = errors.Join(returnErr, <-interruptCleanup)
		}
	}()

	fmt.Println(":: Waiting for guest vsock ...")
	logDebug("waiting for image-modification VM SSH readiness", "vsock_cid", endpoint.VsockCID, "timeout_sec", 60)
	if err := waitForVMGuestReady(launch, 60*time.Second); err != nil {
		return err
	}
	if err := launch.commit(); err != nil {
		return err
	}
	committed = true
	executionStarted := false
	executionDeadline := time.Now().Add(setupExecutionTimeout)
	runSetupScripts := func() error {
		for i, step := range steps {
			stepName := filepath.Base(step)
			logInfo("applying image step", "index", i+1, "total", len(steps), "step", stepName)
			fmt.Printf(":: Applying step %d/%d: %s\n", i+1, len(steps), stepName)
			data, err := os.ReadFile(step)
			if err != nil {
				err = fmt.Errorf("read step %s: %w", stepName, err)
				if executionStarted {
					return &guestSetupExecutionError{stepName: stepName, err: err}
				}
				return err
			}
			stepIntent := intent
			if executionStarted {
				stepIntent = nil
			}
			started, err := sshRunSetupScriptUntil(endpoint, string(data), executionDeadline, stepIntent)
			if started {
				executionStarted = true
			}
			if stepIntent != nil {
				persisted, intentErr := store.setupExecutionIntentPersisted(*stepIntent)
				if persisted {
					executionStarted = true
				}
				if intentErr != nil {
					err = errors.Join(err, intentErr)
				}
			}
			if err != nil {
				err = fmt.Errorf("step %s failed: %w", stepName, err)
				if executionStarted {
					return &guestSetupExecutionError{stepName: stepName, err: err}
				}
				return err
			}
		}

		fmt.Println(":: All scripts finished")
		return nil
	}

	if rootFullNetwork {
		if err := withFullNetworkLeaseForRuntime(runtimeDir, launchID, "setup execution", "WARNING: Setup execution temporarily grants every process in the dedicated image-building VM broad IPv4 TCP/UDP access, including private networks and host data services. This does not grant network access to an ordinary project VM session.", runSetupScripts); err != nil {
			if executionStarted && !isGuestSetupExecutionError(err) {
				stepName := ""
				if len(steps) > 0 {
					stepName = filepath.Base(steps[len(steps)-1])
				}
				return &guestSetupExecutionError{stepName: stepName, err: err}
			}
			return err
		}
	} else {
		if err := runSetupScripts(); err != nil {
			return err
		}
	}
	if err := sshSync(endpoint); err != nil {
		stepName := ""
		if len(steps) > 0 {
			stepName = filepath.Base(steps[len(steps)-1])
		}
		err = fmt.Errorf("confirm setup changes: %w", err)
		if executionStarted {
			return &guestSetupExecutionError{stepName: stepName, err: err}
		}
		return err
	}
	if interrupted.Load() {
		return fmt.Errorf("image modification interrupted")
	}
	return nil
}

func waitForStableSSHContext(ctx context.Context, endpoint vmControlEndpoint, consecutiveSuccesses int) bool {
	logDebug("beginning stable SSH wait loop", "vsock_cid", endpoint.VsockCID, "consecutive_successes", consecutiveSuccesses)
	successes := 0
	for i := 0; ctx.Err() == nil; i++ {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(time.Second):
		}
		if runVMGuestCommand(ctx, endpoint, "root", "true", nil, io.Discard, io.Discard) != nil {
			successes = 0
			continue
		}
		successes++
		if successes >= consecutiveSuccesses {
			logDebug("stable SSH wait loop succeeded", "vsock_cid", endpoint.VsockCID, "attempt", i+1)
			return true
		}
	}
	logWarn("stable SSH wait loop timed out", "vsock_cid", endpoint.VsockCID)
	return false
}

func sshRunScript(endpoint vmControlEndpoint, script string) error {
	return runVMGuestCommand(context.Background(), endpoint, "root", "bash -eu", strings.NewReader(script), os.Stdout, os.Stderr)
}

func sshRunControlScriptContext(ctx context.Context, endpoint vmControlEndpoint, script string) error {
	return runVMGuestCommand(ctx, endpoint, "root", "bash -eu", strings.NewReader(script), os.Stdout, os.Stderr)
}

type setupExecutionStartWriter struct {
	destination io.Writer
	pending     []byte
	resolved    bool
	started     atomic.Bool
}

func (writer *setupExecutionStartWriter) Write(data []byte) (int, error) {
	inputLength := len(data)
	if writer.resolved {
		_, err := writer.destination.Write(data)
		return inputLength, err
	}
	writer.pending = append(writer.pending, data...)
	marker := []byte(setupExecutionStartedMarker)
	if len(writer.pending) < len(marker) && bytes.HasPrefix(marker, writer.pending) {
		return inputLength, nil
	}

	output := writer.pending
	if bytes.HasPrefix(writer.pending, marker) {
		writer.started.Store(true)
		output = writer.pending[len(marker):]
	}
	writer.pending = nil
	writer.resolved = true
	if len(output) == 0 {
		return inputLength, nil
	}
	written, err := writer.destination.Write(output)
	if err == nil && written != len(output) {
		err = io.ErrShortWrite
	}
	return inputLength, err
}

func (writer *setupExecutionStartWriter) flush() error {
	if writer.resolved || len(writer.pending) == 0 {
		return nil
	}
	writer.resolved = true
	written, err := writer.destination.Write(writer.pending)
	if err == nil && written != len(writer.pending) {
		err = io.ErrShortWrite
	}
	writer.pending = nil
	return err
}

func sshRunSetupScriptUntil(endpoint vmControlEndpoint, script string, deadline time.Time, intent *directSetupExecutionIntent) (bool, error) {
	return sshRunSetupScriptInNamespaceUntil(endpoint, "", script, deadline, intent)
}

func sshRunSetupScriptInNamespaceUntil(endpoint vmControlEndpoint, namespace string, script string, deadline time.Time, intent *directSetupExecutionIntent) (bool, error) {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return false, fmt.Errorf("setup execution timed out after %s", setupExecutionTimeout)
	}
	prelude := ""
	if intent != nil {
		var err error
		prelude, err = setupExecutionIntentPrelude(*intent)
		if err != nil {
			return false, fmt.Errorf("prepare setup execution intent: %w", err)
		}
	}
	script = prelude + "printf '" + strings.TrimSuffix(setupExecutionStartedMarker, "\n") + "\\n'\n" + script
	remoteSeconds := int64((remaining + time.Second - 1) / time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), remaining+15*time.Second)
	defer cancel()
	remote := "timeout --signal=TERM --kill-after=10s " + strconv.FormatInt(remoteSeconds, 10) + "s bash -eu"
	if namespace != "" {
		if !validHostPolicyScopeID(strings.TrimPrefix(namespace, "zaigr-maint-")) {
			return false, errors.New("invalid maintenance namespace")
		}
		remote = "ip netns exec " + singleQuotedArg(namespace) + " " + remote
	}
	startWriter := &setupExecutionStartWriter{destination: os.Stdout}
	err := runVMGuestCommand(ctx, endpoint, "root", remote, strings.NewReader(script), startWriter, os.Stderr)
	flushErr := startWriter.flush()
	started := startWriter.started.Load()
	if err == nil && flushErr != nil {
		err = flushErr
	}
	if ctx.Err() != nil {
		return started, fmt.Errorf("setup execution timed out after %s", setupExecutionTimeout)
	}
	var exitErr *vmssh.ExitError
	if errors.As(err, &exitErr) {
		if exitErr.Status == 124 || (exitErr.Status == 137 && !time.Now().Before(deadline)) {
			return started, fmt.Errorf("setup execution timed out after %s", setupExecutionTimeout)
		}
		if exitErr.Status == 137 {
			return started, fmt.Errorf(
				"setup execution exited with status 137 before the %s timeout elapsed; the guest may have killed it due to low memory: %w",
				setupExecutionTimeout,
				err,
			)
		}
	}
	return started, err
}

func sshSync(endpoint vmControlEndpoint) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return sshSyncContext(ctx, endpoint)
}

func sshSyncContext(ctx context.Context, endpoint vmControlEndpoint) error {
	return runVMGuestCommand(ctx, endpoint, "root", "sync", nil, io.Discard, io.Discard)
}

// cleanGuestShutdownTimeout bounds how long a stop waits for the guest to stop
// its services and unmount its disk before quitting QEMU instead.
const cleanGuestShutdownTimeout = 20 * time.Second

// shutDownGuest asks the guest to shut down cleanly and waits for QEMU to exit.
// The guest reboots, and the reboot=t kernel option with QEMU's -no-reboot
// turns that into a QEMU exit. It returns false when the guest didn't shut
// down; the caller then quits QEMU, and its earlier sync has kept the data.
func shutDownGuest(endpoint vmControlEndpoint, waitForExit func(time.Duration) bool) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// A VM started by an older zaigr lacks reboot=t, and its reboot would hang
	// instead of ending QEMU, so it gets the quit right away.
	err := runVMGuestCommand(ctx, endpoint, "root", "grep -qw reboot=t /proc/cmdline && systemctl --no-block reboot", nil, io.Discard, io.Discard)
	var status *vmssh.ExitError
	if errors.As(err, &status) {
		logDebug("guest declined a clean shutdown", "exit_status", status.Status)
		return false
	}
	if err != nil {
		// The guest may close the connection while shutting down; whether
		// QEMU exits tells.
		logDebug("guest shutdown request ended without a status", "error", err)
	}
	if waitForExit(cleanGuestShutdownTimeout) {
		return true
	}
	fmt.Fprintf(os.Stderr, "warning: the VM did not shut down within %s; stopping it now\n", cleanGuestShutdownTimeout)
	return false
}

func sshRunCommandWithExitStatus(endpoint vmControlEndpoint, user string, command string) error {
	return sshRunCommandWithExitStatusContext(context.Background(), endpoint, user, command)
}

func sshRunCommandWithExitStatusContext(ctx context.Context, endpoint vmControlEndpoint, user string, command string) error {
	err := runVMGuestUserCommand(ctx, endpoint, user, "bash -eu -c "+singleQuotedArg(command), os.Stdin, os.Stdout, os.Stderr)
	return vmSSHExitError(err)
}

func ensureUserSSHAccess(endpoint vmControlEndpoint) error {
	return ensureUserSSHAccessContext(context.Background(), endpoint)
}

func ensureUserSSHAccessContext(ctx context.Context, endpoint vmControlEndpoint) error {
	if err := runVMGuestCommand(ctx, endpoint, "user", "true", nil, io.Discard, io.Discard); err != nil {
		return fmt.Errorf("user SSH identity is unavailable; stop the VM and run 'zaigr project rebuild': %w", err)
	}
	return nil
}

func sshReadCommand(endpoint vmControlEndpoint, user string, command string) ([]byte, error) {
	return sshReadCommandContext(context.Background(), endpoint, user, command)
}

func sshReadCommandContext(ctx context.Context, endpoint vmControlEndpoint, user string, command string) ([]byte, error) {
	var output bytes.Buffer
	err := runVMGuestCommand(ctx, endpoint, user, "bash -eu -c "+singleQuotedArg(command), nil, &output, io.Discard)
	return output.Bytes(), err
}

func sshReadPresetCommand(endpoint vmControlEndpoint, command string) ([]byte, error) {
	return sshReadCommand(endpoint, "root", command)
}

func sshRunPresetCommand(endpoint vmControlEndpoint, presetName string, script string) error {
	command, err := isolatedPresetCommand(presetName, script)
	if err != nil {
		return err
	}
	return runVMGuestInteractive(context.Background(), endpoint, "root", command, os.Stdin)
}

func isolatedPresetCommand(presetName string, script string) (string, error) {
	encodedName := base64.StdEncoding.EncodeToString([]byte(presetName))
	encodedScript := base64.StdEncoding.EncodeToString([]byte(script))
	rootKeyGuestPath, err := guestWorkspacePathForHostPath(rootSSHKeyPath())
	if err != nil {
		return "", fmt.Errorf("locate root SSH credential in workspace: %w", err)
	}
	userKeyGuestPath, err := guestWorkspacePathForHostPath(userSSHKeyPath())
	if err != nil {
		return "", fmt.Errorf("locate user SSH credential in workspace: %w", err)
	}
	agentStateGuestPath, err := guestWorkspacePathForHostPath(currentProjectStore().agentStateDir())
	if err != nil {
		return "", fmt.Errorf("locate agent state in workspace: %w", err)
	}
	zaigrControlGuestPath, err := guestWorkspacePathForHostPath(zaigDir())
	if err != nil {
		return "", fmt.Errorf("locate Zaigr control state in workspace: %w", err)
	}
	return "/usr/local/lib/zaigr/run-preset-isolated " +
		encodedName + " " + encodedScript + " " +
		encodedOptionalArgument(rootKeyGuestPath) + " " +
		encodedOptionalArgument(userKeyGuestPath) + " " +
		encodedOptionalArgument(agentStateGuestPath) + " " +
		encodedOptionalArgument(zaigrControlGuestPath), nil
}

func guestWorkspacePathForHostPath(hostPath string) (string, error) {
	workspace, err := os.Getwd()
	if err != nil {
		return "", err
	}
	workspace, err = filepath.EvalSymlinks(workspace)
	if err != nil {
		return "", err
	}
	hostPath, err = filepath.EvalSymlinks(hostPath)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(workspace, hostPath)
	if err != nil {
		return "", err
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) || filepath.IsAbs(relative) {
		return "", nil
	}
	return filepath.Join("/home/user/workspace", relative), nil
}

func encodedOptionalArgument(value string) string {
	if value == "" {
		return "-"
	}
	return base64.StdEncoding.EncodeToString([]byte(value))
}

func singleQuotedArg(text string) string {
	return "'" + strings.ReplaceAll(text, "'", "'\"'\"'") + "'"
}

func qmpQuit(sockPath string) {
	conn, err := net.DialTimeout("unix", sockPath, 2*time.Second)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return
	}

	buf := make([]byte, 4096)
	if _, err := conn.Read(buf); err != nil {
		return
	}
	if _, err := conn.Write([]byte(`{"execute":"qmp_capabilities"}` + "\n")); err != nil {
		return
	}
	if _, err := conn.Read(buf); err != nil {
		return
	}
	if _, err := conn.Write([]byte(`{"execute":"quit"}` + "\n")); err != nil {
		return
	}
	_, _ = conn.Read(buf)
}
