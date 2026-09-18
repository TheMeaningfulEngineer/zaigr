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
)

const sshConnectTimeoutOption = "ConnectTimeout=5"
const setupExecutionTimeout = 30 * time.Minute
const setupExecutionStartedMarker = "__ZAIGR_SETUP_EXECUTION_STARTED__\n"

func sshManagedOptions() []string {
	return []string{
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "LogLevel=ERROR",
	}
}

func sshPresetOptions() []string {
	return []string{
		"-F", "/dev/null",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "LogLevel=ERROR",
		"-o", "ForwardAgent=no",
		"-o", "ForwardX11=no",
		"-o", "ClearAllForwardings=yes",
		"-o", "Tunnel=no",
		"-o", "PermitLocalCommand=no",
	}
}

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

func allocateEphemeralSSHPort() (string, error) {
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		return "", fmt.Errorf("allocate SSH port: %w", err)
	}
	port := fmt.Sprintf("%d", ln.Addr().(*net.TCPAddr).Port)
	_ = ln.Close()
	return port, nil
}

func applyStepsViaSSHWithIntent(imagePath string, steps []string, ram string, cpus string, sshPort string, rootFullNetwork bool, intent *directSetupExecutionIntent) error {
	return applyStepsViaSSHWithIntentAndAgentState(imagePath, steps, ram, cpus, sshPort, rootFullNetwork, intent, "")
}

func applyStepsViaSSHWithAgentState(imagePath string, steps []string, ram string, cpus string, sshPort string, rootFullNetwork bool, agentStateDir string) error {
	return applyStepsViaSSHWithIntentAndAgentState(imagePath, steps, ram, cpus, sshPort, rootFullNetwork, nil, agentStateDir)
}

func applyStepsViaSSHWithIntentAndAgentState(imagePath string, steps []string, ram string, cpus string, sshPort string, rootFullNetwork bool, intent *directSetupExecutionIntent, agentStateDir string) error {
	store := currentProjectStore()
	workspace, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("resolve workspace for image modification: %w", err)
	}
	return applyStepsViaSSHInContextWithIntent(imagePath, steps, ram, cpus, sshPort, rootFullNetwork, intent, agentStateDir, workspace, store)
}

func applyStepsViaSSHInContext(imagePath string, steps []string, ram string, cpus string, sshPort string, rootFullNetwork bool, agentStateDir string, workspace string, store projectStore) error {
	return applyStepsViaSSHInContextWithIntent(imagePath, steps, ram, cpus, sshPort, rootFullNetwork, nil, agentStateDir, workspace, store)
}

func applyStepsViaSSHInContextWithIntent(imagePath string, steps []string, ram string, cpus string, sshPort string, rootFullNetwork bool, intent *directSetupExecutionIntent, agentStateDir string, workspace string, store projectStore) error {
	logInfo("booting temporary VM to apply image steps", "image", imagePath, "step_count", len(steps), "port", sshPort)
	kernelPath, err := ensureKernel(false)
	if err != nil {
		return err
	}

	if ln, err := net.Listen("tcp", ":"+sshPort); err != nil {
		return fmt.Errorf("SSH port %s already in use — another VM is likely running", sshPort)
	} else {
		if err := ln.Close(); err != nil {
			return fmt.Errorf("release SSH port probe: %w", err)
		}
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
	monitorSock := filepath.Join(store.Path, "modify-vm.sock")
	var shortMonitorDir string
	if len(monitorSock) >= 100 {
		shortMonitorDir, err = os.MkdirTemp("", "zaigr-modify-qmp-*")
		if err != nil {
			return fmt.Errorf("create short QMP socket directory: %w", err)
		}
		defer func() { _ = os.RemoveAll(shortMonitorDir) }()
		monitorSock = filepath.Join(shortMonitorDir, "vm.sock")
	}
	_ = os.Remove(monitorSock)
	args := buildQEMUArgsWithContext(imagePath, kernelPath, "qcow2", false, ram, cpus, sshPort, rootPubKey, userPubKey, store.hostname(), monitorSock, agentStateDir, workspace, store.serialLogPath())

	fmt.Println(":: Booting image for modification ...")
	logDebug("starting qemu for image modification", "kernel", kernelPath, "image", imagePath, "monitor_sock", monitorSock)
	cmd := exec.Command(args[0], args[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	cmd.Stdin = nil
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start QEMU: %w", err)
	}
	processDone := make(chan error, 1)
	go func() {
		processDone <- cmd.Wait()
		close(processDone)
	}()
	interrupts := make(chan os.Signal, 1)
	var interrupted atomic.Bool
	signal.Notify(interrupts, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(interrupts)
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-interrupts:
			interrupted.Store(true)
			qmpQuit(monitorSock)
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
		case <-done:
		}
	}()
	defer func() {
		_ = sshSync(sshPort, rootKeyPath)
		stopImageModificationQEMU(cmd, monitorSock, processDone)
		_ = os.Remove(monitorSock)
	}()

	fmt.Println(":: Waiting for SSH ...")
	logDebug("waiting for image-modification VM SSH readiness", "port", sshPort, "timeout_sec", 60)
	if !waitForSSH(sshPort, 60) {
		_ = cmd.Process.Kill()
		return fmt.Errorf("VM did not become reachable via SSH within 60s")
	}
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
			started, err := sshRunSetupScriptUntil(sshPort, rootKeyPath, string(data), executionDeadline, stepIntent)
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
		fmt.Println(":: Setup execution has full network access")
		if err := withTemporaryRootAllowAllFirewallRule(sshPort, rootKeyPath, runSetupScripts); err != nil {
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
	if err := sshSync(sshPort, rootKeyPath); err != nil {
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

func stopImageModificationQEMU(cmd *exec.Cmd, monitorSock string, processDone <-chan error) {
	qmpQuit(monitorSock)
	select {
	case <-processDone:
		return
	case <-time.After(5 * time.Second):
	}
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	select {
	case <-processDone:
	case <-time.After(5 * time.Second):
		logWarn("temporary image-modification QEMU did not exit after kill", "monitor_sock", monitorSock)
	}
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

func waitForStableSSH(port string, timeoutSec int, consecutiveSuccesses int) bool {
	rootKeyPath := filepath.Join(zaigDir(), "root-ssh.key")
	logDebug("beginning stable SSH wait loop", "port", port, "timeout_sec", timeoutSec, "consecutive_successes", consecutiveSuccesses)
	successes := 0
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
		if cmd.Run() != nil {
			successes = 0
			continue
		}
		successes++
		if successes >= consecutiveSuccesses {
			logDebug("stable SSH wait loop succeeded", "port", port, "attempt", i+1)
			return true
		}
	}
	logWarn("stable SSH wait loop timed out", "port", port, "timeout_sec", timeoutSec)
	return false
}

func sshRunScript(port string, keyPath string, script string) error {
	cmd := sshRunScriptCommand(port, keyPath, "root", script)
	return cmd.Run()
}

func sshRunControlScript(port string, keyPath string, script string) error {
	cmd := sshRunScriptCommandWithOptions(sshPresetOptions(), port, keyPath, "root", script)
	cmd.Env = presetSSHEnvironment()
	return cmd.Run()
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

func sshRunSetupScriptUntil(port string, keyPath string, script string, deadline time.Time, intent *directSetupExecutionIntent) (bool, error) {
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
	args := append(sshManagedOptions(), "-o", sshConnectTimeoutOption)
	if keyPath != "" {
		args = append(args, "-i", keyPath)
	}
	args = append(
		args,
		"-p", port,
		"root@localhost",
		"timeout", "--signal=TERM", "--kill-after=10s", strconv.FormatInt(remoteSeconds, 10)+"s",
		"bash", "-eu",
	)
	cmd := exec.CommandContext(ctx, "ssh", args...)
	cmd.Stdin = strings.NewReader(script)
	startWriter := &setupExecutionStartWriter{destination: os.Stdout}
	cmd.Stdout = startWriter
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	flushErr := startWriter.flush()
	started := startWriter.started.Load()
	if err == nil && flushErr != nil {
		err = flushErr
	}
	if ctx.Err() != nil {
		return started, fmt.Errorf("setup execution timed out after %s", setupExecutionTimeout)
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		if exitErr.ExitCode() == 124 || (exitErr.ExitCode() == 137 && !time.Now().Before(deadline)) {
			return started, fmt.Errorf("setup execution timed out after %s", setupExecutionTimeout)
		}
		if exitErr.ExitCode() == 137 {
			return started, fmt.Errorf(
				"setup execution exited with status 137 before the %s timeout elapsed; the guest may have killed it due to low memory: %w",
				setupExecutionTimeout,
				err,
			)
		}
	}
	return started, err
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
	return sshRunScriptCommandWithOptions(sshManagedOptions(), port, keyPath, user, script)
}

func sshRunScriptCommandWithOptions(options []string, port string, keyPath string, user string, script string) *exec.Cmd {
	args := append([]string{}, options...)
	args = append(args, "-o", sshConnectTimeoutOption)
	keyPath = sshKeyPathForUser(keyPath, user)
	if keyPath != "" {
		args = append(args, "-o", "IdentitiesOnly=yes", "-i", keyPath)
	}
	args = append(args, "-p", port, user+"@localhost", "bash", "-eu")

	cmd := exec.Command("ssh", args...)
	cmd.Stdin = strings.NewReader(script)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd
}

func sshRunCommandWithExitStatus(port string, keyPath string, user string, command string) error {
	if user == "user" {
		if err := ensureUserSSHAccess(port); err != nil {
			return err
		}
	}
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

func ensureUserSSHAccess(port string) error {
	userKeyPath, userPubKey, err := ensureUserSSHKey()
	if err != nil {
		return fmt.Errorf("prepare user SSH key: %w", err)
	}
	if userSSHKeyWorks(port, userKeyPath) {
		return nil
	}

	rootKeyPath, _, err := ensureRootSSHKey()
	if err != nil {
		return fmt.Errorf("prepare root SSH key for legacy user access: %w", err)
	}
	runtimeKind, err := sshReadCommand(
		port,
		rootKeyPath,
		"root",
		"if test -x /usr/local/lib/zaigr/run-preset-isolated; then printf current; else printf legacy; fi",
	)
	if err != nil {
		return fmt.Errorf("inspect VM runtime for user SSH access: %w", err)
	}
	if strings.TrimSpace(string(runtimeKind)) != "legacy" {
		return fmt.Errorf("VM rejected the managed user SSH key")
	}

	encodedKey := base64.StdEncoding.EncodeToString([]byte(userPubKey))
	installCommand := "" +
		"for path in /etc/zaigr /etc/zaigr/ssh; do\n" +
		"  if test -L \"$path\" || { test -e \"$path\" && ! test -d \"$path\"; }; then\n" +
		"    printf 'unsafe legacy SSH migration path: %s\\n' \"$path\" >&2\n" +
		"    exit 1\n" +
		"  fi\n" +
		"done\n" +
		"install -d -o root -g root -m 0755 /etc/zaigr /etc/zaigr/ssh\n" +
		"key_tmp=\"$(mktemp /etc/zaigr/ssh/.user-authorized-keys.XXXXXX)\"\n" +
		"config_tmp=\"$(mktemp /etc/ssh/sshd_config.d/.00-zaigr-managed-keys.XXXXXX)\"\n" +
		"trap 'rm -f \"$key_tmp\" \"$config_tmp\"' EXIT\n" +
		"printf '%s' " + singleQuotedArg(encodedKey) + " | base64 -d > \"$key_tmp\"\n" +
		"chown root:root \"$key_tmp\"\n" +
		"chmod 0644 \"$key_tmp\"\n" +
		"mv -fT -- \"$key_tmp\" /etc/zaigr/ssh/user-authorized-keys\n" +
		"printf '%s\\n' " + singleQuotedArg(
		"AuthorizedKeysFile /etc/zaigr/ssh/%u-authorized-keys .ssh/authorized_keys .ssh/authorized_keys2",
	) + " > \"$config_tmp\"\n" +
		"chown root:root \"$config_tmp\"\n" +
		"chmod 0644 \"$config_tmp\"\n" +
		"mv -fT -- \"$config_tmp\" /etc/ssh/sshd_config.d/00-zaigr-managed-keys.conf\n" +
		"sshd -t\n" +
		"systemctl reload ssh\n" +
		"trap - EXIT"
	if err := sshRunCommandWithExitStatus(port, rootKeyPath, "root", installCommand); err != nil {
		return fmt.Errorf("install managed user SSH key in legacy VM: %w", err)
	}
	if !userSSHKeyWorks(port, userKeyPath) {
		return fmt.Errorf("legacy VM rejected the installed managed user SSH key")
	}
	logInfo("installed managed user SSH key in legacy project VM", "port", port)
	return nil
}

func userSSHKeyWorks(port string, keyPath string) bool {
	args := append(
		sshManagedOptions(),
		"-o", sshConnectTimeoutOption,
		"-o", "BatchMode=yes",
		"-o", "IdentitiesOnly=yes",
		"-i", keyPath,
		"-p", port,
		"user@localhost", "true",
	)
	return exec.Command("ssh", args...).Run() == nil
}

func sshRunCommandCommand(port string, keyPath string, user string, command string) *exec.Cmd {
	args := append(sshManagedOptions(), "-o", sshConnectTimeoutOption)
	keyPath = sshKeyPathForUser(keyPath, user)
	if keyPath != "" {
		args = append(args, "-o", "IdentitiesOnly=yes", "-i", keyPath)
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
	keyPath = sshKeyPathForUser(keyPath, user)
	if keyPath != "" {
		args = append(args, "-o", "IdentitiesOnly=yes", "-i", keyPath)
	}
	ssArgs := append(args, "-p", port, user+"@localhost", "bash -eu -c "+singleQuotedArg(command))
	cmd := exec.Command("ssh", ssArgs...)
	return cmd.Output()
}

func sshReadPresetCommand(port string, keyPath string, command string) ([]byte, error) {
	args := append(sshPresetOptions(), "-o", sshConnectTimeoutOption)
	args = append(args, "-o", "IdentitiesOnly=yes", "-i", keyPath)
	args = append(args, "-p", port, "root@localhost", "bash -eu -c "+singleQuotedArg(command))
	cmd := exec.Command("ssh", args...)
	cmd.Env = presetSSHEnvironment()
	return cmd.Output()
}

func presetSSHEnvironment() []string {
	path := os.Getenv("PATH")
	if path == "" {
		path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	}
	terminal := os.Getenv("TERM")
	if terminal == "" {
		terminal = "xterm-256color"
	}
	return []string{"PATH=" + path, "TERM=" + terminal}
}

func sshRunPresetCommand(port string, keyPath string, presetName string, script string) error {
	command, err := isolatedPresetCommand(presetName, script)
	if err != nil {
		return err
	}
	args := []string{
		"-tt",
	}
	args = append(args, sshPresetOptions()...)
	args = append(args, "-o", sshConnectTimeoutOption, "-o", "IdentitiesOnly=yes", "-i", keyPath)
	args = append(args, "-p", port, "root@localhost", command)

	cmd := exec.Command("ssh", args...)
	cmd.Env = presetSSHEnvironment()
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
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

func sshKeyPathForUser(keyPath string, user string) string {
	if keyPath == "" && user == "user" {
		return userSSHKeyPath()
	}
	return keyPath
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
