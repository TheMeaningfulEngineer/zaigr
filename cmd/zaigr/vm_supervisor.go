package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
	"zaigr/cmd/zaigr/hostnet"
	"zaigr/cmd/zaigr/vmssh"
)

type vmOwnedProcess struct {
	PID          int    `json:"pid"`
	StartTime    string `json:"start_time"`
	ProcessGroup int    `json:"process_group"`
	ExeDevice    uint64 `json:"exe_device"`
	ExeInode     uint64 `json:"exe_inode"`
}

type vmExecutableIdentity struct {
	Device uint64
	Inode  uint64
}

type vmSupervisorRecord struct {
	VirtiofsSandbox      string                    `json:"virtiofs_sandbox,omitempty"`
	FormatVersion        int                       `json:"format_version"`
	VsockCID             uint32                    `json:"vsock_cid,omitempty"`
	LaunchID             string                    `json:"launch_id"`
	Mode                 string                    `json:"mode"`
	NetworkBackend       string                    `json:"network_backend,omitempty"`
	RuntimeDir           string                    `json:"runtime_dir"`
	SocketDir            string                    `json:"socket_dir,omitempty"`
	Supervisor           vmOwnedProcess            `json:"supervisor"`
	QEMU                 vmOwnedProcess            `json:"qemu,omitempty"`
	WorkspaceDaemon      vmOwnedProcess            `json:"workspace_daemon,omitempty"`
	AgentStateDaemon     vmOwnedProcess            `json:"agent_state_daemon,omitempty"`
	WorkspaceDescendant  vmOwnedProcess            `json:"workspace_descendant,omitempty"`
	AgentStateDescendant vmOwnedProcess            `json:"agent_state_descendant,omitempty"`
	SSHBroker            vmOwnedProcess            `json:"ssh_broker,omitempty"`
	NetworkGeneration    uint64                    `json:"network_generation,omitempty"`
	NetworkProcesses     map[string]vmOwnedProcess `json:"network_processes,omitempty"`
}

type vmLaunchSpec struct {
	PrecommitDeadlineUnixNano int64
	VirtiofsSandbox           string
	Store                     string
	LogRoot                   string
	RuntimeDir                string
	MonitorSock               string
	WorkspaceSock             string
	AgentStateSock            string
	WorkspaceSockAlias        string
	AgentStateSockAlias       string
	SocketDir                 string
	Workspace                 string
	AgentState                string
	Virtiofsd                 string
	SerialLog                 string
	VsockCID                  uint32
	RootSSHKeyPath            string
	UserSSHKeyPath            string
	Mode                      string
	NetworkBackend            string
	LaunchID                  string
	GuestUID                  int
	GuestGID                  int
	QEMUPath                  string
	QEMUArgs                  []string
}

type vmLaunchMessage struct {
	State   string `json:"state"`
	Message string `json:"message,omitempty"`
}

const vmGuestCIDCollisionState = "cid-collision"

const vmSupervisorPrecommitTimeout = 150 * time.Second
const vmSupervisorReplyGrace = time.Second

type vmGuestCIDCollisionError struct {
	CID       uint32
	Retryable bool
	Detail    string
}

func (err *vmGuestCIDCollisionError) Error() string {
	if err.Detail != "" {
		return fmt.Sprintf("QEMU vhost-vsock guest CID %d is already in use: %s", err.CID, err.Detail)
	}
	return fmt.Sprintf("QEMU vhost-vsock guest CID %d is already in use", err.CID)
}

type vmLaunchHandle struct {
	command           *exec.Cmd
	identity          vmOwnedProcess
	control           *os.File
	readyFile         *os.File
	messages          *bufio.Reader
	exited            chan struct{}
	exitErr           error
	spec              vmLaunchSpec
	committed         bool
	precommitDeadline time.Time
}

func newVMSupervisorCommand() *cobra.Command {
	var spec vmLaunchSpec
	command := &cobra.Command{
		Use: "__supervise-vm -- <qemu-executable> <arguments...>", Hidden: true,
		SilenceUsage: true, SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("missing QEMU executable")
			}
			spec.QEMUPath, spec.QEMUArgs = args[0], args[1:]
			return runVMSupervisor(spec)
		},
	}
	f := command.Flags()
	f.StringVar(&spec.VirtiofsSandbox, "virtiofs-sandbox", "namespace", "filesystem sandbox mode")
	f.StringVar(&spec.Store, "store", "", "absolute store")
	f.StringVar(&spec.LogRoot, "log-root", "", "durable log root")
	f.StringVar(&spec.RuntimeDir, "runtime-dir", "", "private runtime directory")
	f.StringVar(&spec.MonitorSock, "monitor-sock", "", "QMP socket")
	f.StringVar(&spec.WorkspaceSock, "workspace-sock", "", "workspace virtiofs socket")
	f.StringVar(&spec.AgentStateSock, "agent-state-sock", "", "agent-state virtiofs socket")
	f.StringVar(&spec.WorkspaceSockAlias, "workspace-sock-alias", "", "optional symlink pointing at the workspace socket")
	f.StringVar(&spec.AgentStateSockAlias, "agent-state-sock-alias", "", "optional symlink pointing at the agent-state socket")
	f.StringVar(&spec.SocketDir, "socket-dir", "", "optional ephemeral directory holding virtiofs sockets")
	f.StringVar(&spec.Workspace, "workspace", "", "workspace export")
	f.StringVar(&spec.AgentState, "agent-state", "", "agent-state export")
	f.StringVar(&spec.Virtiofsd, "virtiofsd", "", "static virtiofsd executable")
	f.StringVar(&spec.SerialLog, "serial-log", "", "durable QEMU serial log")
	f.Uint32Var(&spec.VsockCID, "vsock-cid", 0, "guest vsock CID")
	f.StringVar(&spec.RootSSHKeyPath, "root-ssh-key", "", "protected root SSH private key")
	f.StringVar(&spec.UserSSHKeyPath, "user-ssh-key", "", "protected user SSH private key")
	f.StringVar(&spec.Mode, "mode", "", "attached or detached")
	spec.NetworkBackend = vmNetworkBackendHost
	f.StringVar(&spec.LaunchID, "launch-id", "", "launch identity")
	f.IntVar(&spec.GuestUID, "guest-uid", 0, "guest user UID")
	f.IntVar(&spec.GuestGID, "guest-gid", 0, "guest user primary GID")
	f.Int64Var(&spec.PrecommitDeadlineUnixNano, "precommit-deadline-unix-ns", 0, "internal supervisor startup deadline")
	return command
}

func validateVMLaunchSpec(spec vmLaunchSpec) error {
	if spec.NetworkBackend != vmNetworkBackendHost {
		return fmt.Errorf("new VM launches require host-enforced networking")
	}
	if spec.VirtiofsSandbox != "" && spec.VirtiofsSandbox != "namespace" && spec.VirtiofsSandbox != "none" {
		return fmt.Errorf("invalid virtiofs sandbox mode: %q", spec.VirtiofsSandbox)
	}
	if spec.VirtiofsSandbox != "namespace" {
		return virtiofsNamespaceRequiredError("the requested VM launch does not use virtiofs-sandbox=namespace")
	}
	if spec.SocketDir == "" || spec.SocketDir != vmSocketDir(spec.LaunchID) || spec.WorkspaceSock != filepath.Join(spec.SocketDir, "workspace.sock") || spec.AgentStateSock != filepath.Join(spec.SocketDir, "agent-state.sock") {
		return fmt.Errorf("invalid VM socket directory")
	}
	for label, path := range map[string]string{
		"store": spec.Store, "log root": spec.LogRoot, "runtime directory": spec.RuntimeDir,
		"QMP socket": spec.MonitorSock, "workspace socket": spec.WorkspaceSock,
		"agent-state socket": spec.AgentStateSock, "workspace export": spec.Workspace,
		"agent-state export": spec.AgentState, "virtiofsd executable": spec.Virtiofsd,
		"serial log": spec.SerialLog, "QEMU executable": spec.QEMUPath,
	} {
		if path == "" || !filepath.IsAbs(path) {
			return fmt.Errorf("%s must be an absolute path", label)
		}
	}
	for label, path := range map[string]string{"QMP": spec.MonitorSock, "workspace": spec.WorkspaceSock, "agent-state": spec.AgentStateSock} {
		if len(path) > 107 {
			return fmt.Errorf("%s Unix socket path exceeds Linux's 107-byte limit: %s", label, path)
		}
	}
	sshSocket := vmControlSocketPath(spec.SocketDir, spec.LaunchID)
	if len(sshSocket) > 107 {
		return fmt.Errorf("SSH broker Unix socket path exceeds Linux's 107-byte limit: %s", sshSocket)
	}
	if spec.LaunchID == "" || spec.VsockCID < 3 || (spec.Mode != "attached" && spec.Mode != "detached") {
		return fmt.Errorf("invalid VM launch identity, vsock CID, or mode")
	}
	for label, path := range map[string]string{"root SSH key": spec.RootSSHKeyPath, "user SSH key": spec.UserSSHKeyPath} {
		if path == "" || !filepath.IsAbs(path) {
			return fmt.Errorf("%s must be an absolute path", label)
		}
	}
	if spec.GuestUID <= 0 || spec.GuestGID <= 0 {
		return fmt.Errorf("invalid guest user identity")
	}
	return nil
}

func vmSupervisorArgs(spec vmLaunchSpec) []string {
	args := []string{
		"__supervise-vm", "--virtiofs-sandbox", spec.VirtiofsSandbox, "--store", spec.Store, "--log-root", spec.LogRoot,
		"--runtime-dir", spec.RuntimeDir, "--monitor-sock", spec.MonitorSock,
		"--workspace-sock", spec.WorkspaceSock, "--agent-state-sock", spec.AgentStateSock,
		"--workspace", spec.Workspace, "--agent-state", spec.AgentState,
		"--virtiofsd", spec.Virtiofsd, "--serial-log", spec.SerialLog,
		"--vsock-cid", strconv.FormatUint(uint64(spec.VsockCID), 10),
		"--root-ssh-key", spec.RootSSHKeyPath, "--user-ssh-key", spec.UserSSHKeyPath,
		"--mode", spec.Mode, "--launch-id", spec.LaunchID,
		"--guest-uid", strconv.Itoa(spec.GuestUID), "--guest-gid", strconv.Itoa(spec.GuestGID),
		"--precommit-deadline-unix-ns", strconv.FormatInt(spec.PrecommitDeadlineUnixNano, 10),
	}
	if spec.WorkspaceSockAlias != "" {
		args = append(args, "--workspace-sock-alias", spec.WorkspaceSockAlias)
	}
	if spec.AgentStateSockAlias != "" {
		args = append(args, "--agent-state-sock-alias", spec.AgentStateSockAlias)
	}
	if spec.SocketDir != "" {
		args = append(args, "--socket-dir", spec.SocketDir)
	}
	args = append(args, "--", spec.QEMUPath)
	return append(args, spec.QEMUArgs...)
}

func newVMLaunchID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func readVMSupervisorRecord(store projectStore) (vmSupervisorRecord, error) {
	var record vmSupervisorRecord
	data, err := os.ReadFile(store.vmSupervisorPath())
	if err != nil {
		return record, err
	}
	if err = json.Unmarshal(data, &record); err != nil {
		return record, fmt.Errorf("decode VM supervisor record: %w", err)
	}
	if (record.FormatVersion != 1 && record.FormatVersion != 2) || record.LaunchID == "" {
		return record, fmt.Errorf("unsupported VM supervisor record format %d", record.FormatVersion)
	}
	if err := validateVMSupervisorRecord(record); err != nil {
		return record, err
	}
	return record, nil
}

func validateVMSupervisorRecord(record vmSupervisorRecord) error {
	if record.FormatVersion == 2 && record.VsockCID < 3 {
		return fmt.Errorf("VM supervisor record has invalid guest vsock CID")
	}
	if record.FormatVersion == 2 && record.SocketDir != vmSocketDir(record.LaunchID) {
		return fmt.Errorf("VM supervisor record has invalid socket directory")
	}
	if record.VirtiofsSandbox != "" && record.VirtiofsSandbox != "namespace" && record.VirtiofsSandbox != "none" {
		return fmt.Errorf("VM supervisor record has invalid virtiofs sandbox mode")
	}
	if record.Supervisor == (vmOwnedProcess{}) {
		return fmt.Errorf("VM supervisor record has no supervisor identity")
	}
	if record.Mode != "attached" && record.Mode != "detached" {
		return fmt.Errorf("VM supervisor record has invalid mode")
	}
	if len(record.LaunchID) != 32 {
		return fmt.Errorf("VM supervisor record has invalid launch ID")
	}
	if _, err := hex.DecodeString(record.LaunchID); err != nil {
		return fmt.Errorf("VM supervisor record has invalid launch ID: %w", err)
	}
	if record.SocketDir != "" && record.SocketDir != vmSocketDir(record.LaunchID) {
		return fmt.Errorf("VM supervisor record has unsafe socket directory")
	}
	children := []struct {
		name    string
		process vmOwnedProcess
	}{
		{"supervisor", record.Supervisor}, {"workspace daemon", record.WorkspaceDaemon},
		{"workspace descendant", record.WorkspaceDescendant}, {"agent-state daemon", record.AgentStateDaemon},
		{"agent-state descendant", record.AgentStateDescendant}, {"QEMU", record.QEMU}, {"SSH broker", record.SSHBroker},
	}
	absent := false
	for _, child := range children {
		p := child.process
		if record.VirtiofsSandbox == "none" && (child.name == "workspace descendant" || child.name == "agent-state descendant") {
			if p != (vmOwnedProcess{}) {
				return fmt.Errorf("unsandboxed VM record has unexpected %s", child.name)
			}
			continue
		}
		if p == (vmOwnedProcess{}) {
			absent = true
			continue
		}
		if absent || p.PID <= 0 || p.ProcessGroup <= 0 || p.ExeDevice == 0 || p.ExeInode == 0 {
			return fmt.Errorf("VM supervisor record has incomplete %s identity", child.name)
		}
		if _, err := strconv.ParseUint(p.StartTime, 10, 64); err != nil {
			return fmt.Errorf("VM supervisor record has invalid %s start time: %w", child.name, err)
		}
	}
	if record.WorkspaceDescendant.PID > 0 && record.WorkspaceDescendant.ProcessGroup != record.WorkspaceDaemon.ProcessGroup {
		return fmt.Errorf("VM supervisor record has mismatched workspace daemon group")
	}
	if record.AgentStateDescendant.PID > 0 && record.AgentStateDescendant.ProcessGroup != record.AgentStateDaemon.ProcessGroup {
		return fmt.Errorf("VM supervisor record has mismatched agent-state daemon group")
	}
	if record.NetworkBackend != "" && record.NetworkBackend != vmNetworkBackendUser && record.NetworkBackend != vmNetworkBackendHost {
		return fmt.Errorf("VM supervisor record has invalid network backend")
	}
	if record.NetworkBackend == vmNetworkBackendHost && record.NetworkGeneration == 0 {
		return fmt.Errorf("host-network VM record has no policy generation")
	}
	if len(record.NetworkProcesses) > 8 {
		return fmt.Errorf("VM supervisor record has too many host network processes")
	}
	for name, process := range record.NetworkProcesses {
		if name == "" || process.PID <= 0 || process.ProcessGroup <= 0 || process.ExeDevice == 0 || process.ExeInode == 0 {
			return fmt.Errorf("VM supervisor record has incomplete host network process identity")
		}
		if _, err := strconv.ParseUint(process.StartTime, 10, 64); err != nil {
			return fmt.Errorf("VM supervisor record has invalid host network process start time: %w", err)
		}
	}
	return nil
}

func vmProcessLive(process vmOwnedProcess) (bool, error) {
	if process == (vmOwnedProcess{}) {
		return false, nil
	}
	actual, err := processStartTime(process.PID)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if actual != process.StartTime {
		return false, nil
	}
	state, _, threads, err := readQemuProcessState(process.PID)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return (state != 'Z' && state != 'X') || threads > 1, nil
}

func vmProcessIsLive(process vmOwnedProcess) bool {
	live, err := vmProcessLive(process)
	return live || err != nil
}

func (store projectStore) supervisorIsLive() (bool, error) {
	record, err := readVMSupervisorRecord(store)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return vmProcessLive(record.Supervisor)
}

// Reject image or staging mutations while a supervisor owns this store. FD5
// covers the interval before its record is published and after it is removed.
func requireNoActiveVMSupervisor(store projectStore, operation string) error {
	return requireNoActiveVMSupervisorWithin(store, operation, 0)
}

func requireNoActiveVMSupervisorWithin(store projectStore, operation string, wait time.Duration) error {
	// Probes must not create files in a fresh/legacy store. A missing lock
	// pathname does not establish absence: an unlinked lock can still be held
	// by its supervisor. Always inspect any surviving record below.
	lock, err := os.OpenFile(store.vmSupervisorLockPath(), os.O_RDWR, 0600)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if lock != nil {
		defer func() { _ = lock.Close() }()
		deadline := time.Now().Add(wait)
		for {
			err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
			if err == nil {
				break
			}
			if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
				return fmt.Errorf("inspect VM lifetime lock before %s: %w", operation, err)
			}
			if !time.Now().Before(deadline) {
				return fmt.Errorf("VM operation in progress; cannot run %s", operation)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	record, err := readVMSupervisorRecord(store)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := validateStaleVMRecord(store, record); err != nil {
		return fmt.Errorf("VM operation in progress; cannot run %s: %w", operation, err)
	}
	return nil
}

func validateStaleVMRecord(store projectStore, record vmSupervisorRecord) error {
	runtimeDir := filepath.Clean(record.RuntimeDir)
	shortTemp := filepath.Dir(runtimeDir) == os.TempDir() &&
		(strings.HasPrefix(filepath.Base(runtimeDir), "zaigr-vm-") || strings.HasPrefix(filepath.Base(runtimeDir), "zaigr-inspect-"))
	if !filepath.IsAbs(runtimeDir) || (runtimeDir != store.runtimeDir() && !shortTemp) {
		return fmt.Errorf("stale VM record has an unsafe runtime directory: %s", record.RuntimeDir)
	}
	supervisorLive, err := vmProcessLive(record.Supervisor)
	if err != nil {
		return fmt.Errorf("inspect previous VM supervisor: %w", err)
	}
	if supervisorLive {
		return fmt.Errorf("previous VM supervisor is still live")
	}
	if err := stopRecordedNetworkProcesses(record); err != nil {
		return fmt.Errorf("stop stale host network processes: %w", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		supervisorLive, err := vmProcessLive(record.Supervisor)
		if err != nil {
			return fmt.Errorf("inspect previous VM supervisor: %w", err)
		}
		if supervisorLive {
			return fmt.Errorf("previous VM supervisor is still live")
		}
		live := false
		for _, child := range []vmOwnedProcess{record.QEMU, record.WorkspaceDaemon, record.AgentStateDaemon, record.WorkspaceDescendant, record.AgentStateDescendant, record.SSHBroker} {
			childLive, err := vmProcessLive(child)
			if err != nil {
				return fmt.Errorf("inspect previous VM descendant %d: %w", child.PID, err)
			}
			if childLive {
				live = true
			}
		}
		for _, child := range record.NetworkProcesses {
			childLive, err := vmProcessLive(child)
			if err != nil {
				return fmt.Errorf("inspect previous host network process %d: %w", child.PID, err)
			}
			live = live || childLive
		}
		if !live {
			empty, err := daemonGroupsEmpty(record)
			if err != nil {
				return err
			}
			if empty {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("previous VM descendants remain live; refusing stale cleanup")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func stopAndWaitForVMSupervisor(store projectStore) error {
	record, err := readVMSupervisorRecord(store)
	if errors.Is(err, os.ErrNotExist) {
		// Same reasoning as requireNoActiveVMSupervisorWithin: without a record,
		// no supervisor has started here. Skip the lock dance (which would
		// otherwise create a stray lock file as a side effect).
		lock, openErr := os.OpenFile(store.vmSupervisorLockPath(), os.O_RDWR, 0600)
		if errors.Is(openErr, os.ErrNotExist) {
			return nil
		}
		if openErr != nil {
			return openErr
		}
		defer func() { _ = lock.Close() }()
		deadline := time.Now().Add(22 * time.Second)
		signaled := false
		for {
			if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
				current, readErr := readVMSupervisorRecord(store)
				if errors.Is(readErr, os.ErrNotExist) {
					return nil
				}
				if readErr != nil {
					return readErr
				}
				if err := validateStaleVMRecord(store, current); err != nil {
					return err
				}
				if err := removeVMRuntime(current); err != nil {
					return err
				}
				if err := os.Remove(store.vmSupervisorPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
					return err
				}
				return nil
			} else if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
				return err
			}
			if !signaled {
				current, readErr := readVMSupervisorRecord(store)
				if readErr == nil {
					if err := signalVerifiedVMProcess(current.Supervisor, syscall.SIGTERM); err != nil {
						return err
					}
					signaled = true
				} else if !errors.Is(readErr, os.ErrNotExist) {
					return readErr
				}
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("VM launch or cleanup timed out")
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	if err != nil {
		return err
	}
	if err := signalVerifiedVMProcess(record.Supervisor, syscall.SIGTERM); err != nil {
		return err
	}
	lock, err := os.OpenFile(store.vmSupervisorLockPath(), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	deadline := time.Now().Add(22 * time.Second)
	for {
		live, err := vmProcessLive(record.Supervisor)
		if err != nil {
			return fmt.Errorf("inspect VM supervisor during stop: %w", err)
		}
		if !live {
			if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
				break
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("VM supervisor cleanup timed out; see %s", filepath.Join(store.Path, "vm-supervisor.log"))
		}
		time.Sleep(50 * time.Millisecond)
	}
	current, err := readVMSupervisorRecord(store)
	if err == nil && current.LaunchID != record.LaunchID {
		return fmt.Errorf("VM supervisor changed during stop; refusing cleanup")
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	verified := record
	if err == nil {
		verified = current
	}
	if err := validateStaleVMRecord(store, verified); err != nil {
		return err
	}
	if err := removeVMRuntime(verified); err != nil {
		return err
	}
	if err := os.Remove(store.vmSupervisorPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func writeVMSupervisorRecord(store projectStore, record vmSupervisorRecord) error {
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeFileAtomically(store.vmSupervisorPath(), data, 0600)
}

func vmProcessIdentity(pid int) (vmOwnedProcess, error) {
	start, err := processStartTime(pid)
	if err != nil {
		return vmOwnedProcess{}, err
	}
	pgid, err := syscall.Getpgid(pid)
	if err != nil {
		return vmOwnedProcess{}, err
	}
	info, err := os.Stat(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return vmOwnedProcess{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return vmOwnedProcess{}, fmt.Errorf("inspect executable identity for PID %d", pid)
	}
	return vmOwnedProcess{PID: pid, StartTime: start, ProcessGroup: pgid, ExeDevice: uint64(stat.Dev), ExeInode: stat.Ino}, nil
}

func processState(pid int) (byte, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	index := strings.LastIndexByte(string(data), ')')
	if index < 0 || index+2 >= len(data) {
		return 0, fmt.Errorf("malformed process stat for PID %d", pid)
	}
	return data[index+2], nil
}

func sameProcessInstance(actual, expected vmOwnedProcess) bool {
	return actual.PID == expected.PID && actual.StartTime == expected.StartTime && actual.ProcessGroup == expected.ProcessGroup
}

func terminateOwnedChildLauncher(child *exec.Cmd, expected vmOwnedProcess) error {
	if child == nil || child.Process == nil || child.Process.Pid != expected.PID {
		return fmt.Errorf("owned launcher handle for PID %d is unavailable", expected.PID)
	}
	if expected.ProcessGroup != expected.PID {
		return fmt.Errorf("owned launcher PID %d is not the leader of its expected session", expected.PID)
	}
	actual, err := vmProcessIdentity(expected.PID)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
		members, memberErr := daemonGroupMembers(expected)
		if memberErr != nil {
			return fmt.Errorf("inspect owned launcher group %d after leader exit: %w", expected.ProcessGroup, memberErr)
		}
		if len(members) > 0 {
			return fmt.Errorf("owned launcher leader PID %d exited while its process group still has members; refusing unanchored signaling", expected.PID)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("verify owned launcher PID %d before cleanup: %w", expected.PID, err)
	}
	if !sameProcessInstance(actual, expected) {
		return fmt.Errorf("owned launcher PID %d changed before cleanup", expected.PID)
	}
	initialMembers, err := daemonGroupMembers(expected)
	if err != nil {
		return fmt.Errorf("snapshot owned launcher group %d: %w", expected.ProcessGroup, err)
	}
	if len(initialMembers) == 0 {
		return nil
	}
	initialInstances := make(map[int]string, len(initialMembers))
	for _, member := range initialMembers {
		initialInstances[member.PID] = member.StartTime
	}
	var cleanupErr error
	// startChild creates a fresh session, so while the verified leader is live
	// its process group contains only this daemon and its descendants.
	if err := syscall.Kill(-expected.ProcessGroup, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		cleanupErr = errors.Join(cleanupErr, fmt.Errorf("terminate owned launcher group %d: %w", expected.ProcessGroup, err))
	}
	if err := child.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) && !errors.Is(err, syscall.ESRCH) {
		cleanupErr = errors.Join(cleanupErr, fmt.Errorf("terminate owned launcher PID %d: %w", expected.PID, err))
	}
	waitGroup := func(deadline time.Time) ([]vmOwnedProcess, error) {
		for time.Now().Before(deadline) {
			members, err := daemonGroupMembers(expected)
			if err != nil {
				return nil, err
			}
			if len(members) == 0 {
				return members, nil
			}
			time.Sleep(25 * time.Millisecond)
		}
		members, err := daemonGroupMembers(expected)
		return members, err
	}
	remaining, waitErr := waitGroup(time.Now().Add(time.Second))
	cleanupErr = errors.Join(cleanupErr, waitErr)
	if waitErr == nil && len(remaining) > 0 {
		anchoredMember := false
		for _, member := range remaining {
			if initialInstances[member.PID] == member.StartTime {
				anchoredMember = true
				break
			}
		}
		if !anchoredMember {
			return errors.Join(cleanupErr, fmt.Errorf("owned launcher group %d no longer has a verified member; refusing escalation", expected.ProcessGroup))
		}
		if err := syscall.Kill(-expected.ProcessGroup, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("kill owned launcher group %d: %w", expected.ProcessGroup, err))
		}
		remaining, waitErr = waitGroup(time.Now().Add(time.Second))
		cleanupErr = errors.Join(cleanupErr, waitErr)
		if waitErr == nil && len(remaining) > 0 {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("owned launcher group %d remains live after SIGKILL", expected.ProcessGroup))
		}
	}
	return cleanupErr
}

func executableIdentity(path string) (vmExecutableIdentity, error) {
	info, err := os.Stat(path)
	if err != nil {
		return vmExecutableIdentity{}, fmt.Errorf("inspect expected executable %s: %w", path, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return vmExecutableIdentity{}, fmt.Errorf("inspect expected executable identity for %s", path)
	}
	return vmExecutableIdentity{Device: uint64(stat.Dev), Inode: stat.Ino}, nil
}

func waitForExpectedExecutable(expected vmOwnedProcess, executable vmExecutableIdentity, deadline time.Time) (vmOwnedProcess, error) {
	for time.Now().Before(deadline) {
		actual, err := vmProcessIdentity(expected.PID)
		if err == nil {
			if !sameProcessInstance(actual, expected) {
				return vmOwnedProcess{}, fmt.Errorf("PID %d changed while waiting for executable transition", expected.PID)
			}
			if actual.ExeDevice == executable.Device && actual.ExeInode == executable.Inode {
				return actual, nil
			}
		} else if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
			return vmOwnedProcess{}, fmt.Errorf("PID %d exited before executable transition: %w", expected.PID, err)
		} else {
			return vmOwnedProcess{}, err
		}
		time.Sleep(20 * time.Millisecond)
	}
	return vmOwnedProcess{}, fmt.Errorf("PID %d did not transition to the expected executable before startup deadline", expected.PID)
}

func waitForQEMUProcessIdentity(launcher vmOwnedProcess, spec vmLaunchSpec, deadline time.Time) (vmOwnedProcess, bool, error) {
	for time.Now().Before(deadline) {
		state, err := processState(launcher.PID)
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
			return vmOwnedProcess{}, false, nil
		}
		if err != nil {
			return vmOwnedProcess{}, false, err
		}
		if state == 'Z' || state == 'X' {
			return vmOwnedProcess{}, false, nil
		}
		actual, err := vmProcessIdentity(launcher.PID)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
				return vmOwnedProcess{}, false, nil
			}
			return vmOwnedProcess{}, false, err
		}
		if !sameProcessInstance(actual, launcher) {
			return vmOwnedProcess{}, false, fmt.Errorf("QEMU launcher PID %d changed before executable confirmation", launcher.PID)
		}
		args, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", launcher.PID))
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
			return vmOwnedProcess{}, false, nil
		}
		if err != nil {
			return vmOwnedProcess{}, false, err
		}
		argv := strings.Split(strings.TrimRight(string(args), "\x00"), "\x00")
		exePath, exeErr := os.Readlink(fmt.Sprintf("/proc/%d/exe", launcher.PID))
		if errors.Is(exeErr, os.ErrNotExist) || errors.Is(exeErr, syscall.ESRCH) {
			return vmOwnedProcess{}, false, nil
		}
		if exeErr != nil {
			return vmOwnedProcess{}, false, exeErr
		}
		if len(argv) > 0 && filepath.Base(argv[0]) == "qemu-system-x86_64" && filepath.Base(exePath) == "qemu-system-x86_64" {
			qmpMatches, cidMatches := false, false
			for i := 1; i+1 < len(argv); i++ {
				if argv[i] == "-qmp" && qemuSocketPathFromOption(argv[i+1]) == spec.MonitorSock {
					qmpMatches = true
				}
				if argv[i] == "-device" && argv[i+1] == fmt.Sprintf("vhost-vsock-device,guest-cid=%d", spec.VsockCID) {
					cidMatches = true
				}
			}
			if qmpMatches && cidMatches {
				return actual, true, nil
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return vmOwnedProcess{}, false, fmt.Errorf("QEMU process PID %d did not exec with the expected QMP socket and vsock CID before startup deadline", launcher.PID)
}

func launchSupervisedVM(spec vmLaunchSpec) (*vmLaunchHandle, error) {
	mode, err := selectVirtiofsSandbox(virtiofsPreferenceStore(spec))
	if err != nil {
		return nil, err
	}
	spec.VirtiofsSandbox = mode
	if err := validateVMLaunchSpec(spec); err != nil {
		return nil, err
	}
	store := projectStore{Path: spec.Store}
	if err := os.MkdirAll(spec.Store, 0755); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(store.vmSupervisorLockPath(), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open VM lifetime lock: %w", err)
	}
	defer func() { _ = lock.Close() }()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		record, _ := readVMSupervisorRecord(store)
		return nil, fmt.Errorf("VM operation in progress in %s (supervisor PID %d)", spec.Store, record.Supervisor.PID)
	}
	if live, err := store.supervisorIsLive(); err != nil {
		return nil, err
	} else if live {
		return nil, fmt.Errorf("VM supervisor already owns %s", spec.Store)
	}
	if old, err := readVMSupervisorRecord(store); err == nil {
		if err := validateStaleVMRecord(store, old); err != nil {
			return nil, err
		}
		if err := removeVMRuntime(old); err != nil {
			return nil, fmt.Errorf("remove stale VM runtime: %w", err)
		}
		if err := os.Remove(store.vmSupervisorPath()); err != nil {
			return nil, err
		}
	}
	if err := os.MkdirAll(spec.RuntimeDir, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(spec.RuntimeDir, 0700); err != nil {
		return nil, err
	}
	// The launch ID makes this directory unique across stores and users. Never
	// remove or reuse an existing directory: it may belong to another launch.
	started := false
	if spec.SocketDir != "" {
		if err := os.Mkdir(spec.SocketDir, 0700); err != nil {
			return nil, fmt.Errorf("create private VM socket directory: %w", err)
		}
		defer func() {
			if !started {
				_ = os.Remove(spec.SocketDir)
			}
		}()
	}
	if err := os.WriteFile(filepath.Join(spec.RuntimeDir, "vsock-cid"), []byte(strconv.FormatUint(uint64(spec.VsockCID), 10)+"\n"), 0600); err != nil {
		return nil, err
	}
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer func() { _ = readyWrite.Close() }()
	controlRead, controlWrite, err := os.Pipe()
	if err != nil {
		_ = readyRead.Close()
		return nil, err
	}
	defer func() { _ = controlRead.Close() }()
	precommitDeadline := time.Now().Add(vmSupervisorPrecommitTimeout)
	spec.PrecommitDeadlineUnixNano = precommitDeadline.UnixNano()
	command := exec.Command("/proc/self/exe", vmSupervisorArgs(spec)...)
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	command.ExtraFiles = []*os.File{readyWrite, controlRead, lock}
	log, err := openVMLog(spec.LogRoot, "vm-supervisor.log", spec.LaunchID)
	if err != nil {
		_ = readyRead.Close()
		_ = controlWrite.Close()
		return nil, err
	}
	command.Stdout, command.Stderr = log, log
	if err = command.Start(); err != nil {
		_ = log.Close()
		_ = readyRead.Close()
		_ = controlWrite.Close()
		return nil, fmt.Errorf("start VM supervisor: %w", err)
	}
	started = true
	// The child now owns its duplicated readiness descriptor. Closing this
	// parent's writer makes EOF observable if the supervisor exits before
	// sending a structured readiness message.
	_ = readyWrite.Close()
	identity, err := vmProcessIdentity(command.Process.Pid)
	if err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		if spec.SocketDir != "" {
			_ = os.Remove(spec.SocketDir)
		}
		_ = readyRead.Close()
		_ = controlWrite.Close()
		_ = log.Close()
		return nil, fmt.Errorf("identify VM supervisor: %w", err)
	}
	_ = log.Close()
	handle := &vmLaunchHandle{command: command, identity: identity, control: controlWrite, readyFile: readyRead, messages: bufio.NewReader(readyRead), exited: make(chan struct{}), spec: spec, precommitDeadline: precommitDeadline}
	go func() {
		handle.exitErr = command.Wait()
		// Early supervisor failure may precede its teardown handler/record.
		// Only remove an empty directory after exit; preserve any evidence.
		if spec.SocketDir != "" {
			_ = os.Remove(spec.SocketDir)
		}
		close(handle.exited)
	}()
	// FD3 remains open until the commit reply. A bounded read also catches a
	// crashed supervisor whose inherited pipe closed without a message.
	message, err := handle.readMessage(time.Until(precommitDeadline) + vmSupervisorReplyGrace)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("VM supervisor startup: %w", err), handle.cancel())
	}
	if message.State == vmGuestCIDCollisionState {
		collision := &vmGuestCIDCollisionError{CID: spec.VsockCID, Detail: message.Message}
		cleanupErr := handle.cancel()
		if _, recordErr := readVMSupervisorRecord(store); recordErr == nil {
			return nil, errors.Join(errors.New("guest CID collision cleanup left supervisor metadata"), cleanupErr)
		} else if !os.IsNotExist(recordErr) {
			return nil, errors.Join(fmt.Errorf("guest CID collision cleanup could not verify supervisor metadata: %w", recordErr), cleanupErr)
		}
		if _, runtimeErr := os.Stat(spec.RuntimeDir); runtimeErr == nil {
			return nil, errors.Join(errors.New("guest CID collision cleanup left runtime state"), cleanupErr)
		} else if !os.IsNotExist(runtimeErr) {
			return nil, errors.Join(fmt.Errorf("guest CID collision cleanup could not verify runtime state: %w", runtimeErr), cleanupErr)
		}
		collision.Retryable = true
		return nil, collision
	}
	if message.State != "ready" {
		return nil, errors.Join(fmt.Errorf("VM supervisor startup: %s", message.Message), handle.cancel())
	}
	return handle, nil
}

const maxGuestCIDLaunchAttempts = 8

func launchSupervisedVMWithCIDRetry(spec vmLaunchSpec) (vmControlEndpoint, *vmLaunchHandle, error) {
	baseArgs := append([]string(nil), spec.QEMUArgs...)
	for attempt := 1; attempt <= maxGuestCIDLaunchAttempts; attempt++ {
		cid, err := newGuestVsockCID()
		if err != nil {
			return vmControlEndpoint{}, nil, err
		}
		args, err := qemuArgsWithGuestCID(baseArgs, cid)
		if err != nil {
			return vmControlEndpoint{}, nil, err
		}
		attemptSpec := spec
		attemptSpec.VsockCID = cid
		attemptSpec.QEMUArgs = args
		handle, err := launchSupervisedVM(attemptSpec)
		if err == nil {
			endpoint, endpointErr := vmControlEndpointForLaunch(attemptSpec)
			if endpointErr != nil {
				return vmControlEndpoint{}, nil, errors.Join(endpointErr, handle.cancel())
			}
			return endpoint, handle, nil
		}
		var collision *vmGuestCIDCollisionError
		if !errors.As(err, &collision) || !collision.Retryable {
			return vmControlEndpoint{}, nil, err
		}
		if attempt == maxGuestCIDLaunchAttempts {
			return vmControlEndpoint{}, nil, fmt.Errorf("guest vsock CID remained occupied after %d QEMU launches: %w", maxGuestCIDLaunchAttempts, err)
		}
		logWarn("QEMU reported an occupied guest vsock CID; retrying with a new CID", "attempt", attempt, "max_attempts", maxGuestCIDLaunchAttempts, "cid", cid)
	}
	return vmControlEndpoint{}, nil, errors.New("guest vsock CID retry loop ended unexpectedly")
}

func qemuArgsWithGuestCID(args []string, cid uint32) ([]string, error) {
	updated := append([]string(nil), args...)
	found := false
	for i, arg := range updated {
		if !strings.HasPrefix(arg, "vhost-vsock-device,") {
			continue
		}
		parts := strings.Split(arg, ",")
		for partIndex, part := range parts {
			if !strings.HasPrefix(part, "guest-cid=") {
				continue
			}
			if found {
				return nil, errors.New("QEMU arguments contain multiple vhost-vsock guest CIDs")
			}
			parts[partIndex] = "guest-cid=" + strconv.FormatUint(uint64(cid), 10)
			updated[i] = strings.Join(parts, ",")
			found = true
		}
	}
	if !found {
		return nil, errors.New("QEMU arguments do not contain a vhost-vsock guest CID")
	}
	return updated, nil
}

func (handle *vmLaunchHandle) readMessage(timeout time.Duration) (vmLaunchMessage, error) {
	result := make(chan struct {
		msg vmLaunchMessage
		err error
	}, 1)
	go func() {
		var msg vmLaunchMessage
		line, err := handle.messages.ReadBytes('\n')
		if err == nil {
			err = json.Unmarshal(line, &msg)
		}
		result <- struct {
			msg vmLaunchMessage
			err error
		}{msg, err}
	}()
	readResult := func(got struct {
		msg vmLaunchMessage
		err error
	}) (vmLaunchMessage, error) {
		if got.err != nil {
			select {
			case <-handle.exited:
				return vmLaunchMessage{}, fmt.Errorf("supervisor exited: %v while reading readiness response: %w; see %s", handle.exitErr, got.err, filepath.Join(handle.spec.LogRoot, "vm-supervisor.log"))
			default:
				return vmLaunchMessage{}, fmt.Errorf("read supervisor readiness response: %w; see %s", got.err, filepath.Join(handle.spec.LogRoot, "vm-supervisor.log"))
			}
		}
		return got.msg, got.err
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	select {
	case got := <-result:
		return readResult(got)
	case <-handle.exited:
		// A final structured error and process exit can become ready at once.
		// Drain the reader result before falling back to the exit status, while
		// keeping the wait bounded by the original startup deadline.
		select {
		case got := <-result:
			return readResult(got)
		case <-deadline.C:
			return vmLaunchMessage{}, fmt.Errorf("supervisor exited: %v; see %s", handle.exitErr, filepath.Join(handle.spec.LogRoot, "vm-supervisor.log"))
		}
	case <-deadline.C:
		return vmLaunchMessage{}, fmt.Errorf("supervisor reply timed out after %s", timeout)
	}
}

func (handle *vmLaunchHandle) commit() error {
	if _, err := io.WriteString(handle.control, "commit\n"); err != nil {
		return errors.Join(fmt.Errorf("commit VM launch: %w", err), handle.cancel())
	}
	msg, err := handle.readMessage(10 * time.Second)
	if err != nil {
		return errors.Join(fmt.Errorf("VM commit acknowledgement: %w", err), handle.cancel())
	}
	if msg.State != "committed" {
		return errors.Join(fmt.Errorf("VM commit rejected: %s", msg.Message), handle.cancel())
	}
	handle.committed = true
	_ = handle.readyFile.Close()
	if handle.spec.Mode == "detached" {
		return handle.control.Close()
	}
	return nil
}

func (handle *vmLaunchHandle) cancel() error {
	if handle == nil {
		return nil
	}
	_ = handle.control.Close()
	if handle.readyFile != nil {
		_ = handle.readyFile.Close()
	}
	var signalErr error
	if handle.command != nil && handle.command.Process != nil {
		signalErr = signalVerifiedVMProcess(handle.identity, syscall.SIGTERM)
	}
	select {
	case <-handle.exited:
		return errors.Join(signalErr, handle.exitErr)
	case <-time.After(22 * time.Second):
		return errors.Join(signalErr, fmt.Errorf("VM supervisor cleanup timed out; see %s", filepath.Join(handle.spec.LogRoot, "vm-supervisor.log")))
	}
}

func (handle *vmLaunchHandle) precommitContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithDeadline(context.Background(), handle.precommitDeadline)
	go func() {
		select {
		case <-handle.exited:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

func (handle *vmLaunchHandle) stop() error {
	if handle == nil {
		return nil
	}
	if handle.control != nil {
		_, _ = io.WriteString(handle.control, "stop\n")
		_ = handle.control.Close()
	}
	if handle.readyFile != nil {
		_ = handle.readyFile.Close()
	}
	select {
	case <-handle.exited:
		return handle.exitErr
	case <-time.After(22 * time.Second):
		return errors.Join(fmt.Errorf("VM supervisor cleanup timed out"), handle.cancel())
	}
}

func waitForVMGuestReady(handle *vmLaunchHandle, timeout time.Duration) error {
	if handle == nil {
		return fmt.Errorf("VM launch handle is missing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var output bytes.Buffer
	command := "findmnt -n -o FSTYPE /home/user/workspace; findmnt -n -o FSTYPE /home/user/.zaigr-agent-state"
	endpoint, err := vmControlEndpointForLaunch(handle.spec)
	if err != nil {
		return err
	}
	err = vmssh.Run(ctx, endpoint.SocketPath, vmssh.Request{User: "root", Command: command}, nil, &output, io.Discard)
	if err != nil {
		return fmt.Errorf("verify guest mounts over vsock SSH: %w", err)
	}
	mounts := strings.Fields(output.String())
	if len(mounts) != 2 || mounts[0] != "virtiofs" || mounts[1] != "virtiofs" {
		return fmt.Errorf("guest mount verification failed (workspace and agent state must be virtiofs): %q", strings.TrimSpace(output.String()))
	}
	return nil
}

func vmControlEndpointForLaunch(spec vmLaunchSpec) (vmControlEndpoint, error) {
	return vmControlEndpointForRecord(vmSupervisorRecord{
		RuntimeDir: spec.RuntimeDir,
		SocketDir:  spec.SocketDir,
		LaunchID:   spec.LaunchID,
		VsockCID:   spec.VsockCID,
	})
}

func openVMLog(root, name, launchID string) (*os.File, error) {
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(root, name)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	if _, err := fmt.Fprintf(file, "\n[%s] launch %s\n", time.Now().UTC().Format(time.RFC3339), launchID); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

type vmChildExit struct {
	name string
	err  error
}

func qemuExitResult(err error) error {
	if err == nil {
		return nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
			if status.Signaled() {
				return &cliError{code: 128 + int(status.Signal())}
			}
			if status.Exited() {
				return &cliError{code: status.ExitStatus()}
			}
		}
	}
	return fmt.Errorf("QEMU exited: %w", err)
}

func qemuCIDCollisionSince(path string, offset int64) (string, bool) {
	file, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer file.Close()
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return "", false
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(data), "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "vhost-vsock") && strings.Contains(lower, "guest cid") && strings.Contains(lower, "address already in use") {
			return strings.TrimSpace(line), true
		}
	}
	return "", false
}

func startSupervisorHostNetwork(spec vmLaunchSpec, store projectStore) (*hostNetworkHandle, error) {
	names, generation, grants, err := loadHostNetworkInitialPolicy(store)
	if err != nil {
		return nil, err
	}
	slirp, err := ensureSlirp4netnsWithWriter(false, io.Discard)
	if err != nil {
		return nil, fmt.Errorf("extract bundled slirp4netns: %w", err)
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return startHostNetworkRuntime(context.Background(), hostnet.Options{
		LaunchID: spec.LaunchID, RuntimeDir: spec.RuntimeDir, Executable: executable,
		SlirpPath:       slirp,
		InitialIPGrants: grants, InitialGeneration: generation,
	}, store, names, generation)
}

func newGuestVsockCID() (uint32, error) {
	var raw [4]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return 0, fmt.Errorf("generate guest vsock CID: %w", err)
	}
	// Keep random CIDs in the upper half of the 32-bit space, away from the
	// well-known local, host, and any CIDs. QEMU reports collisions at launch.
	cid := uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])
	cid = 0x40000000 | (cid & 0x3fffffff)
	return cid, nil
}

func hostNetworkOwnedProcesses(processes map[string]hostnet.ProcessIdentity) (map[string]vmOwnedProcess, error) {
	if len(processes) == 0 || len(processes) > 8 {
		return nil, fmt.Errorf("host network reported invalid process count %d", len(processes))
	}
	owned := make(map[string]vmOwnedProcess, len(processes))
	for name, reported := range processes {
		if name == "" || reported.PID <= 0 {
			return nil, fmt.Errorf("host network reported incomplete process identity")
		}
		identity, err := vmProcessIdentity(reported.PID)
		if err != nil {
			return nil, err
		}
		if identity.StartTime != reported.StartTime {
			return nil, fmt.Errorf("host network process %s changed identity during startup", name)
		}
		owned[name] = identity
	}
	return owned, nil
}

func verifyHostNetworkReady(handle *hostNetworkHandle, record *vmSupervisorRecord, recordMu *sync.Mutex) error {
	if handle == nil {
		return nil
	}
	status, err := handle.Status(context.Background())
	if err != nil {
		return err
	}
	recordMu.Lock()
	generation := record.NetworkGeneration
	processes := make(map[string]vmOwnedProcess, len(record.NetworkProcesses))
	for name, process := range record.NetworkProcesses {
		processes[name] = process
	}
	recordMu.Unlock()
	if status.Generation != generation {
		return fmt.Errorf("policy generation differs from recorded generation (%d != %d)", status.Generation, generation)
	}
	if len(status.Processes) != len(processes) {
		return fmt.Errorf("host network process set differs from the supervisor record")
	}
	for name, reported := range status.Processes {
		process, ok := processes[name]
		if !ok || process.PID != reported.PID || process.StartTime != reported.StartTime {
			return fmt.Errorf("host network process %s identity differs from the supervisor record", name)
		}
		live, err := vmProcessLive(process)
		if err != nil {
			return fmt.Errorf("inspect host network process %s: %w", name, err)
		}
		if !live {
			return fmt.Errorf("host network process %s exited", name)
		}
	}
	return nil
}

func verifyNetworkProcessesStopped(processes map[string]vmOwnedProcess) error {
	for name, process := range processes {
		live, err := vmProcessLive(process)
		if err != nil {
			return fmt.Errorf("inspect host network process %s: %w", name, err)
		}
		if live {
			return fmt.Errorf("host network process %s (PID %d) remains live after teardown", name, process.PID)
		}
		members, err := daemonGroupMembers(process)
		if err != nil {
			return fmt.Errorf("inspect host network process group %s: %w", name, err)
		}
		if len(members) > 0 {
			return fmt.Errorf("host network process group %s (PGID %d) remains live after teardown", name, process.ProcessGroup)
		}
	}
	return nil
}

func forwardHostNetworkEvents(handle *hostNetworkHandle, exit chan<- vmChildExit) {
	childExits := handle.ChildExits()
	fatal := handle.Fatal()
	for childExits != nil || fatal != nil {
		select {
		case <-handle.Done():
			return
		case child, ok := <-childExits:
			if !ok {
				childExits = nil
				continue
			}
			select {
			case exit <- vmChildExit{name: "host-network-" + child.Name, err: child.Err}:
			case <-handle.Done():
				return
			}
		case err, ok := <-fatal:
			if !ok {
				fatal = nil
				continue
			}
			select {
			case exit <- vmChildExit{name: "host-network-fatal", err: err}:
			case <-handle.Done():
				return
			}
			fatal = nil
		}
	}
}

// openPinnedVMShare opens the already validated directory without following a
// replacement symlink. The supervisor later compares the namespace daemon's
// root device/inode to this descriptor before allowing QEMU to attach.
func openPinnedVMShare(path string) (*os.File, error) {
	canonical, err := canonicalPathWithMissingSuffix(path)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "zaigr-pinned-virtiofs-share")
	fail := func(err error) (*os.File, error) { _ = file.Close(); return nil, err }
	info, err := file.Stat()
	if err != nil {
		return fail(err)
	}
	if !info.IsDir() {
		return fail(fmt.Errorf("export path is not a directory"))
	}
	resolved, err := filepath.EvalSymlinks(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return fail(err)
	}
	if filepath.Clean(resolved) != canonical {
		return fail(fmt.Errorf("export directory changed while it was being pinned"))
	}
	return file, nil
}

func pinnedVMSharePath(file *os.File) (string, error) {
	if file == nil {
		return "", errors.New("missing pinned export directory")
	}
	resolved, err := filepath.EvalSymlinks(fmt.Sprintf("/proc/self/fd/%d", file.Fd()))
	if err != nil {
		return "", err
	}
	if strings.HasSuffix(resolved, " (deleted)") {
		return "", errors.New("pinned export directory was removed")
	}
	return filepath.Clean(resolved), nil
}

func verifyVMShareNamespaceRoot(process vmOwnedProcess, pinned *os.File) error {
	if process.PID <= 0 || pinned == nil {
		return errors.New("missing namespace process or pinned export directory")
	}
	expected, err := pinned.Stat()
	if err != nil {
		return err
	}
	actual, err := os.Stat(fmt.Sprintf("/proc/%d/root", process.PID))
	if err != nil {
		return fmt.Errorf("stat namespace root for PID %d: %w", process.PID, err)
	}
	expectedStat, ok := expected.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("pinned export stat lacks device and inode")
	}
	actualStat, ok := actual.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("namespace root stat lacks device and inode")
	}
	if expectedStat.Dev != actualStat.Dev || expectedStat.Ino != actualStat.Ino {
		return fmt.Errorf("virtiofs namespace root does not match pinned export directory")
	}
	return nil
}

func runVMSupervisor(spec vmLaunchSpec) (retErr error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ready := os.NewFile(3, "ready")
	var committed bool
	var readyErrorReported bool
	defer func() {
		// Some validation failures happen before the supervisor's normal
		// teardown handler is installed. Report those through the same bounded
		// readiness protocol instead of making the launcher infer an exit code.
		if retErr != nil && !committed && !readyErrorReported && ready != nil {
			state := "error"
			var collision *vmGuestCIDCollisionError
			if errors.As(retErr, &collision) {
				state = vmGuestCIDCollisionState
			}
			_, _ = fmt.Fprintf(ready, "{\"state\":%q,\"message\":%q}\n", state, retErr.Error())
		}
		if ready != nil {
			_ = ready.Close()
		}
	}()
	startupDeadline := time.Now().Add(30 * time.Second)
	precommitDeadline := time.Now().Add(vmSupervisorPrecommitTimeout)
	if spec.PrecommitDeadlineUnixNano > 0 {
		precommitDeadline = time.Unix(0, spec.PrecommitDeadlineUnixNano)
	}
	precommitTimer := time.NewTimer(time.Until(precommitDeadline))
	defer precommitTimer.Stop()
	if err := validateVMLaunchSpec(spec); err != nil {
		return err
	}
	control := os.NewFile(4, "control")
	lock := os.NewFile(5, "lifetime-lock")
	syscall.CloseOnExec(3)
	syscall.CloseOnExec(4)
	syscall.CloseOnExec(5)
	defer func() { _ = control.Close() }()
	defer func() { _ = lock.Close() }()
	if ready == nil || control == nil || lock == nil {
		return fmt.Errorf("missing inherited supervisor descriptors")
	}
	store := projectStore{Path: spec.Store}
	var err error
	var workspaceRoot, agentStateRoot *os.File
	if spec.NetworkBackend == vmNetworkBackendHost {
		if spec.VirtiofsSandbox != "namespace" {
			return fmt.Errorf("host network backend requires namespace virtiofs sandbox for export identity verification")
		}
		for _, keyPath := range []string{rootSSHKeyPath(), userSSHKeyPath()} {
			if err := validateProtectedSSHPrivateKey(keyPath); err != nil {
				return fmt.Errorf("validate host SSH credential before VM export: %w", err)
			}
		}
		if err := validateHostNetworkExport(spec.Workspace, spec.AgentState, spec.Store, zaigDir(), spec.RuntimeDir); err != nil {
			return fmt.Errorf("VM export validation: %w", err)
		}
		workspaceRoot, err = openPinnedVMShare(spec.Workspace)
		if err != nil {
			return fmt.Errorf("pin workspace export: %w", err)
		}
		defer workspaceRoot.Close()
		agentStateRoot, err = openPinnedVMShare(spec.AgentState)
		if err != nil {
			return fmt.Errorf("pin agent-state export: %w", err)
		}
		defer agentStateRoot.Close()
		pinnedWorkspacePath, err := pinnedVMSharePath(workspaceRoot)
		if err != nil {
			return fmt.Errorf("resolve pinned workspace export: %w", err)
		}
		pinnedAgentStatePath, err := pinnedVMSharePath(agentStateRoot)
		if err != nil {
			return fmt.Errorf("resolve pinned agent-state export: %w", err)
		}
		if err := validateHostNetworkExport(pinnedWorkspacePath, pinnedAgentStatePath, spec.Store, zaigDir(), spec.RuntimeDir); err != nil {
			return fmt.Errorf("pinned VM export validation: %w", err)
		}
	}
	own, err := vmProcessIdentity(os.Getpid())
	if err != nil {
		return err
	}
	record := vmSupervisorRecord{FormatVersion: 2, VsockCID: spec.VsockCID, LaunchID: spec.LaunchID, Mode: spec.Mode, NetworkBackend: spec.NetworkBackend, RuntimeDir: spec.RuntimeDir, SocketDir: spec.SocketDir, Supervisor: own, VirtiofsSandbox: spec.VirtiofsSandbox}
	if spec.NetworkBackend == vmNetworkBackendHost {
		record.NetworkGeneration = 1
	}
	if err := writeVMSupervisorRecord(store, record); err != nil {
		return err
	}
	supervisorLog, err := openVMLog(spec.LogRoot, "vm-supervisor.log", spec.LaunchID)
	if err != nil {
		return err
	}
	defer func() { _ = supervisorLog.Close() }()
	exit := make(chan vmChildExit, 8)
	commands := make(chan string, 2)
	go func() {
		scanner := bufio.NewScanner(control)
		for scanner.Scan() {
			commands <- scanner.Text()
		}
		commands <- "__eof__"
	}()
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	children := map[string]*exec.Cmd{}
	alive := map[string]bool{}
	expectedExecutables := map[string]vmExecutableIdentity{}
	var networkHandle *hostNetworkHandle
	var sshBroker *vmSSHBroker
	var networkExitWriter *os.File
	var qemuTap *os.File
	var qemuMaintenanceTap *os.File
	var recordMu sync.Mutex
	networkCleanupFailed := false
	childTransitionCleanupFailed := false
	defer func() {
		// Closing the slirp exit writer is the first teardown action: it drops
		// uplink connectivity before coordinator locks or DNS workers can delay
		// cleanup of guest access.
		if networkExitWriter != nil {
			_ = networkExitWriter.Close()
			networkExitWriter = nil
		}
		if qemuTap != nil {
			_ = qemuTap.Close()
			qemuTap = nil
		}
		if qemuMaintenanceTap != nil {
			_ = qemuMaintenanceTap.Close()
			qemuMaintenanceTap = nil
		}
		// Send the phase-specific startup error immediately after closing the
		// uplink. Broker shutdown can take its own bounded grace period, but it
		// must not hide the failure from the launcher until then.
		if retErr != nil && !committed {
			state := "error"
			var collision *vmGuestCIDCollisionError
			if errors.As(retErr, &collision) {
				state = vmGuestCIDCollisionState
			}
			_, _ = fmt.Fprintf(ready, "{\"state\":%q,\"message\":%q}\n", state, retErr.Error())
			readyErrorReported = true
		}
		if sshBroker != nil {
			retErr = errors.Join(retErr, sshBroker.Close())
			brokerLive, brokerErr := vmProcessLive(record.SSHBroker)
			retErr = errors.Join(retErr, brokerErr)
			alive["ssh-broker"] = brokerLive || brokerErr != nil
			sshBroker = nil
		}
		if networkHandle != nil {
			closeErr := networkHandle.Close(context.Background())
			retErr = errors.Join(retErr, closeErr)
			if closeErr != nil {
				networkCleanupFailed = true
			}
			if err := verifyNetworkProcessesStopped(record.NetworkProcesses); err != nil {
				retErr = errors.Join(retErr, err)
				networkCleanupFailed = true
			}
		}
		if err := teardownVMChildren(spec, record, children, alive, exit, supervisorLog, childTransitionCleanupFailed); err != nil {
			retErr = errors.Join(retErr, err)
		} else if networkCleanupFailed {
			retErr = errors.Join(retErr, errors.New("host network cleanup was not verified; retaining supervisor recovery metadata"))
		} else {
			if err := os.RemoveAll(spec.RuntimeDir); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("remove VM runtime: %w", err))
			} else if err := os.Remove(store.vmSupervisorPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
				retErr = errors.Join(retErr, fmt.Errorf("remove VM supervisor record: %w", err))
			}
		}
	}()
	startChild := func(name, path string, args []string, logName string) error {
		log, err := openVMLog(spec.LogRoot, logName, spec.LaunchID)
		if err != nil {
			return err
		}
		child := exec.Command(path, args...)
		var expectedExecutable vmExecutableIdentity
		if name == "workspace" || name == "agent-state" {
			expectedExecutable, err = executableIdentity(child.Path)
			if err != nil {
				_ = log.Close()
				return err
			}
		}
		child.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Pdeathsig: syscall.SIGKILL}
		switch name {
		case "workspace":
			if spec.NetworkBackend == vmNetworkBackendHost {
				child.ExtraFiles = []*os.File{workspaceRoot}
			}
		case "agent-state":
			if spec.NetworkBackend == vmNetworkBackendHost {
				child.ExtraFiles = []*os.File{agentStateRoot}
			}
		case "qemu":
			if spec.NetworkBackend == vmNetworkBackendHost {
				if qemuTap == nil || qemuMaintenanceTap == nil {
					_ = log.Close()
					return errors.New("host network TAP descriptors are unavailable")
				}
				child.ExtraFiles = []*os.File{qemuTap, qemuMaintenanceTap}
			}
		}
		child.Stdout, child.Stderr = log, log
		if err := child.Start(); err != nil {
			_ = log.Close()
			return err
		}
		if name == "qemu" && qemuTap != nil {
			_ = qemuTap.Close()
			qemuTap = nil
			_ = qemuMaintenanceTap.Close()
			qemuMaintenanceTap = nil
		}
		_ = log.Close()
		identity, err := vmProcessIdentity(child.Process.Pid)
		if err != nil {
			_ = child.Process.Kill()
			_ = child.Wait()
			return err
		}
		children[name] = child
		alive[name] = true
		if name == "workspace" || name == "agent-state" {
			expectedExecutables[name] = expectedExecutable
		}
		go func() { exit <- vmChildExit{name, child.Wait()} }()
		recordMu.Lock()
		switch name {
		case "workspace":
			record.WorkspaceDaemon = identity
		case "agent-state":
			record.AgentStateDaemon = identity
		case "qemu":
			record.QEMU = identity
		}
		if err := writeVMSupervisorRecord(store, record); err != nil {
			recordMu.Unlock()
			return err
		}
		recordMu.Unlock()
		return nil
	}
	refreshChildExecutable := func(name, path string, deadline time.Time) error {
		recordMu.Lock()
		var launcher vmOwnedProcess
		switch name {
		case "workspace":
			launcher = record.WorkspaceDaemon
		case "agent-state":
			launcher = record.AgentStateDaemon
		default:
			recordMu.Unlock()
			return fmt.Errorf("cannot refresh executable identity for child %q", name)
		}
		recordMu.Unlock()
		executable, ok := expectedExecutables[name]
		if !ok {
			return fmt.Errorf("expected executable identity for %s was not captured before launch", name)
		}
		actual, err := waitForExpectedExecutable(launcher, executable, deadline)
		if err != nil {
			cleanupErr := terminateOwnedChildLauncher(children[name], launcher)
			if cleanupErr != nil {
				childTransitionCleanupFailed = true
			}
			return errors.Join(err, cleanupErr)
		}
		recordMu.Lock()
		defer recordMu.Unlock()
		var current vmOwnedProcess
		switch name {
		case "workspace":
			current = record.WorkspaceDaemon
		case "agent-state":
			current = record.AgentStateDaemon
		}
		if !sameProcessInstance(current, launcher) {
			return fmt.Errorf("%s launcher identity changed while confirming executable", name)
		}
		switch name {
		case "workspace":
			record.WorkspaceDaemon = actual
		case "agent-state":
			record.AgentStateDaemon = actual
		}
		return writeVMSupervisorRecord(store, record)
	}
	if spec.NetworkBackend == vmNetworkBackendHost {
		networkHandle, err = startSupervisorHostNetwork(spec, store)
		if err != nil {
			return fmt.Errorf("start host network backend: %w", err)
		}
		networkExitWriter = networkHandle.TakeSupervisorExitWriter()
		qemuTap = networkHandle.TakeTapFile()
		qemuMaintenanceTap = networkHandle.TakeMaintenanceTapFile()
		if networkExitWriter == nil || qemuTap == nil || qemuMaintenanceTap == nil {
			return errors.New("host network backend did not provide guest and maintenance TAPs and supervisor exit descriptor")
		}
		status, err := networkHandle.Status(context.Background())
		if err != nil {
			return fmt.Errorf("inspect host network startup: %w", err)
		}
		processes, err := hostNetworkOwnedProcesses(status.Processes)
		if err != nil {
			return fmt.Errorf("record host network process identities: %w", err)
		}
		recordMu.Lock()
		record.NetworkGeneration = status.Generation
		record.NetworkProcesses = processes
		if err := writeVMSupervisorRecord(store, record); err != nil {
			recordMu.Unlock()
			return err
		}
		recordMu.Unlock()
		networkHandle.SetPolicyRecordUpdater(func(generation uint64) error {
			recordMu.Lock()
			defer recordMu.Unlock()
			record.NetworkGeneration = generation
			return writeVMSupervisorRecord(store, record)
		})
		go forwardHostNetworkEvents(networkHandle, exit)
	}

	workspacePath := spec.Workspace
	if spec.NetworkBackend == vmNetworkBackendHost {
		workspacePath = "/proc/self/fd/3"
	}
	if err := startChild("workspace", spec.Virtiofsd, virtiofsDaemonArgs(workspacePath, spec.WorkspaceSock, spec.GuestUID, spec.GuestGID, spec.VirtiofsSandbox), "virtiofsd-workspace.log"); err != nil {
		return fmt.Errorf("start workspace virtiofsd (%s): %w", filepath.Join(spec.LogRoot, "virtiofsd-workspace.log"), err)
	}
	if err := refreshChildExecutable("workspace", spec.Virtiofsd, startupDeadline); err != nil {
		return fmt.Errorf("identify workspace virtiofsd executable: %w", err)
	}
	if err := waitVMSocket(spec.WorkspaceSock, "workspace", filepath.Join(spec.LogRoot, "virtiofsd-workspace.log"), children, alive, exit, commands, signals); err != nil {
		return err
	}
	if err := placeSocketAlias(spec.WorkspaceSockAlias, spec.WorkspaceSock); err != nil {
		return fmt.Errorf("link workspace socket alias: %w", err)
	}
	if time.Now().After(startupDeadline) {
		return fmt.Errorf("VM supervisor 30s startup deadline exceeded")
	}
	if spec.VirtiofsSandbox == "namespace" {
		var descendant vmOwnedProcess
		descendant, err = waitDaemonDescendant(record.WorkspaceDaemon, startupDeadline, exit, commands, signals, alive)
		if err != nil {
			return fmt.Errorf("identify workspace namespace child: %w", err)
		}
		recordMu.Lock()
		record.WorkspaceDescendant = descendant
		if spec.NetworkBackend == vmNetworkBackendHost {
			if err := verifyVMShareNamespaceRoot(descendant, workspaceRoot); err != nil {
				recordMu.Unlock()
				return fmt.Errorf("verify pinned workspace export in virtiofs namespace: %w", err)
			}
		}
		if err := writeVMSupervisorRecord(store, record); err != nil {
			recordMu.Unlock()
			return err
		}
		recordMu.Unlock()
	} else {
		recordMu.Lock()
		if err := writeVMSupervisorRecord(store, record); err != nil {
			recordMu.Unlock()
			return err
		}
		recordMu.Unlock()
	}
	agentStatePath := spec.AgentState
	if spec.NetworkBackend == vmNetworkBackendHost {
		agentStatePath = "/proc/self/fd/3"
	}
	if err := startChild("agent-state", spec.Virtiofsd, virtiofsDaemonArgs(agentStatePath, spec.AgentStateSock, spec.GuestUID, spec.GuestGID, spec.VirtiofsSandbox), "virtiofsd-agent-state.log"); err != nil {
		return fmt.Errorf("start agent-state virtiofsd (%s): %w", filepath.Join(spec.LogRoot, "virtiofsd-agent-state.log"), err)
	}
	if err := refreshChildExecutable("agent-state", spec.Virtiofsd, startupDeadline); err != nil {
		return fmt.Errorf("identify agent-state virtiofsd executable: %w", err)
	}
	if err := waitVMSocket(spec.AgentStateSock, "agent-state", filepath.Join(spec.LogRoot, "virtiofsd-agent-state.log"), children, alive, exit, commands, signals); err != nil {
		return err
	}
	if err := placeSocketAlias(spec.AgentStateSockAlias, spec.AgentStateSock); err != nil {
		return fmt.Errorf("link agent-state socket alias: %w", err)
	}
	if time.Now().After(startupDeadline) {
		return fmt.Errorf("VM supervisor 30s startup deadline exceeded")
	}
	if spec.VirtiofsSandbox == "namespace" {
		var descendant vmOwnedProcess
		descendant, err = waitDaemonDescendant(record.AgentStateDaemon, startupDeadline, exit, commands, signals, alive)
		if err != nil {
			return fmt.Errorf("identify agent-state namespace child: %w", err)
		}
		recordMu.Lock()
		record.AgentStateDescendant = descendant
		if spec.NetworkBackend == vmNetworkBackendHost {
			if err := verifyVMShareNamespaceRoot(descendant, agentStateRoot); err != nil {
				recordMu.Unlock()
				return fmt.Errorf("verify pinned agent-state export in virtiofs namespace: %w", err)
			}
		}
		if err := writeVMSupervisorRecord(store, record); err != nil {
			recordMu.Unlock()
			return err
		}
		recordMu.Unlock()
	} else {
		recordMu.Lock()
		if err := writeVMSupervisorRecord(store, record); err != nil {
			recordMu.Unlock()
			return err
		}
		recordMu.Unlock()
	}
	qemuLogPath := filepath.Join(spec.LogRoot, "vm-qemu.log")
	var qemuLogStart int64
	if info, statErr := os.Stat(qemuLogPath); statErr == nil {
		qemuLogStart = info.Size()
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf("inspect QEMU log before launch: %w", statErr)
	}
	if err := startChild("qemu", spec.QEMUPath, spec.QEMUArgs, "vm-qemu.log"); err != nil {
		return fmt.Errorf("start QEMU (%s): %w", filepath.Join(spec.LogRoot, "vm-qemu.log"), err)
	}
	qemuLauncher := record.QEMU
	qemuIdentity, qemuExecConfirmed, err := waitForQEMUProcessIdentity(qemuLauncher, spec, startupDeadline)
	if err != nil {
		return fmt.Errorf("identify QEMU process: %w", err)
	}
	if qemuExecConfirmed {
		recordMu.Lock()
		if record.QEMU.PID != qemuLauncher.PID || record.QEMU.StartTime != qemuLauncher.StartTime || record.QEMU.ProcessGroup != qemuLauncher.ProcessGroup {
			recordMu.Unlock()
			return errors.New("QEMU process identity changed while confirming its executable")
		}
		record.QEMU = qemuIdentity
		if err := writeVMSupervisorRecord(store, record); err != nil {
			recordMu.Unlock()
			return err
		}
		recordMu.Unlock()
	}
	brokerCtx, cancelBroker := context.WithCancel(context.Background())
	sshSocket := vmControlSocketPath(spec.SocketDir, spec.LaunchID)
	sshBroker, err = startVMSSHBroker(brokerCtx, spec.VsockCID, sshSocket, spec.RootSSHKeyPath, spec.UserSSHKeyPath)
	if err != nil {
		cancelBroker()
		return fmt.Errorf("start guest SSH broker: %w", err)
	}
	defer cancelBroker()
	brokerIdentity, err := vmProcessIdentity(sshBroker.PID())
	if err != nil {
		return fmt.Errorf("identify guest SSH broker: %w", err)
	}
	alive["ssh-broker"] = true
	recordMu.Lock()
	record.SSHBroker = brokerIdentity
	if err := writeVMSupervisorRecord(store, record); err != nil {
		recordMu.Unlock()
		return err
	}
	recordMu.Unlock()
	brokerChild := sshBroker
	go func() {
		<-brokerChild.Done()
		exit <- vmChildExit{name: "ssh-broker", err: brokerChild.Wait()}
	}()
	readyCtx, cancelReady := context.WithDeadline(brokerCtx, precommitDeadline)
	defer cancelReady()
	qmpReady := make(chan error, 1)
	sshReady := make(chan error, 1)
	qmpTimeout := time.Until(startupDeadline)
	if qmpTimeout > 30*time.Second {
		qmpTimeout = 30 * time.Second
	}
	if qmpTimeout <= 0 {
		return fmt.Errorf("VM supervisor 30s startup deadline exceeded")
	}
	go func() { qmpReady <- waitQMPReady(spec.MonitorSock, qmpTimeout) }()
	go func() { sshReady <- sshBroker.WaitReady(readyCtx) }()
	qemuCollision := func() *vmGuestCIDCollisionError {
		detail, found := qemuCIDCollisionSince(qemuLogPath, qemuLogStart)
		if !found {
			return nil
		}
		// QEMU may write the kernel's EADDRINUSE diagnostic just before it
		// exits. Require the exact owned process to be gone before reporting a
		// retryable collision, but allow that short exit race to settle.
		deadline := time.Now().Add(time.Second)
		for {
			live, liveErr := vmProcessLive(record.QEMU)
			if liveErr != nil {
				return nil
			}
			if !live {
				return &vmGuestCIDCollisionError{CID: spec.VsockCID, Detail: detail}
			}
			if !time.Now().Before(deadline) {
				return nil
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	qmpOK, sshOK := false, false
	for !qmpOK || !sshOK {
		select {
		case err := <-qmpReady:
			if err != nil {
				if collision := qemuCollision(); collision != nil {
					return collision
				}
				return fmt.Errorf("QMP readiness: %w", err)
			}
			qmpOK = true
			qmpReady = nil
		case err := <-sshReady:
			if err != nil {
				if collision := qemuCollision(); collision != nil {
					return collision
				}
				return fmt.Errorf("guest SSH readiness: %w", err)
			}
			sshOK = true
			sshReady = nil
		case ended := <-exit:
			alive[ended.name] = false
			if ended.name == "qemu" {
				if detail, collision := qemuCIDCollisionSince(qemuLogPath, qemuLogStart); collision {
					return &vmGuestCIDCollisionError{CID: spec.VsockCID, Detail: detail}
				}
			}
			return fmt.Errorf("%s exited during QMP/SSH startup: %v", ended.name, ended.err)
		case <-signals:
			return fmt.Errorf("supervisor signaled during QMP/SSH startup")
		case line := <-commands:
			return fmt.Errorf("launcher command %q before QMP/SSH readiness", line)
		case <-precommitTimer.C:
			if !sshOK {
				return fmt.Errorf("guest SSH readiness: %w", context.DeadlineExceeded)
			}
			return fmt.Errorf("VM precommit deadline exceeded")
		}
	}
	var mountOutput bytes.Buffer
	verifyCtx, cancelVerify := context.WithDeadline(context.Background(), precommitDeadline)
	verifyErr := vmssh.Run(verifyCtx, sshSocket, vmssh.Request{
		User: "root", Command: "findmnt -n -o FSTYPE /home/user/workspace; findmnt -n -o FSTYPE /home/user/.zaigr-agent-state",
	}, nil, &mountOutput, io.Discard)
	cancelVerify()
	if verifyErr != nil {
		return fmt.Errorf("guest mount verification over vsock SSH: %w", verifyErr)
	}
	mounts := strings.Fields(mountOutput.String())
	if len(mounts) != 2 || mounts[0] != "virtiofs" || mounts[1] != "virtiofs" {
		return fmt.Errorf("guest mount verification failed (workspace and agent state must be virtiofs): %q", strings.TrimSpace(mountOutput.String()))
	}
	if err := verifyHostNetworkReady(networkHandle, &record, &recordMu); err != nil {
		return fmt.Errorf("host network failed before VM readiness: %w", err)
	}
	if _, err := io.WriteString(ready, "{\"state\":\"ready\"}\n"); err != nil {
		return err
	}
	for {
		select {
		case line := <-commands:
			switch line {
			case "commit":
				if committed {
					return fmt.Errorf("duplicate VM commit")
				}
				if !time.Now().Before(precommitDeadline) {
					return fmt.Errorf("VM precommit deadline exceeded")
				}
				for {
					select {
					case ended := <-exit:
						alive[ended.name] = false
						return fmt.Errorf("%s exited before commit: %v", ended.name, ended.err)
					default:
						goto drainedPrecommitExits
					}
				}
			drainedPrecommitExits:
				for _, name := range []string{"workspace", "agent-state", "qemu", "ssh-broker"} {
					if !alive[name] {
						return fmt.Errorf("%s exited before commit", name)
					}
				}
				for _, child := range []struct {
					name     string
					identity vmOwnedProcess
				}{
					{"workspace", record.WorkspaceDaemon}, {"workspace namespace child", record.WorkspaceDescendant},
					{"agent-state", record.AgentStateDaemon}, {"agent-state namespace child", record.AgentStateDescendant},
					{"QEMU", record.QEMU}, {"SSH broker", record.SSHBroker},
				} {
					if spec.VirtiofsSandbox == "none" && (child.name == "workspace namespace child" || child.name == "agent-state namespace child") {
						continue
					}
					live, err := vmProcessLive(child.identity)
					if err != nil {
						return fmt.Errorf("inspect %s before commit: %w", child.name, err)
					}
					if !live {
						return fmt.Errorf("%s exited before commit", child.name)
					}
				}
				if err := verifyHostNetworkReady(networkHandle, &record, &recordMu); err != nil {
					return fmt.Errorf("host network failed before VM commit: %w", err)
				}
				committed = true
				precommitTimer.Stop()
				if _, err := io.WriteString(ready, "{\"state\":\"committed\"}\n"); err != nil {
					return err
				}
				_ = ready.Close()
			case "stop":
				return nil
			case "__eof__":
				if !committed || spec.Mode == "attached" {
					return fmt.Errorf("VM launcher disconnected")
				}
			default:
				return fmt.Errorf("invalid supervisor control command %q", line)
			}
		case ended := <-exit:
			alive[ended.name] = false
			_, _ = fmt.Fprintf(supervisorLog, "%s exited: %v\n", ended.name, ended.err)
			if ended.name == "qemu" {
				return qemuExitResult(ended.err)
			}
			return fmt.Errorf("%s exited: %v", ended.name, ended.err)
		case sig := <-signals:
			_, _ = fmt.Fprintf(supervisorLog, "signal %s\n", sig)
			return nil
		case <-precommitTimer.C:
			return fmt.Errorf("VM startup commit deadline exceeded")
		}
	}
}

func waitVMSocket(path, name, logPath string, children map[string]*exec.Cmd, alive map[string]bool, exit <-chan vmChildExit, commands <-chan string, signals <-chan os.Signal) error {
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			info, err := os.Lstat(path)
			if err == nil && info.Mode()&os.ModeSocket != 0 {
				return nil
			}
			if err == nil {
				return fmt.Errorf("%s virtiofsd produced a non-socket path %s", name, path)
			}
		case ended := <-exit:
			alive[ended.name] = false
			failure := fmt.Sprintf("%s virtiofsd exited before %s socket readiness: %v", ended.name, name, ended.err)
			if ended.name == "workspace" || ended.name == "agent-state" {
				logPath = filepath.Join(filepath.Dir(logPath), "virtiofsd-"+ended.name+".log")
			}
			if log, err := os.Open(logPath); err == nil {
				if info, err := log.Stat(); err == nil {
					offset := info.Size() - 4096
					if offset < 0 {
						offset = 0
					}
					if _, err := log.Seek(offset, io.SeekStart); err == nil {
						if output, err := io.ReadAll(io.LimitReader(log, 4096)); err == nil {
							if detail := strings.TrimSpace(string(output)); detail != "" {
								failure += ": " + detail
							}
						}
					}
				}
				_ = log.Close()
			}
			return fmt.Errorf("%s; see %s", failure, logPath)
		case line := <-commands:
			return fmt.Errorf("launcher command %q before %s socket readiness", line, name)
		case <-signals:
			return fmt.Errorf("supervisor signaled before %s socket readiness", name)
		case <-deadline.C:
			return fmt.Errorf("%s virtiofsd socket deadline exceeded: %s", name, path)
		}
	}
}

func waitQMPReady(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("unix", path, 200*time.Millisecond)
		if err != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		_ = conn.SetDeadline(deadline)
		reader := bufio.NewReader(conn)
		var greeting map[string]json.RawMessage
		line, err := reader.ReadBytes('\n')
		if err == nil {
			err = json.Unmarshal(line, &greeting)
		}
		if err == nil && greeting["QMP"] != nil {
			_, err = io.WriteString(conn, "{\"execute\":\"qmp_capabilities\"}\n")
			if err == nil {
				line, err = reader.ReadBytes('\n')
			}
			if err == nil && strings.Contains(string(line), "\"return\"") {
				_ = conn.Close()
				return nil
			}
		}
		_ = conn.Close()
		if err != nil {
			return err
		}
	}
	return fmt.Errorf("QMP socket %s did not become ready", path)
}

func signalVerifiedVMProcess(process vmOwnedProcess, signal syscall.Signal) error {
	if process == (vmOwnedProcess{}) {
		return nil
	}
	handle, err := os.FindProcess(process.PID)
	if err != nil {
		return err
	}
	defer func() { _ = handle.Release() }()
	live, err := vmProcessLive(process)
	if err != nil {
		return err
	}
	if !live {
		return nil
	}
	if err := handle.Signal(signal); err != nil && !errors.Is(err, os.ErrProcessDone) && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	return nil
}

func daemonGroupMembers(process vmOwnedProcess) ([]vmOwnedProcess, error) {
	if process.ProcessGroup <= 0 {
		return nil, nil
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	members := make([]vmOwnedProcess, 0)
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
			continue
		}
		if err != nil {
			return nil, err
		}
		index := strings.LastIndexByte(string(data), ')')
		if index < 0 {
			return nil, fmt.Errorf("malformed process stat for PID %d", pid)
		}
		fields := strings.Fields(string(data[index+1:]))
		if len(fields) < 20 {
			return nil, fmt.Errorf("short process stat for PID %d", pid)
		}
		pgid, err := strconv.Atoi(fields[2])
		if err != nil {
			return nil, err
		}
		if pgid == process.ProcessGroup && fields[0] != "Z" && fields[0] != "X" {
			identity, err := vmProcessIdentity(pid)
			if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if identity.ProcessGroup == process.ProcessGroup {
				members = append(members, identity)
			}
		}
	}
	return members, nil
}

func discoverDaemonDescendant(parent vmOwnedProcess) (vmOwnedProcess, error) {
	members, err := daemonGroupMembers(parent)
	if err != nil {
		return vmOwnedProcess{}, err
	}
	parentNamespace, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", parent.PID))
	if err != nil {
		return vmOwnedProcess{}, err
	}
	for _, child := range members {
		if child.PID == parent.PID {
			continue
		}
		if child.ExeDevice != parent.ExeDevice || child.ExeInode != parent.ExeInode {
			continue
		}
		childNamespace, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", child.PID))
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
			continue
		}
		if err != nil {
			return vmOwnedProcess{}, err
		}
		if childNamespace == parentNamespace {
			continue
		}
		live, err := vmProcessLive(child)
		if err != nil {
			return vmOwnedProcess{}, err
		}
		if live {
			return child, nil
		}
	}
	return vmOwnedProcess{}, nil
}

func waitDaemonDescendant(parent vmOwnedProcess, deadline time.Time, exit <-chan vmChildExit, commands <-chan string, signals <-chan os.Signal, alive map[string]bool) (vmOwnedProcess, error) {
	for time.Now().Before(deadline) {
		child, err := discoverDaemonDescendant(parent)
		if err != nil {
			return vmOwnedProcess{}, err
		}
		if child.PID > 0 {
			return child, nil
		}
		select {
		case ended := <-exit:
			alive[ended.name] = false
			return vmOwnedProcess{}, fmt.Errorf("%s exited before namespace child readiness: %v", ended.name, ended.err)
		case line := <-commands:
			return vmOwnedProcess{}, fmt.Errorf("launcher command %q before namespace child readiness", line)
		case <-signals:
			return vmOwnedProcess{}, fmt.Errorf("supervisor signaled before namespace child readiness")
		case <-time.After(50 * time.Millisecond):
		}
	}
	return vmOwnedProcess{}, fmt.Errorf("virtiofsd namespace child did not start within supervisor deadline")
}

func signalVerifiedDaemonGroup(parent, descendant vmOwnedProcess, daemonPath string, signal syscall.Signal) error {
	members, err := daemonGroupMembers(parent)
	if err != nil {
		return err
	}
	if len(members) == 0 {
		return nil
	}
	if daemonGroupWasReused(parent, descendant, members) {
		return nil
	}
	anchored := false
	for _, identity := range []vmOwnedProcess{parent, descendant} {
		live, err := vmProcessLive(identity)
		if err != nil {
			return err
		}
		if !live {
			continue
		}
		pgid, err := syscall.Getpgid(identity.PID)
		if errors.Is(err, syscall.ESRCH) {
			continue
		}
		if err != nil {
			return err
		}
		if pgid != parent.ProcessGroup {
			continue
		}
		actual, err := vmProcessIdentity(identity.PID)
		if errors.Is(err, syscall.ESRCH) || errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("verify daemon executable: %w", err)
		}
		if actual.ExeDevice != identity.ExeDevice || actual.ExeInode != identity.ExeInode {
			return fmt.Errorf("daemon process identity changed executable")
		}
		anchored = true
	}
	if !anchored {
		remaining, err := daemonGroupMembers(parent)
		if err != nil {
			return err
		}
		if len(remaining) == 0 || daemonGroupWasReused(parent, descendant, remaining) {
			return nil
		}
		return fmt.Errorf("daemon group %d has unverified surviving members; refusing signal", parent.ProcessGroup)
	}
	for _, identity := range members {
		handle, err := os.FindProcess(identity.PID)
		if errors.Is(err, syscall.ESRCH) {
			continue
		}
		if err != nil {
			return err
		}
		actual, err := vmProcessIdentity(identity.PID)
		if errors.Is(err, syscall.ESRCH) || errors.Is(err, os.ErrNotExist) {
			_ = handle.Release()
			continue
		}
		if err != nil {
			_ = handle.Release()
			return err
		}
		if actual.StartTime != identity.StartTime || actual.ProcessGroup != identity.ProcessGroup || actual.ExeDevice != identity.ExeDevice || actual.ExeInode != identity.ExeInode || actual.ExeDevice != parent.ExeDevice || actual.ExeInode != parent.ExeInode {
			_ = handle.Release()
			return fmt.Errorf("daemon group contains unverified process %d", identity.PID)
		}
		live, liveErr := vmProcessLive(identity)
		if liveErr != nil {
			_ = handle.Release()
			return liveErr
		}
		if live {
			err = handle.Signal(signal)
		}
		_ = handle.Release()
		if err != nil && !errors.Is(err, os.ErrProcessDone) && !errors.Is(err, syscall.ESRCH) {
			return err
		}
	}
	return nil
}

func daemonGroupWasReused(parent, descendant vmOwnedProcess, members []vmOwnedProcess) bool {
	// The daemon creates a new session, so its original group leader is the
	// recorded parent. A different live leader with that PID proves that the
	// numeric group ID belongs to a later, unrelated session.
	for _, member := range members {
		if member.PID == parent.ProcessGroup && member.StartTime != parent.StartTime {
			return true
		}
	}
	// When the reused group's leader has itself exited, an entirely different
	// executable still proves these survivors do not belong to our daemon.
	unrelated := true
	for _, member := range members {
		if member.ExeDevice == parent.ExeDevice && member.ExeInode == parent.ExeInode {
			unrelated = false
		}
	}
	if unrelated {
		return true
	}
	_ = descendant
	return false
}

func daemonGroupsEmpty(record vmSupervisorRecord) (bool, error) {
	for _, pair := range [][2]vmOwnedProcess{{record.WorkspaceDaemon, record.WorkspaceDescendant}, {record.AgentStateDaemon, record.AgentStateDescendant}} {
		process := pair[0]
		members, err := daemonGroupMembers(process)
		if err != nil {
			return false, err
		}
		if len(members) > 0 && !daemonGroupWasReused(process, pair[1], members) {
			return false, nil
		}
	}
	return true, nil
}

func stopRecordedNetworkProcesses(record vmSupervisorRecord) error {
	processes := make([]vmOwnedProcess, 0, len(record.NetworkProcesses))
	for _, process := range record.NetworkProcesses {
		processes = append(processes, process)
	}
	for _, process := range processes {
		if err := signalVerifiedVMProcess(process, syscall.SIGTERM); err != nil {
			return err
		}
	}
	wait := func(deadline time.Time) error {
		for time.Now().Before(deadline) {
			allGone := true
			for _, process := range processes {
				live, err := vmProcessLive(process)
				if err != nil {
					return err
				}
				allGone = allGone && !live
			}
			if allGone {
				return nil
			}
			time.Sleep(50 * time.Millisecond)
		}
		return fmt.Errorf("host network processes did not stop before deadline")
	}
	if err := wait(time.Now().Add(2 * time.Second)); err == nil {
		return nil
	}
	for _, process := range processes {
		if err := signalVerifiedVMProcess(process, syscall.SIGKILL); err != nil {
			return err
		}
	}
	return wait(time.Now().Add(2 * time.Second))
}

func groupsEmpty(record vmSupervisorRecord) bool {
	empty, err := daemonGroupsEmpty(record)
	return err == nil && empty
}

func teardownVMChildren(spec vmLaunchSpec, record vmSupervisorRecord, children map[string]*exec.Cmd, alive map[string]bool, exit <-chan vmChildExit, log io.Writer, retainRecoveryMetadata bool) error {
	var cleanupErr error
	drain := func() {
		for {
			select {
			case ended := <-exit:
				alive[ended.name] = false
			default:
				return
			}
		}
	}
	drain()
	if alive["ssh-broker"] {
		cleanupErr = errors.Join(cleanupErr, signalVerifiedVMProcess(record.SSHBroker, syscall.SIGTERM))
		brokerDeadline := time.Now().Add(5 * time.Second)
		for alive["ssh-broker"] && time.Now().Before(brokerDeadline) {
			select {
			case ended := <-exit:
				alive[ended.name] = false
			case <-time.After(50 * time.Millisecond):
			}
		}
		if alive["ssh-broker"] {
			cleanupErr = errors.Join(cleanupErr, signalVerifiedVMProcess(record.SSHBroker, syscall.SIGKILL))
			brokerDeadline = time.Now().Add(2 * time.Second)
			for alive["ssh-broker"] && time.Now().Before(brokerDeadline) {
				select {
				case ended := <-exit:
					alive[ended.name] = false
				case <-time.After(50 * time.Millisecond):
				}
			}
		}
	}
	if alive["qemu"] {
		cleanupErr = errors.Join(cleanupErr, signalVerifiedVMProcess(record.QEMU, syscall.SIGTERM))
	}
	deadline := time.Now().Add(10 * time.Second)
	for alive["qemu"] && time.Now().Before(deadline) {
		select {
		case ended := <-exit:
			alive[ended.name] = false
		case <-time.After(50 * time.Millisecond):
		}
	}
	if alive["qemu"] {
		cleanupErr = errors.Join(cleanupErr, signalVerifiedVMProcess(record.QEMU, syscall.SIGKILL))
	}
	for _, pair := range [][2]vmOwnedProcess{{record.WorkspaceDaemon, record.WorkspaceDescendant}, {record.AgentStateDaemon, record.AgentStateDescendant}} {
		cleanupErr = errors.Join(cleanupErr, signalVerifiedDaemonGroup(pair[0], pair[1], spec.Virtiofsd, syscall.SIGTERM))
	}
	daemonDeadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(daemonDeadline) {
		drain()
		if !alive["workspace"] && !alive["agent-state"] && groupsEmpty(record) {
			break
		}
		select {
		case ended := <-exit:
			alive[ended.name] = false
		case <-time.After(50 * time.Millisecond):
		}
	}
	for _, pair := range [][2]vmOwnedProcess{{record.WorkspaceDaemon, record.WorkspaceDescendant}, {record.AgentStateDaemon, record.AgentStateDescendant}} {
		cleanupErr = errors.Join(cleanupErr, signalVerifiedDaemonGroup(pair[0], pair[1], spec.Virtiofsd, syscall.SIGKILL))
	}
	finalDeadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(finalDeadline) {
		drain()
		if !alive["workspace"] && !alive["agent-state"] && !alive["qemu"] && !alive["ssh-broker"] && groupsEmpty(record) {
			break
		}
		select {
		case ended := <-exit:
			alive[ended.name] = false
		case <-time.After(50 * time.Millisecond):
		}
	}
	groupsClear, groupErr := daemonGroupsEmpty(record)
	if alive["qemu"] || alive["workspace"] || alive["agent-state"] || alive["ssh-broker"] || !groupsClear || groupErr != nil {
		_, _ = fmt.Fprintln(log, "VM cleanup could not confirm process tree termination")
		return errors.Join(cleanupErr, groupErr, fmt.Errorf("VM cleanup could not confirm process tree termination; record retained"))
	}
	if retainRecoveryMetadata {
		_, _ = fmt.Fprintln(log, "VM cleanup encountered an unverified executable transition; recovery metadata retained")
		return errors.Join(cleanupErr, errors.New("VM cleanup encountered an unverified executable transition; record retained"))
	}
	cleanupPaths := []string{spec.WorkspaceSock, spec.WorkspaceSock + ".pid", spec.AgentStateSock, spec.AgentStateSock + ".pid", spec.MonitorSock}
	if spec.WorkspaceSockAlias != "" {
		cleanupPaths = append(cleanupPaths, spec.WorkspaceSockAlias)
	}
	if spec.AgentStateSockAlias != "" {
		cleanupPaths = append(cleanupPaths, spec.AgentStateSockAlias)
	}
	for _, path := range cleanupPaths {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}
	if spec.SocketDir != "" {
		if err := removeVMSocketDir(spec.SocketDir, spec.LaunchID); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}
	return cleanupErr
}

// placeSocketAlias writes a symlink at aliasPath pointing to target so the
// store runtime dir still exposes the virtiofs socket for troubleshooting
// even when the real socket lives in a short ephemeral directory. Any stale
// file or symlink at aliasPath is removed first. A no-op when aliasPath is
// empty (temporary VMs that keep sockets in their runtime dir directly).
func placeSocketAlias(aliasPath, target string) error {
	if aliasPath == "" {
		return nil
	}
	if err := os.Remove(aliasPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Symlink(target, aliasPath)
}

// Use a short, fixed parent independent of TMPDIR. The random launch identity
// prevents collisions between homes, users, and successive launches.
func vmSocketDir(launchID string) string {
	return filepath.Join("/tmp", fmt.Sprintf("zaigr-sockets-%d-%s", os.Geteuid(), launchID))
}

// Called only after the recorded process tree has been confirmed stopped.
// Remove known socket files, then the empty directory; never recursively remove
// an unrecognized entry or follow a substituted directory symlink.
func removeVMSocketDir(dir, launchID string) error {
	if dir == "" {
		return nil
	}
	if dir != vmSocketDir(launchID) {
		return fmt.Errorf("unsafe VM socket directory: %s", dir)
	}
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("VM socket directory was replaced: %s", dir)
	}
	for _, name := range []string{"workspace.sock", "workspace.sock.pid", "agent-state.sock", "agent-state.sock.pid", "ssh.sock"} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return os.Remove(dir)
}

func removeVMRuntime(record vmSupervisorRecord) error {
	if err := stopRecordedNetworkProcesses(record); err != nil {
		return err
	}
	if err := removeVMSocketDir(record.SocketDir, record.LaunchID); err != nil {
		return err
	}
	return os.RemoveAll(record.RuntimeDir)
}

func virtiofsDaemonArgs(shared, sock string, guestUID, guestGID int, sandbox string) []string {
	uid, gid := os.Geteuid(), os.Getegid()
	return []string{"--sandbox", sandbox, "--cache", "auto", "--inode-file-handles=never",
		"--shared-dir", shared, "--socket-path", sock,
		"--translate-uid", fmt.Sprintf("squash-guest:0:%d:1", uid),
		"--translate-uid", fmt.Sprintf("guest:%d:%d:1", guestUID, uid),
		"--translate-uid", fmt.Sprintf("host:%d:%d:1", uid, guestUID),
		"--translate-gid", fmt.Sprintf("squash-guest:0:%d:1", gid),
		"--translate-gid", fmt.Sprintf("guest:%d:%d:1", guestGID, gid),
		"--translate-gid", fmt.Sprintf("host:%d:%d:1", gid, guestGID)}
}
