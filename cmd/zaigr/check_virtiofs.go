package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func checkVirtiofs(host checkHost) checkResult {
	result := checkVirtiofsMode(host, "namespace")
	if !result.passed {
		result.summary = "could not start the required filesystem sandbox"
		result.guidance = hostNamespaceGuidance(host)
	}
	if mode, err := currentProjectStore().virtiofsSandbox(); err == nil && mode == "none" {
		result.detail += "\nProject setting: virtiofs-sandbox=none is unsupported; use virtiofs-sandbox=namespace after resolving the host restriction."
	}
	return result
}

func checkVirtiofsMode(host checkHost, sandbox string) checkResult {
	result := checkResult{name: "virtiofs sandbox"}
	daemon, err := ensureVirtiofsdWithWriter(false, io.Discard)
	if err != nil {
		result.detail = err.Error()
		return result
	}
	// Keep socket paths short, independent of HOME and TMPDIR. Export only a
	// disposable empty directory, never the caller's project or agent state.
	dir, err := os.MkdirTemp("/tmp", "zaigr-check-")
	if err != nil {
		result.detail = fmt.Sprintf("create private probe directory in /tmp: %v", err)
		return result
	}
	defer func() { _ = os.RemoveAll(dir) }()
	shared := filepath.Join(dir, "export")
	if err := os.Mkdir(shared, 0700); err != nil {
		result.detail = err.Error()
		return result
	}
	logPath := filepath.Join(dir, "daemon.log")
	probe, err := probeVirtiofs(daemon, shared, filepath.Join(dir, "fs.sock"), logPath, sandbox)
	if err == nil {
		result.passed = true
		result.detail = "bundled daemon entered its sandbox and answered a vhost-user request"
		if sandbox == "none" {
			result.detail = "bundled daemon answered a vhost-user request without a namespace sandbox"
		}
		return result
	}
	log, readErr := os.ReadFile(logPath)
	if readErr != nil {
		log = []byte(fmt.Sprintf("cannot read daemon log: %v", readErr))
	}
	if len(log) > 8192 {
		log = log[len(log)-8192:]
	}
	audit := readProbeKernelAudit(host, probe)
	text := string(log)
	detail := diagnoseVirtiofs(host, text, audit) + fmt.Sprintf("\nProbe failure: %v\nDaemon: %s\n%s", err, daemon, host.context())
	result.detail = detail + "\n" + audit.detail + "\nDaemon output:\n" + strings.TrimSpace(text)
	return result
}

type virtiofsProbe struct {
	started time.Time
	ended   time.Time
	pids    map[int]bool
}

func probeVirtiofs(daemon, shared, socket, logPath, sandbox string) (probe virtiofsProbe, probeErr error) {
	probe = virtiofsProbe{started: time.Now(), pids: make(map[int]bool)}
	defer func() { probe.ended = time.Now() }()
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return probe, err
	}
	defer func() { _ = log.Close() }()
	// Guest identity does not affect namespace entry; use the factory identity
	// without extracting or inspecting a guest disk image.
	cmd := exec.Command(daemon, virtiofsDaemonArgs(shared, socket, 1000, 1001, sandbox)...)
	cmd.Stdout, cmd.Stderr = log, log
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		return probe, fmt.Errorf("execute bundled virtiofsd: %w", err)
	}
	probe.pids[cmd.Process.Pid] = true
	defer func() {
		// Do not reap the parent until after signalling its private group: its
		// unreaped PID keeps the group ID from being reused by another process.
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if err != nil && !errors.Is(err, syscall.ESRCH) {
			probeErr = errors.Join(probeErr, fmt.Errorf("stop probe process group: %w", err))
		}
		_ = cmd.Wait()
	}()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		// Capture namespace children when observable, so audit attribution uses
		// this probe's PIDs rather than another running virtiofs daemon's name.
		if children, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/children", cmd.Process.Pid, cmd.Process.Pid)); err == nil {
			for _, child := range strings.Fields(string(children)) {
				if pid, err := strconv.Atoi(child); err == nil {
					probe.pids[pid] = true
				}
			}
		}
		state, _, _, err := readQemuProcessState(cmd.Process.Pid)
		if err != nil || state == 'Z' || state == 'X' {
			return probe, fmt.Errorf("virtiofsd exited before sandbox readiness; see daemon output below")
		}
		conn, err := net.DialTimeout("unix", socket, 100*time.Millisecond)
		if err != nil {
			time.Sleep(25 * time.Millisecond)
			continue
		}
		defer func() { _ = conn.Close() }()
		if err := conn.SetDeadline(deadline); err != nil {
			return probe, err
		}
		// The listening socket exists BEFORE sandbox entry. A successful dial
		// is insufficient: GET_FEATURES must be answered by the sandboxed child.
		// vhost-user header: request=1, version=1, payload size=0 (little endian).
		request := [3]uint32{1, 1, 0}
		if err := binary.Write(conn, binary.LittleEndian, request); err != nil {
			return probe, fmt.Errorf("send sandbox readiness request: %w", err)
		}
		var reply [20]byte // 12-byte header followed by the 64-bit feature mask.
		if _, err := io.ReadFull(conn, reply[:]); err != nil {
			return probe, fmt.Errorf("sandbox did not answer readiness request: %w", err)
		}
		if binary.LittleEndian.Uint32(reply[0:4]) != 1 || binary.LittleEndian.Uint32(reply[4:8]) != 5 || binary.LittleEndian.Uint32(reply[8:12]) != 8 {
			return probe, fmt.Errorf("invalid sandbox readiness response")
		}
		return probe, nil
	}
	return probe, fmt.Errorf("virtiofsd sandbox readiness timed out after 10 seconds")
}
