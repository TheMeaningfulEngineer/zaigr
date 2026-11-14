package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// leaveTerminalCgroup moves the supervisor of a detached VM into its own
// systemd user scope, before it starts QEMU and the daemons, so they start
// there too. Otherwise they all stay in the cgroup of the terminal that ran
// zaigr. When that terminal is killed, systemd stops its cgroup and sends
// SIGTERM to every process in it at once, QEMU included, so the VM dies with
// the terminal although zaigr detached it from the terminal's session.
func leaveTerminalCgroup(launchID, workspace string) (string, error) {
	unit := "zaigr-vm-" + launchID + ".scope"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, findTool("busctl", "/usr/bin/busctl"), "--user", "call",
		"org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager",
		"StartTransientUnit", "ssa(sv)a(sa(sv))", unit, "fail",
		"3",
		"PIDs", "au", "1", strconv.Itoa(os.Getpid()),
		"Description", "s", "zaigr VM for "+workspace,
		"CollectMode", "s", "inactive-or-failed",
		"0",
	).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	// systemd moves the process when it runs the start job, which can be
	// just after the call returns.
	deadline := time.Now().Add(3 * time.Second)
	for {
		cgroup, err := os.ReadFile("/proc/self/cgroup")
		if err == nil && strings.Contains(string(cgroup), "/"+unit+"\n") {
			return unit, nil
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("systemd did not move the supervisor into %s", unit)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
