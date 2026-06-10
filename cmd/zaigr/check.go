package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/spf13/cobra"
)

const (
	colorGreen = "\033[32m"
	colorRed   = "\033[31m"
	colorReset = "\033[0m"
)

func newCheckCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "check",
		Short: "Verify host requirements for running zaigr VMs",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cmdCheck()
		},
	}
}

type checkResult struct {
	name   string
	detail string
	passed bool
}

func cmdCheck() error {
	checks := []checkResult{
		checkKVM(),
		checkQEMU(),
		checkDiskSpace(),
	}

	passed := 0
	for _, c := range checks {
		if c.passed {
			fmt.Printf("  %s✓%s %s", colorGreen, colorReset, c.name)
			passed++
		} else {
			fmt.Printf("  %s✗%s %s", colorRed, colorReset, c.name)
		}
		if c.detail != "" {
			fmt.Printf(" (%s)", c.detail)
		}
		fmt.Println()
	}

	fmt.Printf("\n  %d/%d checks passed\n", passed, len(checks))

	if passed < len(checks) {
		return exitError(1)
	}
	return nil
}

func checkKVM() checkResult {
	if err := requireKVMAccess(); err != nil {
		return checkResult{name: "KVM available", detail: err.Error(), passed: false}
	}

	return checkResult{name: "KVM available", detail: "/dev/kvm", passed: true}
}

func requireKVMAccess() error {
	if _, err := os.Stat("/dev/kvm"); err != nil {
		return fmt.Errorf("KVM not available (/dev/kvm not found) — zaigr requires hardware virtualization")
	}
	f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("KVM not usable (/dev/kvm is not readable and writable by this user) — add user to kvm group")
	}
	f.Close()
	return nil
}

func checkQEMU() checkResult {
	path, err := exec.LookPath("qemu-system-x86_64")
	if err != nil {
		return checkResult{name: "QEMU installed", detail: "qemu-system-x86_64 not found in PATH", passed: false}
	}

	out, err := exec.Command(path, "--version").Output()
	if err != nil {
		return checkResult{name: "QEMU installed", detail: path, passed: true}
	}

	line := string(out)
	for i, c := range line {
		if c == '\n' {
			line = line[:i]
			break
		}
	}
	return checkResult{name: "QEMU installed", detail: line, passed: true}
}

func checkDiskSpace() checkResult {
	var stat syscall.Statfs_t
	home, _ := os.UserHomeDir()
	if err := syscall.Statfs(home, &stat); err != nil {
		return checkResult{name: "disk space", detail: "cannot stat home directory", passed: false}
	}

	freeGB := (stat.Bavail * uint64(stat.Bsize)) / (1024 * 1024 * 1024)
	if freeGB < 4 {
		return checkResult{
			name:   "disk space",
			detail: fmt.Sprintf("%d GB free, need 4 GB", freeGB),
			passed: false,
		}
	}
	return checkResult{
		name:   "disk space",
		detail: fmt.Sprintf("%d GB free", freeGB),
		passed: true,
	}
}
