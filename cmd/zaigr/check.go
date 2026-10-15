package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

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
	host := detectCheckHost()
	fmt.Printf("Host: %s (kernel %s)\n", host.name, host.kernel)
	checks := []checkResult{
		checkKVM(),
		checkQEMU(),
		checkHostTools(host),
		checkVirtiofs(host),
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
			fmt.Printf("\n    %s", strings.ReplaceAll(c.detail, "\n", "\n    "))
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
	if err := f.Close(); err != nil {
		return fmt.Errorf("close /dev/kvm: %w", err)
	}
	return nil
}

func checkQEMU() checkResult {
	path, err := exec.LookPath("qemu-system-x86_64")
	if err != nil {
		return checkResult{name: "QEMU installed", detail: "qemu-system-x86_64 not found in PATH", passed: false}
	}

	out, err := checkCommandOutput(path, "--version")
	if err != nil {
		return checkResult{name: "QEMU usable", detail: fmt.Sprintf("%s: %v", path, err)}
	}
	for _, feature := range []struct{ option, name string }{
		{"-device", "vhost-user-fs-device"},
		{"-object", "memory-backend-memfd"},
	} {
		help, err := checkCommandOutput(path, feature.option, "help")
		if err != nil {
			return checkResult{name: "QEMU virtiofs support", detail: fmt.Sprintf("%s %s help failed: %v", path, feature.option, err)}
		}
		if !strings.Contains(string(help), feature.name) {
			return checkResult{name: "QEMU virtiofs support", detail: fmt.Sprintf("%s lacks %s; install a QEMU build with virtiofs and shared memfd support", path, feature.name)}
		}
	}
	return checkResult{name: "QEMU virtiofs support", detail: strings.SplitN(string(out), "\n", 2)[0], passed: true}
}

func checkCommandOutput(path string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.WaitDelay = time.Second
	return cmd.CombinedOutput()
}

func checkHostTools(host checkHost) checkResult {
	var missing []string
	for _, tool := range []struct{ name, fallback string }{
		{"qemu-img", "/usr/bin/qemu-img"}, {"ssh", ""}, {"ssh-keygen", ""},
		{"debugfs", "/usr/sbin/debugfs"}, {"e2fsck", "/sbin/e2fsck"},
		{"resize2fs", "/sbin/resize2fs"}, {"dumpe2fs", "/sbin/dumpe2fs"},
	} {
		path := tool.name
		if tool.fallback != "" {
			path = findTool(tool.name, tool.fallback)
		}
		if _, err := exec.LookPath(path); err != nil {
			missing = append(missing, tool.name)
		}
	}
	if len(missing) > 0 {
		advice := "install packages providing these tools for " + host.name
		if host.family("debian") || host.family("ubuntu") {
			advice = "install qemu-utils, openssh-client and e2fsprogs"
		}
		return checkResult{name: "host tools", detail: "missing host tools: " + strings.Join(missing, ", ") + "; " + advice}
	}
	return checkResult{name: "host tools", detail: "qemu-img, ssh, ssh-keygen, debugfs, e2fsck, resize2fs, dumpe2fs", passed: true}
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
