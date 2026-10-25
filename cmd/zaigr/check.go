package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"zaigr/cmd/zaigr/hostnet"
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
	name         string
	detail       string
	summary      string
	guidance     string
	passed       bool
	missingTools string
}

func cmdCheck() error {
	host := detectCheckHost()
	fmt.Printf("Host: %s (kernel %s)\n", host.name, host.kernel)
	checks := collectHostPreflight(host)

	passed := printHostChecks(checks)
	fmt.Printf("\n  %d/%d checks passed\n", passed, len(checks))

	if passed < len(checks) {
		fmt.Println()
		printHostPreflightGuidance(checks)
		printHostPreflightAdvice(host, checks)
		return exitError(1)
	}
	return nil
}

func collectHostPreflight(host checkHost) []checkResult {
	return []checkResult{
		checkKVM(),
		checkVhostVSock(),
		checkQEMU(),
		checkHostTools(host),
		checkVirtiofs(host),
		checkDiskSpace(),
		checkHostNetworking(host),
	}
}

func printHostChecks(checks []checkResult) int {
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

	return passed
}

func requireHostPreflight(operation string) error {
	host := detectCheckHost()
	checks := collectHostPreflight(host)
	var failed []checkResult
	for _, check := range checks {
		if !check.passed {
			failed = append(failed, check)
		}
	}
	return formatHostPreflightFailure(operation, host, failed)
}

func formatHostPreflightFailure(operation string, host checkHost, failed []checkResult) error {
	if len(failed) == 0 {
		return nil
	}
	var details []string
	missingTools := make(map[string]bool)
	for _, check := range failed {
		detail := check.name
		if check.summary != "" {
			detail += ": " + check.summary
		} else if check.detail != "" {
			detail += ": " + shortPreflightDetail(check.detail)
		}
		details = append(details, detail)
		for _, tool := range strings.Split(check.missingTools, ",") {
			if tool = strings.TrimSpace(tool); tool != "" {
				missingTools[tool] = true
			}
		}
	}
	message := fmt.Sprintf("Host preflight failed before %s.\n%s\nRun 'zaigr misc check' for the full host report.", operation, strings.Join(details, "\n"))
	guidance := hostPreflightGuidance(failed)
	if guidance != "" {
		message += "\n\n" + guidance
	}
	packages := hostPreflightPackageGuidance(host, missingTools)
	if packages != "" {
		message += "\n\n" + packages
	}
	return errors.New(message)
}

func shortPreflightDetail(detail string) string {
	line, _, _ := strings.Cut(detail, "\n")
	return strings.TrimSpace(line)
}

func hostPreflightPackageGuidance(host checkHost, missing map[string]bool) string {
	if len(missing) == 0 {
		return ""
	}
	if !host.family("debian") && !host.family("ubuntu") {
		return "Missing tool names are listed above; install their providers for " + host.name + "."
	}
	packages := map[string]bool{}
	for tool := range missing {
		switch tool {
		case "qemu-system-x86_64":
			packages["qemu-system-x86"] = true
		case "qemu-img":
			packages["qemu-utils"] = true
		case "debugfs", "e2fsck", "resize2fs", "dumpe2fs":
			packages["e2fsprogs"] = true
		}
	}
	var ordered []string
	for _, name := range []string{"qemu-system-x86", "qemu-utils", "e2fsprogs"} {
		if packages[name] {
			ordered = append(ordered, name)
		}
	}
	if len(ordered) == 0 {
		return ""
	}
	message := "Install missing packages: sudo apt install " + strings.Join(ordered, " ")
	return message
}

func printHostPreflightAdvice(host checkHost, checks []checkResult) {
	missing := make(map[string]bool)
	for _, check := range checks {
		for _, tool := range strings.Split(check.missingTools, ",") {
			if tool = strings.TrimSpace(tool); tool != "" {
				missing[tool] = true
			}
		}
	}
	if message := hostPreflightPackageGuidance(host, missing); message != "" {
		fmt.Println(message)
	}
}

func hostPreflightGuidance(checks []checkResult) string {
	seen := make(map[string]bool)
	var blocks []string
	for _, check := range checks {
		if !check.passed && check.guidance != "" && !seen[check.guidance] {
			seen[check.guidance] = true
			blocks = append(blocks, check.guidance)
		}
	}
	return strings.Join(blocks, "\n\n")
}

func printHostPreflightGuidance(checks []checkResult) {
	if guidance := hostPreflightGuidance(checks); guidance != "" {
		fmt.Println(guidance)
	}
}

func checkHostNetworking(host checkHost) checkResult {
	var details []string
	var summary []string
	var guidance string
	failed := false
	runtimeCanRun := true
	if st, err := os.Stat("/dev/net/tun"); err != nil || st.Mode()&os.ModeDevice == 0 || st.Mode()&os.ModeCharDevice == 0 {
		failed = true
		runtimeCanRun = false
		summary = append(summary, "/dev/net/tun is missing or not a character device")
		details = append(details, "/dev/net/tun: missing or not a character device")
	}
	if os.Geteuid() == 0 {
		failed = true
		runtimeCanRun = false
		summary = append(summary, "Zaigr must run as an unprivileged account")
		details = append(details, "host user: zaigr must run as an unprivileged account, not uid 0")
	}
	probeStarted := time.Now()
	probeCtx, probeCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer probeCancel()
	probe := exec.CommandContext(probeCtx, "/bin/true")
	probe.SysProcAttr = hostnet.RootlessUserNamespaceSysProcAttr(true)
	probe.WaitDelay = time.Second
	if out, err := probe.CombinedOutput(); err != nil {
		failed = true
		runtimeCanRun = false
		summary = append(summary, "could not create user/network namespaces")
		detail := strings.TrimSpace(string(out))
		if detail == "" {
			detail = err.Error()
		}
		pids := map[int]bool{os.Getpid(): true}
		audit := readProbeKernelAudit(host, virtiofsProbe{started: probeStarted, ended: time.Now(), pids: pids})
		report := "Zaigr user/network namespace probe:\n  operation: exec /bin/true with clone(CLONE_NEWUSER|CLONE_NEWNET) and single-UID/GID mappings\n  result: " + detail + "\n  " + audit.detail + "\nHost context:\n" + host.context()
		details = append(details, report)
		guidance = hostNamespaceGuidance(host)
	}
	if tun, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0); err == nil {
		_ = tun.Close()
	} else {
		failed = true
		runtimeCanRun = false
		summary = append(summary, "cannot open /dev/net/tun read/write")
		details = append(details, "open /dev/net/tun read/write: "+err.Error())
	}
	if runtimeCanRun {
		if err := probeHostNetworkRuntime(); err != nil {
			failed = true
			summary = append(summary, "could not start the disposable host network runtime: "+boundedPreflightCause(err))
			details = append(details, "Disposable host-network namespace probe:\n  operation: Zaigr-created user/network namespace followed by a no-VM TAP/nftables/slirp start/stop\n  result: "+err.Error()+"\n  diagnosis: "+networkRuntimeDiagnosis(host, err))
		} else if failed {
			details = append(details, "Bundled slirp4netns "+strings.TrimSpace(embeddedSlirp4netnsVersion)+" started and stopped.")
		}
	}
	if failed {
		report := []string{"Bundled slirp4netns version: " + strings.TrimSpace(embeddedSlirp4netnsVersion)}
		report = append(report, details...)
		return checkResult{name: "host-enforced networking", detail: strings.Join(report, "\n"), summary: strings.Join(summary, "; "), guidance: guidance}
	}
	return checkResult{name: "host-enforced networking", detail: "bundled slirp4netns " + strings.TrimSpace(embeddedSlirp4netnsVersion) + "; disposable host namespace, TAP, nftables controller and slirp start/stop probe passed; this does not verify outbound traffic or every later runtime condition", passed: true}
}

func boundedPreflightCause(err error) string {
	if err == nil {
		return "unknown error"
	}
	text := strings.Join(strings.Fields(err.Error()), " ")
	const maxRunes = 240
	runes := []rune(text)
	if len(runes) > maxRunes {
		const headRunes = 80
		const tailRunes = maxRunes - headRunes - 3
		return string(runes[:headRunes]) + "..." + string(runes[len(runes)-tailRunes:])
	}
	return text
}

func networkRuntimeDiagnosis(host checkHost, err error) string {
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "tun"):
		return "The disposable runtime failed while preparing TAP. Review /dev/net/tun access, kernel TUN support, and the exact error above; no cause is inferred from namespace settings."
	case strings.Contains(text, "nft") || strings.Contains(text, "netlink") || strings.Contains(text, "operation not permitted"):
		return "The namespace probe passed but disposable firewall setup failed. The exact operation/error is above; host kernel nftables support or a host security policy may be involved, but this probe does not identify which. Observed host settings:\n" + host.context()
	default:
		return "The namespace probe passed but a later disposable network startup step failed. The exact operation/error is above; review it with the host administrator. Observed host settings:\n" + host.context()
	}
}

func checkHostToolPath(name string) (string, error) {
	if path, err := exec.LookPath(name); err == nil {
		return path, nil
	}
	return "", fmt.Errorf("not found in PATH")
}

func probeHostNetworkRuntime() (returnErr error) {
	slirp, err := ensureSlirp4netnsWithWriter(false, io.Discard)
	if err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		return errors.New("host-enforced networking must run as an unprivileged account")
	}
	dir, err := os.MkdirTemp("/tmp", "zaigr-network-check-")
	if err != nil {
		return fmt.Errorf("create private temporary runtime directory: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("remove disposable network runtime directory: %w", err))
		}
	}()
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve zaigr helper executable: %w", err)
	}
	launchID, err := newVMLaunchID()
	if err != nil {
		return fmt.Errorf("create disposable launch identity: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 17*time.Second)
	runtime, err := hostnet.Start(ctx, hostnet.Options{
		LaunchID: launchID, RuntimeDir: filepath.Clean(dir), Executable: executable,
		SlirpPath: slirp,
	})
	defer cancel()
	if err != nil {
		logPath := filepath.Join(dir, "network-helper.log")
		if log, readErr := os.ReadFile(logPath); readErr == nil {
			if len(log) > 4096 {
				log = log[len(log)-4096:]
			}
			if detail := strings.TrimSpace(string(log)); detail != "" {
				return fmt.Errorf("%w; network helper log: %s", err, detail)
			}
		}
		return err
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	if err := runtime.Stop(stopCtx); err != nil {
		return fmt.Errorf("stop disposable host-network runtime: %w", err)
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

func checkVhostVSock() checkResult {
	info, err := os.Stat("/dev/vhost-vsock")
	if err != nil || info.Mode()&os.ModeDevice == 0 || info.Mode()&os.ModeCharDevice == 0 {
		return checkResult{
			name:   "vhost-vsock available",
			detail: "/dev/vhost-vsock is missing or not a character device; enable the host vhost-vsock device for SSH access to project VMs",
			passed: false,
		}
	}
	device, err := os.OpenFile("/dev/vhost-vsock", os.O_RDWR, 0)
	if err != nil {
		return checkResult{
			name:   "vhost-vsock available",
			detail: "/dev/vhost-vsock is not readable and writable by this user; add the user to the kvm group",
			passed: false,
		}
	}
	if err := device.Close(); err != nil {
		return checkResult{name: "vhost-vsock available", detail: "close /dev/vhost-vsock: " + err.Error(), passed: false}
	}
	return checkResult{name: "vhost-vsock available", detail: "/dev/vhost-vsock", passed: true}
}

func checkQEMU() checkResult {
	path, err := exec.LookPath("qemu-system-x86_64")
	if err != nil {
		return checkResult{name: "QEMU installed", detail: "qemu-system-x86_64 not found in PATH", missingTools: "qemu-system-x86_64"}
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
		{"qemu-img", "/usr/bin/qemu-img"},
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
		return checkResult{name: "host tools", detail: "missing host tools: " + strings.Join(missing, ", "), missingTools: strings.Join(missing, ", ")}
	}
	return checkResult{name: "host tools", detail: "qemu-img, debugfs, e2fsck, resize2fs, dumpe2fs", passed: true}
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
