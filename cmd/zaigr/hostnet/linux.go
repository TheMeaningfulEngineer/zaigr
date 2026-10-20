//go:build linux

package hostnet

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Start creates the private network and returns only after the policy helper
// and rootless uplink have acknowledged readiness. Any partial startup is
// torn down; callers must not continue with QEMU on error.
func Start(ctx context.Context, opts Options) (Runtime, error) {
	return startLinux(ctx, opts)
}

func preflight(opts Options) error {
	if opts.LaunchID == "" || opts.RuntimeDir == "" || opts.Executable == "" {
		return errors.New("host network requires launch ID, runtime directory, and executable")
	}
	if opts.SlirpPath == "" {
		return errors.New("slirp4netns is required for host-enforced networking")
	}
	if st, err := os.Stat("/dev/net/tun"); err != nil || st.Mode()&os.ModeDevice == 0 {
		return errors.New("host-enforced networking requires /dev/net/tun")
	}
	if os.Geteuid() == 0 {
		return errors.New("host-enforced rootless networking must run as an unprivileged host user")
	}
	return nil
}

// RootlessUserNamespaceSysProcAttr creates the child in a user namespace
// whose root maps to the invoking host UID/GID. The namespace clone is issued
// by the calling Zaigr process rather than a system utility, so path-scoped
// host userns policy can authorize Zaigr itself.
func RootlessUserNamespaceSysProcAttr(network bool) *syscall.SysProcAttr {
	flags := uintptr(syscall.CLONE_NEWUSER)
	if network {
		flags |= uintptr(syscall.CLONE_NEWNET)
	}
	return &syscall.SysProcAttr{
		Cloneflags: flags,
		UidMappings: []syscall.SysProcIDMap{{
			ContainerID: 0,
			HostID:      os.Getuid(),
			Size:        1,
		}},
		GidMappings: []syscall.SysProcIDMap{{
			ContainerID: 0,
			HostID:      os.Getgid(),
			Size:        1,
		}},
		GidMappingsEnableSetgroups: false,
	}
}

func cleanIPv4Addresses(in []netip.Addr) ([]netip.Addr, error) {
	out := make([]netip.Addr, 0, len(in))
	seen := map[netip.Addr]bool{}
	for _, a := range in {
		if !a.IsValid() || !a.Is4() || a.IsUnspecified() || a.IsMulticast() || a.IsLoopback() || a.IsLinkLocalUnicast() || a == netip.MustParseAddr("10.0.2.3") || a == netip.MustParseAddr("10.0.2.15") || a == netip.MustParseAddr("10.0.2.1") || a.IsGlobalUnicast() && a.IsPrivate() && a.As4()[0] == 10 && a.As4()[1] == 0 && a.As4()[2] == 3 {
			return nil, fmt.Errorf("host firewall grant is reserved or invalid: %s", a)
		}
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out, nil
}

func privateRuntimeDir(path string) error {
	if err := os.Mkdir(path, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("host network runtime directory must be a pre-created private real directory: %s", path)
	}
	return nil
}

func namespaceInode(path string) (uint64, error) {
	st, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	raw, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("namespace stat has unexpected type")
	}
	return raw.Ino, nil
}

func socketPath(runtimeDir, name string) string { return filepath.Join(runtimeDir, name+".sock") }

func closeFiles(files ...*os.File) {
	for _, f := range files {
		if f != nil {
			_ = f.Close()
		}
	}
}

func hostNetworkError(op string, err error) error {
	return fmt.Errorf("host-enforced network %s: %w", op, err)
}

func waitUntil(ctx context.Context, deadline time.Time, fn func() (bool, error)) error {
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		ok, err := fn()
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("readiness deadline exceeded")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

func helperArgs(socket, launchID string, hostUID, parentPID int, hostUserNS, hostNetNS uint64, eventFD int) []string {
	return []string{"__host-network-helper", "--socket", socket, "--launch-id", launchID, "--host-uid", strconv.Itoa(hostUID), "--parent-pid", strconv.Itoa(parentPID), "--host-user-ns", strconv.FormatUint(hostUserNS, 10), "--host-net-ns", strconv.FormatUint(hostNetNS, 10), "--event-fd", strconv.Itoa(eventFD)}
}

func commandContext(ctx context.Context, path string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Pdeathsig: syscall.SIGKILL}
	return cmd
}

func nonempty(s string) bool { return strings.TrimSpace(s) != "" }
