package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
	"zaigr/cmd/zaigr/hostdns"
)

func newHostDNSFrontendCommand() *cobra.Command {
	var ipcPath string
	var udpFD, tcpFD, readyFD int
	var bootstrapPrivileges bool
	cmd := &cobra.Command{
		Use:           "__host-dns-frontend",
		Hidden:        true,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if bootstrapPrivileges {
				if err := dropFrontendPrivilegesAndReexec(); err != nil {
					return reportHostDNSFrontendError(fmt.Errorf("host DNS frontend privilege drop: %w", err))
				}
				return nil
			}
			if udpFD < 0 || tcpFD < 0 || readyFD < 0 || udpFD == tcpFD || udpFD == readyFD || tcpFD == readyFD {
				return reportHostDNSFrontendError(fmt.Errorf("host DNS frontend: invalid inherited descriptor numbers"))
			}
			if err := hostdns.RunFrontend(context.Background(), hostdns.FrontendConfig{
				UDPFD: udpFD, TCPFD: tcpFD, ReadyFD: readyFD, IPCPath: ipcPath,
			}); err != nil {
				return reportHostDNSFrontendError(fmt.Errorf("host DNS frontend: %w", err))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&ipcPath, "ipc", "", "private host DNS broker socket")
	cmd.Flags().BoolVar(&bootstrapPrivileges, "bootstrap-privileges", false, "drop all Linux capabilities before re-executing the DNS frontend")
	cmd.Flags().IntVar(&udpFD, "udp-fd", -1, "inherited guest DNS UDP socket descriptor")
	cmd.Flags().IntVar(&tcpFD, "tcp-fd", -1, "inherited guest DNS TCP socket descriptor")
	cmd.Flags().IntVar(&readyFD, "ready-fd", -1, "inherited frontend readiness descriptor")
	return cmd
}

func dropFrontendPrivilegesAndReexec() error {
	runtime.LockOSThread()
	capLast, err := os.ReadFile("/proc/sys/kernel/cap_last_cap")
	if err != nil {
		return fmt.Errorf("read kernel capability limit: %w", err)
	}
	lastCapability, err := strconv.Atoi(strings.TrimSpace(string(capLast)))
	if err != nil || lastCapability < 0 || lastCapability > 1024 {
		return fmt.Errorf("invalid kernel capability limit %q", strings.TrimSpace(string(capLast)))
	}
	for capability := 0; capability <= lastCapability; capability++ {
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(capability), 0, 0, 0); err != nil {
			return fmt.Errorf("drop bounding capability %d: %w", capability, err)
		}
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return fmt.Errorf("clear ambient capabilities: %w", err)
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{}
	if err := unix.Capset(&header, &data[0]); err != nil {
		return fmt.Errorf("clear effective, permitted, and inheritable capabilities: %w", err)
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set no_new_privs: %w", err)
	}
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve frontend executable: %w", err)
	}
	args := make([]string, 0, len(os.Args))
	for _, arg := range os.Args {
		if arg != "--bootstrap-privileges" && !strings.HasPrefix(arg, "--bootstrap-privileges=") {
			args = append(args, arg)
		}
	}
	if err := syscall.Exec(executable, args, os.Environ()); err != nil {
		return fmt.Errorf("re-exec capless frontend: %w", err)
	}
	return nil
}

func reportHostDNSFrontendError(err error) error {
	_, _ = fmt.Fprintln(os.Stderr, err)
	return err
}
