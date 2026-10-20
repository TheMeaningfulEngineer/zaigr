package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"zaigr/cmd/zaigr/hostdns"
)

func newHostDNSFrontendCommand() *cobra.Command {
	var ipcPath string
	var udpFD, tcpFD, readyFD int
	cmd := &cobra.Command{
		Use:           "__host-dns-frontend",
		Hidden:        true,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
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
	cmd.Flags().IntVar(&udpFD, "udp-fd", -1, "inherited guest DNS UDP socket descriptor")
	cmd.Flags().IntVar(&tcpFD, "tcp-fd", -1, "inherited guest DNS TCP socket descriptor")
	cmd.Flags().IntVar(&readyFD, "ready-fd", -1, "inherited frontend readiness descriptor")
	return cmd
}

func reportHostDNSFrontendError(err error) error {
	_, _ = fmt.Fprintln(os.Stderr, err)
	return err
}
