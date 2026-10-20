package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"zaigr/cmd/zaigr/hostnet"
)

func newHostNetworkHelperCommand() *cobra.Command {
	var socketPath, launchID string
	var hostUID int
	var eventFD int
	var parentPID int
	var hostUserNS, hostNetNS uint64
	cmd := &cobra.Command{
		Use:           "__host-network-helper",
		Hidden:        true,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := hostnet.RunHelper(socketPath, launchID, hostUID, parentPID, hostUserNS, hostNetNS, eventFD); err != nil {
				return fmt.Errorf("host network helper: %w", err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&socketPath, "socket", "", "private helper socket")
	cmd.Flags().StringVar(&launchID, "launch-id", "", "launch identity")
	cmd.Flags().IntVar(&hostUID, "host-uid", -1, "expected mapped host UID for controller IPC")
	cmd.Flags().IntVar(&eventFD, "event-fd", -1, "private firewall event channel descriptor")
	cmd.Flags().IntVar(&parentPID, "parent-pid", -1, "expected controller PID")
	cmd.Flags().Uint64Var(&hostUserNS, "host-user-ns", 0, "initial user namespace identity")
	cmd.Flags().Uint64Var(&hostNetNS, "host-net-ns", 0, "initial network namespace identity")
	return cmd
}
