package main

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

// zaigr data directory: ~/.zaigr/
func zaigDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".zaigr"
	}
	return filepath.Join(home, ".zaigr")
}

func newShellCommand() *cobra.Command {
	var ram string
	var cpu string
	var preset string
	var setups []string
	var root bool
	cmd := &cobra.Command{
		Use:   "shell",
		Short: "Open a shell in a VM sandbox",
		Long:  "Boot the project image and open a shell.",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cmdVMShell(ram, cpu, preset, setups, root)
		},
	}
	cmd.Flags().StringVar(&ram, "ram", "", "RAM in MB (default: 512, or ZAIGR_VM_RAM env)")
	cmd.Flags().StringVar(&cpu, "cpu", "", "CPU cores (default: 1, or ZAIGR_VM_CPU env)")
	cmd.Flags().StringVar(&preset, "preset", "", "Run a named preset")
	cmd.Flags().StringSliceVar(&setups, "setup", nil, "Run one or more named setups")
	cmd.Flags().BoolVar(&root, "root", false, "Connect as root")
	_ = cmd.RegisterFlagCompletionFunc("preset", completePresetName)
	_ = cmd.RegisterFlagCompletionFunc("setup", completeSetupName)
	return cmd
}

func newProjectCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "project",
		Short: "Inspect and manage project state",
		Long:  "Inspect project configuration, status, and setup state.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	cmd.AddCommand(newProjectSetupCommand())
	cmd.AddCommand(newProjectVMCommand())
	cmd.AddCommand(newProjectFirewallCommand())
	cmd.AddCommand(newProjectStatusCommand())
	cmd.AddCommand(newProjectRebuildCommand())
	cmd.AddCommand(newProjectCleanCommand())
	cmd.AddCommand(newProjectDeleteCommand())
	return cmd
}

func newProjectSetupCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Run and inspect project setup state",
		Long:  "Run named setups and inspect setup state for this project.",
	}
	cmd.AddCommand(newProjectSetupRunCommand())
	cmd.AddCommand(newProjectSetupCaptureCommand())
	cmd.AddCommand(newProjectSetupListCommand())
	cmd.AddCommand(newProjectSetupShowCommand())
	return cmd
}

func newProjectSetupRunCommand() *cobra.Command {
	var ram string
	var cpu string
	var force bool
	cmd := &cobra.Command{
		Use:   "run <setup> [<setup> ...]",
		Short: "Run one or more named setups",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return cmdSetupRun(args, ram, cpu, force)
		},
	}
	cmd.Flags().StringVar(&ram, "ram", "", "RAM in MB")
	cmd.Flags().StringVar(&cpu, "cpu", "", "CPU cores")
	cmd.Flags().BoolVar(&force, "force", false, "Run setups even when already recorded")
	cmd.ValidArgsFunction = completeSetupName
	return cmd
}

func newProjectSetupListCommand() *cobra.Command {
	var committed bool
	var awaitingCommit bool
	var failed bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List setups by state",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cmdProjectSetupList(committed, awaitingCommit, failed)
		},
	}
	cmd.Flags().BoolVar(&committed, "committed", false, "List committed setups")
	cmd.Flags().BoolVar(&awaitingCommit, "awaiting-commit", false, "List setups awaiting image commit")
	cmd.Flags().BoolVar(&failed, "failed", false, "List failed setups")
	return cmd
}

func newProjectSetupShowCommand() *cobra.Command {
	var committed bool
	var awaitingCommit bool
	var failed bool
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show setup scripts by state",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cmdProjectSetupShow(committed, awaitingCommit, failed)
		},
	}
	cmd.Flags().BoolVar(&committed, "committed", false, "Show committed setups")
	cmd.Flags().BoolVar(&awaitingCommit, "awaiting-commit", false, "Show setups awaiting image commit")
	cmd.Flags().BoolVar(&failed, "failed", false, "Show failed setups")
	return cmd
}

func newProjectFirewallCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "firewall",
		Short: "Inspect project firewall state",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	cmd.AddCommand(newProjectFirewallShowCommand())
	cmd.AddCommand(newProjectFirewallDomainLogCommand())
	return cmd
}

func newProjectFirewallDomainLogCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "domain-log",
		Short: "Stream observed firewall domain events from the running project VM",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cmdProjectFirewallDomainLog()
		},
	}
	return cmd
}

func newProjectSetupCaptureCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "capture",
		Short: "Capture setup changes into a reusable setup definition",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			return c.Help()
		},
	}
	cmd.AddCommand(newProjectSetupCaptureStartCommand())
	cmd.AddCommand(newProjectSetupCaptureReviewCommand())
	cmd.AddCommand(newProjectSetupCaptureAcceptCommand())
	cmd.AddCommand(newProjectSetupCaptureDiscardCommand())
	return cmd
}

func newProjectSetupCaptureStartCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start an interactive setup capture session",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cmdProjectSetupCaptureStart()
		},
	}
	return cmd
}

func newProjectSetupCaptureReviewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "review",
		Short: "Review the active capture's observed endpoints and setup candidates",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cmdProjectSetupCaptureReview()
		},
	}
	return cmd
}

func newProjectSetupCaptureAcceptCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "accept",
		Short: "Accept capture output and promote it as a reusable setup",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cmdProjectSetupCaptureAccept()
		},
	}
	return cmd
}

func newProjectSetupCaptureDiscardCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "discard",
		Short: "Discard the active capture and delete its overlay",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cmdProjectSetupCaptureDiscard()
		},
	}
	return cmd
}

func newProjectFirewallShowCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show current firewall rules for the project",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cmdProjectFirewallShow()
		},
	}
	return cmd
}

func newProjectVMCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vm",
		Short: "Manage the project VM",
		Long:  "Manage project VM lifecycle and configuration.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	cmd.AddCommand(newProjectVMStartCommand())
	cmd.AddCommand(newProjectVMExecCommand())
	cmd.AddCommand(newProjectVMStopCommand())
	cmd.AddCommand(newProjectVMShowConfigCommand())
	cmd.AddCommand(newProjectVMSetConfigCommand())
	return cmd
}

func newProjectVMStartCommand() *cobra.Command {
	var ram string
	var cpu string
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the project VM in the background",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cmdProjectStartVM(ram, cpu)
		},
	}
	cmd.Flags().StringVar(&ram, "ram", "", "Start with RAM in MB")
	cmd.Flags().StringVar(&cpu, "cpu", "", "Start with CPU cores")
	return cmd
}

func newProjectVMExecCommand() *cobra.Command {
	var root bool
	cmd := &cobra.Command{
		Use:   "exec [--root] -- <command> [args...]",
		Short: "Run a command in the running project VM",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return cmdProjectVMExec(args, root)
		},
	}
	cmd.Flags().BoolVar(&root, "root", false, "Run command as root and mark the project image dirty")
	return cmd
}

func newProjectVMShowConfigCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show-config",
		Short: "Show project VM configuration",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cmdProjectShowVMConfig()
		},
	}
	return cmd
}

func newProjectVMSetConfigCommand() *cobra.Command {
	var ram string
	var cpu string
	cmd := &cobra.Command{
		Use:   "set-config",
		Short: "Set default project VM configuration",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cmdProjectSetVMConfig(ram, cpu)
		},
	}
	cmd.Flags().StringVar(&ram, "ram", "", "Set default RAM in MB")
	cmd.Flags().StringVar(&cpu, "cpu", "", "Set default CPU count")
	return cmd
}

func newProjectStatusCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show project status",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cmdProjectStatus()
		},
	}
	return cmd
}

func newProjectRebuildCommand() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "rebuild",
		Short: "Rebuild the project image from committed setup state",
		Long:  "Rebuild the project image from the current base image and committed setup state without deleting the project store.",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cmdProjectRebuild(force)
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "Rebuild even when dirty project-image changes would be lost")
	return cmd
}

func newProjectCleanCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "clean",
		Short: "Reset project image to base",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cmdProjectClean()
		},
	}
	return cmd
}

func newProjectDeleteCommand() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete the current project store",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cmdProjectDelete(force)
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "Delete without prompting")
	return cmd
}

func newProjectVMStopCommand() *cobra.Command {
	var abrupt bool
	cmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop running project VM",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cmdProjectStopVM(abrupt)
		},
	}
	cmd.Flags().BoolVar(&abrupt, "abrupt", false, "Force kill the VM process")
	return cmd
}
