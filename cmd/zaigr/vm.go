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
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	cmd.AddCommand(newProjectSetupRunCommand())
	cmd.AddCommand(newProjectSetupCaptureCommand())
	cmd.AddCommand(newProjectSetupListCommand())
	cmd.AddCommand(newProjectSetupLocalSkeletonCommand())
	return cmd
}

func newProjectSetupLocalSkeletonCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "local-skeleton",
		Short: "Create a project-local setup skeleton",
		Long: "Create .zaigr/setups/local/setup.script and setup.firewall " +
			"in the current project without initializing its VM.",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cmdProjectSetupLocalSkeleton()
		},
	}
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
	var applied bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List applied setups",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cmdProjectSetupList(applied)
		},
	}
	cmd.Flags().BoolVar(&applied, "applied", false, "List applied setups")
	return cmd
}

func newProjectFirewallCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "firewall",
		Short: "Manage persistent project firewall permissions",
		Long: "Manage firewall permissions owned by this project. Exact IPv4 permissions " +
			"apply to all ports, persist until removed, and do not require the target to be reachable.",
		Example: "  zaigr project firewall allow 192.168.2.11\n" +
			"  zaigr project firewall show\n" +
			"  # From an ordinary zaigr shell: ssh user@192.168.2.11\n" +
			"  zaigr project firewall remove 192.168.2.11",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	cmd.AddCommand(newProjectFirewallAllowCommand())
	cmd.AddCommand(newProjectFirewallRemoveCommand())
	cmd.AddCommand(newProjectFirewallShowCommand())
	cmd.AddCommand(newProjectFirewallDomainLogCommand())
	return cmd
}

func newProjectFirewallAllowCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "allow <ipv4>",
		Short: "Allow an exact IPv4 address on all ports for this project",
		Long: "Allow an exact IPv4 address on all ports for this project until removed. " +
			"The permission persists across VM restarts, clean, and rebuild. The target may be offline; " +
			"connect normally afterward, for example: ssh user@192.168.2.11.",
		Example: "  zaigr project firewall allow 192.168.2.11\n" +
			"  zaigr project firewall show\n" +
			"  # From an ordinary zaigr shell: ssh user@192.168.2.11\n" +
			"  zaigr project firewall remove 192.168.2.11",
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return cmdProjectFirewallIPChange(args[0], true)
		},
	}
}

func newProjectFirewallRemoveCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <ipv4>",
		Short: "Remove a project's exact IPv4 all-port permission",
		Long: "Remove a persistent exact IPv4 permission from this project. " +
			"Existing outbound TCP and UDP connections to that address are revoked when the VM is running.",
		Example: "  zaigr project firewall allow 192.168.2.11\n" +
			"  zaigr project firewall show\n" +
			"  zaigr project firewall remove 192.168.2.11",
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return cmdProjectFirewallIPChange(args[0], false)
		},
	}
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
		Long: `Set default project VM configuration.

The project must already be initialized and its VM stopped.
For a new project, run 'zaigr project vm start' to initialize it, then
'zaigr project vm stop' before using this command.`,
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
		Short: "Rebuild the project image from applied setup state",
		Long:  "Rebuild the project image from the current base image and current definitions of applied setups.",
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
