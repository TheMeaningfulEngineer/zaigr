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
	var fullNetwork bool
	cmd := &cobra.Command{
		Use:   "shell",
		Short: "Open a shell in a VM sandbox",
		Long:  "Boot the project image and open a shell.",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cmdVMShell(ram, cpu, preset, setups, root, fullNetwork)
		},
	}
	cmd.Flags().StringVar(&ram, "ram", "", "RAM in MB (default: 512, or ZAIGR_VM_RAM env)")
	cmd.Flags().StringVar(&cpu, "cpu", "", "CPU cores (default: 1, or ZAIGR_VM_CPU env)")
	cmd.Flags().StringVar(&preset, "preset", "", "Run a named preset")
	cmd.Flags().StringSliceVar(&setups, "setup", nil, "Run one or more named setups")
	cmd.Flags().BoolVar(&root, "root", false, "Connect as root")
	cmd.Flags().BoolVar(&fullNetwork, "full-network", false, "Temporarily give this --root maintenance shell and its child processes broad IPv4 TCP/UDP access")
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
	cmd.AddCommand(newProjectHostAccessCommand())
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
		Long: "Manage firewall permissions owned by this project. Allow domain names, or exact IPv4 " +
			"addresses on all ports. Permissions persist until removed.",
		Example: "  zaigr project firewall allow huggingface.co hf.co\n" +
			"  zaigr project firewall allow 192.168.2.11\n" +
			"  zaigr project firewall show\n" +
			"  zaigr project firewall remove hf.co 192.168.2.11",
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
		Use:   "allow <domain|ipv4> [<domain|ipv4> ...]",
		Short: "Allow domain names or exact IPv4 addresses for this project",
		Long: "Allow each domain name or exact IPv4 address for this project until removed. " +
			"A domain allows that exact name, not its subdomains. An IPv4 address is allowed on all ports " +
			"and may be offline. Permissions persist across VM restarts, clean, and rebuild.",
		Example: "  zaigr project firewall allow huggingface.co hf.co\n" +
			"  zaigr project firewall allow 192.168.2.11\n" +
			"  # From an ordinary zaigr shell: ssh user@192.168.2.11\n" +
			"  zaigr project firewall show",
		Args: cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return cmdProjectFirewallChange(args, true)
		},
	}
}

func newProjectFirewallRemoveCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <domain|ipv4> [<domain|ipv4> ...]",
		Short: "Remove domain names or exact IPv4 addresses from this project",
		Long: "Remove each domain name or exact IPv4 permission from this project. " +
			"Existing connections that only that permission allowed are cut when the VM is running.",
		Example: "  zaigr project firewall remove hf.co\n" +
			"  zaigr project firewall remove 192.168.2.11\n" +
			"  zaigr project firewall show",
		Args: cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return cmdProjectFirewallChange(args, false)
		},
	}
}

func newProjectFirewallDomainLogCommand() *cobra.Command {
	var history bool
	cmd := &cobra.Command{
		Use:   "domain-log",
		Short: "Stream DNS and firewall packet outcomes observed by the running project VM",
		Long: "Print DNS resolver outcomes and observed host firewall packet verdicts. " +
			"Repeated DNS lines with the same name and verdict collapse for about two seconds; -v shows each query type and retry. " +
			"Firewall allowed/blocked records describe packet decisions, not remote connection or application success. " +
			"Only events after the command starts are shown; --history first replays what the running VM already recorded.",
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			verbose, err := c.Root().PersistentFlags().GetCount("verbose")
			if err != nil {
				return err
			}
			return cmdProjectFirewallDomainLog(verbose > 0, history)
		},
	}
	cmd.Flags().BoolVar(&history, "history", false, "Replay events recorded since the VM started before following new ones")
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
	var sandbox string
	var ram string
	var cpu string
	cmd := &cobra.Command{
		Use:   "set-config",
		Short: "Set default project VM configuration",
		Long: `Set default project VM configuration.

The project must already be initialized and its VM stopped.
For a new project, run 'zaigr project vm start' to initialize it, then
'zaigr project vm stop' before using this command.`,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cmdProjectSetVMConfig(ram, cpu, sandbox)
		},
	}
	cmd.Flags().StringVar(&ram, "ram", "", "Set default RAM in MB")
	cmd.Flags().StringVar(&cpu, "cpu", "", "Set default CPU count")
	cmd.Flags().StringVar(&sandbox, "virtiofs-sandbox", "", "Filesystem isolation: namespace (required for host-enforced networking)")
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
