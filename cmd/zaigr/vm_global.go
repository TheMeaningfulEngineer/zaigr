package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

func newGlobalCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "global",
		Short: "Manage project VMs and global resources",
		Long:  "Inspect, stop, and rebuild project VMs, and manage global setups, presets, firewall rules, and base images from any directory.",
	}
	cmd.AddCommand(newGlobalSetupCommand())
	cmd.AddCommand(newGlobalPresetCommand())
	cmd.AddCommand(newGlobalProjectsCommand())
	cmd.AddCommand(newGlobalFirewallCommand())
	cmd.AddCommand(newGlobalBaseImageCommand())
	return cmd
}

func newGlobalBaseImageCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "base-image", Short: "Customize the global base image for new projects", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() }}
	cmd.AddCommand(&cobra.Command{Use: "status", Short: "Show the current global base image", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error { return cmdGlobalBaseImageStatus() }})
	cmd.AddCommand(&cobra.Command{Use: "reset", Short: "Select the bundled factory base image", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error { return cmdGlobalBaseImageReset() }})
	setup := &cobra.Command{Use: "setup", Short: "Apply setups to the global base image", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() }}
	var ram, cpu string
	var force bool
	run := &cobra.Command{Use: "run <setup> [<setup> ...]", Short: "Apply global setups to the global base image", Args: cobra.ArbitraryArgs, RunE: func(_ *cobra.Command, args []string) error { return cmdGlobalBaseImageSetupRun(args, ram, cpu, force) }}
	run.Flags().StringVar(&ram, "ram", "", "RAM in MB (default: 4096, or ZAIGR_VM_RAM env)")
	run.Flags().StringVar(&cpu, "cpu", "", "CPU cores (default: 1, or ZAIGR_VM_CPU env)")
	run.Flags().BoolVar(&force, "force", false, "Run selected setups even when already applied")
	run.ValidArgsFunction = completeSetupName
	setup.AddCommand(run)
	cmd.AddCommand(setup)
	return cmd
}

func newGlobalSetupCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Inspect globally available setup definitions",
	}
	cmd.AddCommand(newGlobalSetupListCommand())
	cmd.AddCommand(newGlobalSetupShowCommand())
	cmd.AddCommand(newGlobalSetupPathCommand())
	return cmd
}

func newGlobalSetupListCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List available setup definitions",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cmdGlobalSetupList()
		},
	}
	return cmd
}

func newGlobalSetupShowCommand() *cobra.Command {
	var showScript bool
	var showFirewall bool
	var full bool
	cmd := &cobra.Command{
		Use:   "show <setup>",
		Short: "Show setup metadata and optional file contents",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if full {
				showScript = true
				showFirewall = true
			}
			return cmdGlobalSetupShow(args[0], showScript, showFirewall)
		},
	}
	cmd.Flags().BoolVar(&showScript, "script", false, "Show contents of direct *.script files")
	cmd.Flags().BoolVar(&showFirewall, "firewall", false, "Show contents of direct *.firewall files")
	cmd.Flags().BoolVar(&full, "full", false, "Show script and firewall file contents")
	cmd.ValidArgsFunction = completeSetupName
	return cmd
}

func newGlobalSetupPathCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "path <setup>",
		Short: "Show materialized setup path",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return cmdGlobalSetupPath(args[0])
		},
	}
	cmd.ValidArgsFunction = completeSetupName
	return cmd
}

func newGlobalPresetCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "preset",
		Short: "Inspect globally available presets",
	}
	cmd.AddCommand(newGlobalPresetListCommand())
	cmd.AddCommand(newGlobalPresetShowCommand())
	cmd.AddCommand(newGlobalPresetPathCommand())
	return cmd
}

func newGlobalPresetListCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List available presets",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cmdGlobalPresetList()
		},
	}
	return cmd
}

func newGlobalPresetShowCommand() *cobra.Command {
	var showScript bool
	var showFirewall bool
	var full bool
	cmd := &cobra.Command{
		Use:   "show <preset>",
		Short: "Show preset metadata and optional setup details",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if full {
				showScript = true
				showFirewall = true
			}
			return cmdGlobalPresetShow(args[0], showScript, showFirewall)
		},
	}
	cmd.Flags().BoolVar(&showScript, "script", false, "Show preset run script and setup script contents")
	cmd.Flags().BoolVar(&showFirewall, "firewall", false, "Show dependent setup firewall contents")
	cmd.Flags().BoolVar(&full, "full", false, "Show script and firewall contents")
	cmd.ValidArgsFunction = completePresetName
	return cmd
}

func newGlobalPresetPathCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "path <preset>",
		Short: "Show materialized preset path",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return cmdGlobalPresetPath(args[0])
		},
	}
	cmd.ValidArgsFunction = completePresetName
	return cmd
}

func cmdGlobalSetupList() error {
	names, err := listAvailableSetups()
	if err != nil {
		return err
	}
	for _, name := range names {
		fmt.Println(name)
	}
	return nil
}

func cmdGlobalSetupShow(name string, showScript bool, showFirewall bool) error {
	definitions, err := loadSetupDefinitions([]string{name})
	if err != nil {
		return err
	}
	if len(definitions) != 1 {
		return fmt.Errorf("setup %q not found", name)
	}
	definition := definitions[0]

	printSetupSummary(definition, "")
	switch {
	case showScript && showFirewall:
		if err := printSetupContents(definition, "", true, true); err != nil {
			return err
		}
	case showScript:
		if err := printSetupContents(definition, "", true, false); err != nil {
			return err
		}
	case showFirewall:
		if err := printSetupContents(definition, "", false, true); err != nil {
			return err
		}
	}
	return nil
}

func cmdGlobalSetupPath(name string) error {
	definitions, err := loadSetupDefinitions([]string{name})
	if err != nil {
		return err
	}
	if len(definitions) != 1 {
		return fmt.Errorf("setup %q not found", name)
	}
	fmt.Printf("%s\n", definitions[0].RootPath)
	return nil
}

func cmdGlobalPresetList() error {
	names, err := listAvailablePresets()
	if err != nil {
		return err
	}
	for _, name := range names {
		fmt.Println(name)
	}
	return nil
}

func cmdGlobalPresetShow(name string, showScript bool, showFirewall bool) error {
	preset, err := loadPresetForGlobal(name)
	if err != nil {
		return err
	}
	fmt.Printf("name: %s\n", preset.Name)
	fmt.Printf("path: %s\n", filepath.Dir(preset.RunPath))
	fmt.Printf("run script: %s\n", preset.RunPath)

	printNameList("setup dependencies:", preset.SetupRefs, "")

	if showScript {
		if err := printPresetRunScript(preset.RunPath); err != nil {
			return err
		}
	}
	if (!showScript && !showFirewall) || len(preset.SetupRefs) == 0 {
		return nil
	}
	setupDefinitions, err := loadSetupDefinitions(preset.SetupRefs)
	if err != nil {
		return err
	}
	if len(setupDefinitions) != len(preset.SetupRefs) {
		return fmt.Errorf("failed to resolve all setup dependencies for preset %q", preset.Name)
	}

	for i, definition := range setupDefinitions {
		fmt.Printf("setup dependency %d:\n", i+1)
		printSetupSummary(definition, "  ")
		if err := printSetupContents(definition, "  ", showScript, showFirewall); err != nil {
			return err
		}
	}
	return nil
}

func cmdGlobalPresetPath(name string) error {
	preset, err := loadPresetForGlobal(name)
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", filepath.Dir(preset.RunPath))
	return nil
}

func loadPresetForGlobal(name string) (presetDefinition, error) {
	if err := ensureBuiltinPresetStructure(name); err != nil {
		return presetDefinition{}, err
	}
	return loadPreset(name)
}

func printSetupSummary(definition setupDefinition, indent string) {
	fmt.Printf("%sname: %s\n", indent, displaySetupName(definition.Name, definition.ProjectLocal))
	fmt.Printf("%spath: %s\n", indent, definition.RootPath)
	printNameList("script files:", definition.ScriptPaths, indent)
	printNameList("firewall files:", definition.FirewallPaths, indent)
}

func printNameList(label string, paths []string, indent string) {
	fmt.Printf("%s%s\n", indent, label)
	if len(paths) == 0 {
		fmt.Printf("%s  (none)\n", indent)
		return
	}
	for _, path := range paths {
		fmt.Printf("%s  %s\n", indent, filepath.Base(path))
	}
}

func printSetupContents(definition setupDefinition, indent string, withScript bool, withFirewall bool) error {
	if withScript {
		if err := printFileContentsWithHeaders(definition.ScriptPaths, "script", indent); err != nil {
			return err
		}
	}
	if withFirewall {
		if err := printFileContentsWithHeaders(definition.FirewallPaths, "firewall", indent); err != nil {
			return err
		}
	}
	return nil
}

func printPresetRunScript(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read preset run script %s: %w", filepath.Base(path), err)
	}

	fmt.Printf("\n== preset run script: %s ==\n", filepath.Base(path))
	fmt.Print(string(content))
	if !strings.HasSuffix(string(content), "\n") {
		fmt.Println()
	}
	return nil
}

func printFileContentsWithHeaders(paths []string, kind string, indent string) error {
	paths = append([]string{}, paths...)
	sort.Strings(paths)
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s %s: %w", kind, filepath.Base(path), err)
		}

		fmt.Printf("\n%s== %s file: %s ==\n", indent, kind, filepath.Base(path))
		fmt.Printf("%s%s", indent, content)
		if !strings.HasSuffix(string(content), "\n") {
			fmt.Println()
		}
	}
	return nil
}
