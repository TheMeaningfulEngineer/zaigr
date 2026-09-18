package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newTestHelpersCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "test-helpers",
		Short: "Testing and diagnostic helpers",
	}
	cmd.AddCommand(newProjectStoreDirProbeCommand())
	return cmd
}

func newMiscCommand(rootCmd *cobra.Command) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "misc",
		Short: "Miscellaneous commands",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	cmd.AddCommand(newFullVersionCommand())
	cmd.AddCommand(newTestHelpersCommand())
	cmd.AddCommand(newCheckCommand())
	cmd.AddCommand(newAutocompleteCommand(rootCmd))
	return cmd
}

func newFullVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "full-version",
		Short: "Print full version metadata",
		Args:  cobra.NoArgs,
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Printf("version: %s\n", version)
			fmt.Printf("build: %s\n", build)
			fmt.Printf("commit: %s\n", commit)
			fmt.Printf("built: %s\n", buildTime)
			fmt.Printf("miniconfig: %s\n", embeddedVersion(embeddedKernel, "zaigr-"))
			fmt.Printf("building-blocks: %s\n", buildingBlocksVersion())
			fmt.Printf("base-image: %s\n", baseRootfsVersion())
		},
	}
}

func newProjectStoreDirProbeCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "project-store-dir",
		Short: "Print the current project's store directory",
		Args:  cobra.NoArgs,
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Println(storeDir())
		},
	}
}
