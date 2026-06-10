package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// version, build, commit, and buildTime are set at build time via -ldflags.
var version = "dev"
var build = "undefined"
var commit = "undefined"
var buildTime = "unknown"

func main() {
	os.Exit(realMain())
}

func realMain() int {
	rootCmd := newRootCommand()
	err := rootCmd.Execute()
	if err == nil {
		return 0
	}
	return handleRuntimeError(err)
}

func newRootCommand() *cobra.Command {
	var logLevel string
	var verboseCount int
	rootCmd := &cobra.Command{
		Use:           "zaigr",
		Short:         "Sandbox launcher for AI coding agents.",
		Long:          "Sandbox launcher for AI coding agents.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	rootCmd.SetHelpCommand(&cobra.Command{Hidden: true})
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.SetOut(os.Stdout)
	rootCmd.SetErr(os.Stderr)
	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		return configureLogging(logLevel, verboseCount, cmd.Flags().Changed("log-level"))
	}
	rootCmd.Version = version
	rootCmd.SetVersionTemplate("{{.Version}}\n")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "warn", "Set log level (error, warn, info, debug)")
	rootCmd.PersistentFlags().CountVarP(&verboseCount, "verbose", "v", "Increase log verbosity (-v=info, -vv=debug)")

	rootCmd.AddCommand(newShellCommand())
	rootCmd.AddCommand(newProjectCommand())
	rootCmd.AddCommand(newGlobalCommand())
	rootCmd.AddCommand(newMiscCommand(rootCmd))

	return rootCmd
}

type cliError struct {
	code int
}

func (e *cliError) Error() string {
	return fmt.Sprintf("exit status %d", e.code)
}

func handleRuntimeError(err error) int {
	var cliErr *cliError
	if errors.As(err, &cliErr) {
		return cliErr.code
	}
	_, _ = fmt.Fprintln(os.Stderr, err.Error())
	return 1
}

func exitError(code int) error {
	return &cliError{code: code}
}
