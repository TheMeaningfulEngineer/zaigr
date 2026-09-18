package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

const (
	autocompleteBlockBegin = "# BEGIN ZAIGR AUTOCOMPLETE"
	autocompleteBlockEnd   = "# END ZAIGR AUTOCOMPLETE"
)

func newAutocompleteCommand(rootCmd *cobra.Command) *cobra.Command {
	return &cobra.Command{
		Use:   "autocomplete",
		Short: "Install Bash completion",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cmdAutocomplete(rootCmd)
		},
	}
}

func cmdAutocomplete(rootCmd *cobra.Command) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("determine home directory: %w", err)
	}

	bashrcPath := filepath.Join(homeDir, ".bashrc")
	_, _ = fmt.Fprintf(os.Stderr, "Do you want to add autocomplete for zaigr %s to %s? ", version, bashrcPath)

	response, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && err.Error() != "EOF" {
		return fmt.Errorf("read confirmation: %w", err)
	}

	answer := strings.TrimSpace(strings.ToLower(response))
	if answer != "y" && answer != "yes" {
		return nil
	}

	return cmdAutocompleteInstall(rootCmd)
}

func cmdAutocompleteInstall(rootCmd *cobra.Command) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("determine home directory: %w", err)
	}

	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("determine executable path: %w", err)
	}
	executable = filepath.Clean(executable)

	autocompleteDir := filepath.Join(homeDir, ".zaigr", "autocomplete")
	if err := os.MkdirAll(autocompleteDir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", autocompleteDir, err)
	}

	scriptPath := filepath.Join(autocompleteDir, "zaigr.bash")
	script, err := renderAutocompleteScript(rootCmd, executable, completionCommandNames())
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "generating %s\n", scriptPath)
	if err := os.WriteFile(scriptPath, []byte(script), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", scriptPath, err)
	}

	bashrcPath := filepath.Join(homeDir, ".bashrc")
	block := renderAutocompleteInstallBlock(scriptPath)
	existing, err := os.ReadFile(bashrcPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", bashrcPath, err)
	}

	updated, changed, err := replaceAutocompleteBlock(string(existing), block)
	if err != nil {
		return fmt.Errorf("update %s: %w", bashrcPath, err)
	}
	if changed {
		fmt.Fprintf(os.Stderr, "adding zaigr autocomplete source block to %s\n", bashrcPath)
		if err := os.WriteFile(bashrcPath, []byte(updated), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", bashrcPath, err)
		}
	} else {
		fmt.Fprintf(os.Stderr, "zaigr autocomplete source block already up to date in %s\n", bashrcPath)
	}

	return nil
}

func completionCommandNames() []string {
	names := map[string]struct{}{
		"zaigr":   struct{}{},
		"./zaigr": struct{}{},
	}

	if executablePath, err := os.Executable(); err == nil {
		base := filepath.Base(executablePath)
		names[executablePath] = struct{}{}
		names["./"+base] = struct{}{}
		names[base] = struct{}{}
	}

	out := make([]string, 0, len(names))
	for name := range names {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func renderAutocompleteScript(rootCmd *cobra.Command, completionBinary string, completionNames []string) (string, error) {
	var script bytes.Buffer
	if err := rootCmd.GenBashCompletionV2(&script, true); err != nil {
		return "", fmt.Errorf("generate bash completion: %w", err)
	}
	return normalizeAutocompleteScript(script.String(), completionBinary, completionNames)
}

func renderAutocompleteInstallBlock(scriptPath string) string {
	var block strings.Builder
	block.WriteString(autocompleteBlockBegin)
	block.WriteByte('\n')
	block.WriteString("[ -r ")
	block.WriteString(shellQuote(scriptPath))
	block.WriteString(" ] && . ")
	block.WriteString(shellQuote(scriptPath))
	block.WriteByte('\n')
	block.WriteString(autocompleteBlockEnd)
	block.WriteByte('\n')
	return block.String()
}

func replaceAutocompleteBlock(existing, block string) (string, bool, error) {
	start := strings.Index(existing, autocompleteBlockBegin)
	end := strings.Index(existing, autocompleteBlockEnd)

	switch {
	case start == -1 && end == -1:
		if existing == "" {
			return block, true, nil
		}
		if !strings.HasSuffix(existing, "\n") {
			existing += "\n"
		}
		return existing + "\n" + block, true, nil
	case start == -1 || end == -1 || end < start:
		return "", false, fmt.Errorf("found incomplete zaigr autocomplete block")
	}

	end += len(autocompleteBlockEnd)
	if end < len(existing) && existing[end] == '\n' {
		end++
	}

	current := existing[start:end]
	if current == block {
		return existing, false, nil
	}

	return existing[:start] + block + existing[end:], true, nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func normalizeAutocompleteScript(script, completionBinary string, completionNames []string) (string, error) {
	const requestCompLine = `    requestComp="${words[0]} __complete ${args[*]}"`
	const requestCompReplacement = `    local completionBinary="${words[0]}"
    if [[ -n ${__zaigr_completion_binary-} && -x ${__zaigr_completion_binary} ]]; then
        completionBinary=${__zaigr_completion_binary}
    fi
    printf -v requestComp '%q __complete %s' "${completionBinary}" "${args[*]}"`

	if !strings.Contains(script, requestCompLine) {
		return "", fmt.Errorf("unexpected bash completion template: missing request command")
	}

	script = "__zaigr_completion_binary=" + shellQuote(completionBinary) + "\n\n" + script
	script = strings.Replace(script, requestCompLine, requestCompReplacement, 1)
	script = appendCompletionRegistration(script, completionNames)

	return script, nil
}

func appendCompletionRegistration(script string, names []string) string {
	if len(names) == 0 {
		return script
	}

	var registration strings.Builder
	registration.WriteString("\n")
	registration.WriteString("__zaigr_completion_names=(\n")
	for _, name := range names {
		if name == "zaigr" {
			continue
		}
		registration.WriteString("    ")
		registration.WriteString(shellQuote(name))
		registration.WriteString("\n")
	}
	registration.WriteString(")\n")
	registration.WriteString(`for __zaigr_completion_name in "${__zaigr_completion_names[@]}"; do
    if [[ $(type -t compopt) = "builtin" ]]; then
        complete -o default -F __start_zaigr "$__zaigr_completion_name" 2>/dev/null || true
    else
        complete -o default -o nospace -F __start_zaigr "$__zaigr_completion_name" 2>/dev/null || true
    fi
done
unset __zaigr_completion_name
unset __zaigr_completion_names
`)
	return script + registration.String()
}
