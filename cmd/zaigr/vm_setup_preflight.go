package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

type setupAptConfirmationIssue struct {
	SetupName string
	Path      string
	Line      int
	Command   string
}

type setupScriptLogicalLine struct {
	Line int
	Text string
}

type setupHeredoc struct {
	Delimiter string
	StripTabs bool
}

var aptCommandsRequiringConfirmation = map[string]bool{
	"autoremove":      true,
	"build-dep":       true,
	"dist-upgrade":    true,
	"dselect-upgrade": true,
	"full-upgrade":    true,
	"install":         true,
	"purge":           true,
	"reinstall":       true,
	"remove":          true,
	"satisfy":         true,
	"upgrade":         true,
}

func confirmSetupAptCommands(definitions []setupDefinition, operation string) error {
	issues := setupAptConfirmationIssues(definitions)
	if len(issues) == 0 {
		return nil
	}

	fmt.Fprintln(os.Stderr, ":: Setup scripts contain APT commands without automatic confirmation:")
	for _, issue := range issues {
		fmt.Fprintf(os.Stderr, "  %s\n", issue.SetupName)
		fmt.Fprintf(os.Stderr, "    %s:%d: %s\n", issue.Path, issue.Line, issue.Command)
	}
	fmt.Fprintln(os.Stderr, "   Setup scripts run non-interactively, so these commands will usually abort when APT asks to continue.")
	fmt.Fprintln(os.Stderr, "   Add `-y` or `--assume-yes` to each command (prefer `apt-get` in scripts).")
	fmt.Fprint(os.Stderr, "Continue with setup execution anyway? [y/N] ")
	var answer string
	if _, err := fmt.Scanln(&answer); err == nil {
		answer = strings.ToLower(strings.TrimSpace(answer))
		if answer == "y" || answer == "yes" {
			return nil
		}
	}
	if operation == "project rebuild" {
		return fmt.Errorf("project rebuild aborted before setup execution; original project left unchanged")
	}
	return fmt.Errorf("%s aborted before running setup scripts", operation)
}

func setupAptConfirmationIssues(definitions []setupDefinition) []setupAptConfirmationIssue {
	issues := make([]setupAptConfirmationIssue, 0)
	for _, definition := range definitions {
		for _, path := range definition.ScriptPaths {
			content, ok := definition.SourceContent[path]
			if !ok {
				continue
			}
			for _, line := range setupScriptLogicalLines(content) {
				for _, command := range setupShellCommandSegments(line.Text) {
					command = strings.TrimSpace(command)
					if command == "" || !aptCommandNeedsAutomaticConfirmation(command) {
						continue
					}
					issues = append(issues, setupAptConfirmationIssue{
						SetupName: displaySetupName(definition.Name, definition.ProjectLocal),
						Path:      filepath.ToSlash(path),
						Line:      line.Line,
						Command:   strings.Join(strings.Fields(command), " "),
					})
				}
			}
		}
	}
	return issues
}

func setupScriptLogicalLines(content []byte) []setupScriptLogicalLine {
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	lines := make([]setupScriptLogicalLine, 0)
	var pending strings.Builder
	startLine := 0
	lineNumber := 0
	heredocs := make([]setupHeredoc, 0)
	for scanner.Scan() {
		lineNumber++
		text := scanner.Text()
		if len(heredocs) > 0 {
			closing := text
			if heredocs[0].StripTabs {
				closing = strings.TrimLeft(closing, "\t")
			}
			if closing == heredocs[0].Delimiter {
				heredocs = heredocs[1:]
			}
			continue
		}
		text = strings.TrimRightFunc(text, unicode.IsSpace)
		if startLine == 0 {
			startLine = lineNumber
		}
		continued := hasUnescapedTrailingBackslash(text)
		if continued {
			text = strings.TrimSpace(text[:len(text)-1])
		}
		if pending.Len() > 0 && text != "" {
			pending.WriteByte(' ')
		}
		pending.WriteString(text)
		if continued {
			continue
		}
		logicalText := pending.String()
		lines = append(lines, setupScriptLogicalLine{Line: startLine, Text: logicalText})
		heredocs = append(heredocs, setupHeredocs(logicalText)...)
		pending.Reset()
		startLine = 0
	}
	if pending.Len() > 0 {
		lines = append(lines, setupScriptLogicalLine{Line: startLine, Text: pending.String()})
	}
	return lines
}

func setupHeredocs(line string) []setupHeredoc {
	heredocs := make([]setupHeredoc, 0)
	singleQuoted := false
	doubleQuoted := false
	escaped := false
	for index := 0; index < len(line); index++ {
		char := line[index]
		if escaped {
			escaped = false
			continue
		}
		if char == '\\' && !singleQuoted {
			escaped = true
			continue
		}
		if char == '\'' && !doubleQuoted {
			singleQuoted = !singleQuoted
			continue
		}
		if char == '"' && !singleQuoted {
			doubleQuoted = !doubleQuoted
			continue
		}
		if singleQuoted || doubleQuoted {
			continue
		}
		if char == '#' && (index == 0 || setupShellTokenBoundary(line[index-1])) {
			break
		}
		if strings.HasPrefix(line[index:], "$((") ||
			(strings.HasPrefix(line[index:], "((") && (index == 0 || setupShellTokenBoundary(line[index-1]))) {
			if end := strings.Index(line[index+2:], "))"); end >= 0 {
				index += end + 3
				continue
			}
		}
		if strings.HasPrefix(line[index:], "<<<") {
			index += 2
			continue
		}
		if !strings.HasPrefix(line[index:], "<<") {
			continue
		}

		cursor := index + 2
		stripTabs := cursor < len(line) && line[cursor] == '-'
		if stripTabs {
			cursor++
		}
		for cursor < len(line) && unicode.IsSpace(rune(line[cursor])) {
			cursor++
		}
		delimiter, end := setupHeredocDelimiter(line, cursor)
		if delimiter != "" {
			heredocs = append(heredocs, setupHeredoc{Delimiter: delimiter, StripTabs: stripTabs})
		}
		index = end - 1
	}
	return heredocs
}

func setupHeredocDelimiter(line string, start int) (string, int) {
	var delimiter strings.Builder
	singleQuoted := false
	doubleQuoted := false
	escaped := false
	index := start
	for ; index < len(line); index++ {
		char := line[index]
		if escaped {
			delimiter.WriteByte(char)
			escaped = false
			continue
		}
		if char == '\\' && !singleQuoted {
			escaped = true
			continue
		}
		if char == '\'' && !doubleQuoted {
			singleQuoted = !singleQuoted
			continue
		}
		if char == '"' && !singleQuoted {
			doubleQuoted = !doubleQuoted
			continue
		}
		if !singleQuoted && !doubleQuoted && setupShellTokenBoundary(char) {
			break
		}
		delimiter.WriteByte(char)
	}
	return delimiter.String(), index
}

func setupShellTokenBoundary(char byte) bool {
	return unicode.IsSpace(rune(char)) || strings.ContainsRune(";|&<>()", rune(char))
}

func hasUnescapedTrailingBackslash(line string) bool {
	count := 0
	for i := len(line) - 1; i >= 0 && line[i] == '\\'; i-- {
		count++
	}
	return count%2 == 1
}

func setupShellCommandSegments(line string) []string {
	segments := make([]string, 0, 1)
	start := 0
	singleQuoted := false
	doubleQuoted := false
	escaped := false
	appendSegment := func(end int) {
		if segment := strings.TrimSpace(line[start:end]); segment != "" {
			segments = append(segments, segment)
		}
	}
	for i := 0; i < len(line); i++ {
		char := line[i]
		if escaped {
			escaped = false
			continue
		}
		if char == '\\' && !singleQuoted {
			escaped = true
			continue
		}
		if char == '\'' && !doubleQuoted {
			singleQuoted = !singleQuoted
			continue
		}
		if char == '"' && !singleQuoted {
			doubleQuoted = !doubleQuoted
			continue
		}
		if singleQuoted || doubleQuoted {
			continue
		}
		if char == '#' && (i == start || unicode.IsSpace(rune(line[i-1]))) {
			appendSegment(i)
			return segments
		}
		separatorWidth := 0
		switch char {
		case ';':
			separatorWidth = 1
		case '&':
			if i+1 < len(line) && line[i+1] == '&' {
				separatorWidth = 2
			}
		case '|':
			if i+1 < len(line) && line[i+1] == '|' {
				separatorWidth = 2
			}
		}
		if separatorWidth == 0 {
			continue
		}
		appendSegment(i)
		i += separatorWidth - 1
		start = i + 1
	}
	appendSegment(len(line))
	return segments
}

func aptCommandNeedsAutomaticConfirmation(command string) bool {
	fields := strings.Fields(command)
	commandIndex := setupShellExecutableIndex(fields)
	if commandIndex < 0 || commandIndex >= len(fields) {
		return false
	}
	executable := strings.Trim(fields[commandIndex], "'\"(){}")
	executable = filepath.Base(executable)
	if executable != "apt" && executable != "apt-get" {
		return false
	}

	action := ""
	skipOptionValue := false
	for _, field := range fields[commandIndex+1:] {
		field = strings.Trim(field, "'\"(){}")
		lower := strings.ToLower(field)
		if skipOptionValue {
			skipOptionValue = false
			continue
		}
		switch lower {
		case "-c", "--config-file", "-o", "--option", "-t", "--target-release":
			skipOptionValue = true
			continue
		}
		if strings.HasPrefix(field, "-") {
			continue
		}
		action = lower
		break
	}
	if !aptCommandsRequiringConfirmation[action] {
		return false
	}
	return !aptCommandAssumesYes(fields[commandIndex+1:])
}

func setupShellExecutableIndex(fields []string) int {
	for index := 0; index < len(fields); index++ {
		field := strings.Trim(fields[index], "'\"(){}")
		lower := strings.ToLower(field)
		if field == "" || isShellAssignment(field) {
			continue
		}
		switch lower {
		case "!", "if", "then", "while", "until", "do", "command", "builtin", "exec", "nohup":
			continue
		case "env":
			continue
		case "sudo":
			continue
		}
		if strings.HasPrefix(field, "-") {
			continue
		}
		return index
	}
	return -1
}

func isShellAssignment(field string) bool {
	name, _, ok := strings.Cut(field, "=")
	if !ok || name == "" {
		return false
	}
	for index, char := range name {
		if char != '_' && !unicode.IsLetter(char) && (index == 0 || !unicode.IsDigit(char)) {
			return false
		}
	}
	return true
}

func aptCommandAssumesYes(fields []string) bool {
	for _, field := range fields {
		field = strings.Trim(field, "'\"(){}")
		lower := strings.ToLower(field)
		if lower == "-y" || lower == "--yes" || lower == "--assume-yes" {
			return true
		}
		if strings.HasPrefix(lower, "--assume-yes=") && strings.TrimPrefix(lower, "--assume-yes=") == "true" {
			return true
		}
		if strings.Contains(lower, "apt::get::assume-yes=") && strings.HasSuffix(lower, "=true") {
			return true
		}
		if len(lower) > 2 && lower[0] == '-' && lower[1] != '-' {
			shortOptions := lower[1:]
			onlyLetters := true
			for _, char := range shortOptions {
				if !unicode.IsLetter(char) {
					onlyLetters = false
					break
				}
			}
			if onlyLetters && strings.ContainsRune(shortOptions, 'y') {
				return true
			}
		}
	}
	return false
}
