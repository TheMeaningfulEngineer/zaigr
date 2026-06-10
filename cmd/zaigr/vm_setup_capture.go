package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const setupCaptureGuestAgentStateDir = "/home/user/.zaigr-agent-state"
const setupCaptureGuestCommandsPath = setupCaptureGuestAgentStateDir + "/" + setupCaptureCommandsFile
const setupCaptureGuestHistoryPath = setupCaptureGuestAgentStateDir + "/" + setupCaptureLegacyCommandsFile

type setupCaptureCommand struct {
	Command         string
	ExitStatus      int
	HasExitStatus   bool
	StartedUnixNano int64
	EndedUnixNano   int64
	NeededEndpoints []string
}

type setupCaptureEndpointEvent struct {
	UnixNano int64
	Endpoint string
}

type setupCaptureStartAction int

const (
	setupCaptureStartCancel setupCaptureStartAction = iota
	setupCaptureStartDiscard
	setupCaptureStartContinue
)

func cmdProjectSetupCaptureStart() error {
	if err := ensureProjectInitializedForVM("", ""); err != nil {
		return err
	}

	store := currentProjectStore()
	if meta, has, err := store.readSetupCaptureMetadata(); err != nil {
		return err
	} else if has {
		return handleActiveSetupCaptureStart(store, meta)
	}

	return startNewSetupCapture(store, true)
}

func startNewSetupCapture(store projectStore, confirmRunningVM bool) error {
	running, stale := detectRunningProjectVM()
	if stale {
		_ = store.clearRuntimeState()
		running = nil
	}
	if running != nil {
		if confirmRunningVM && !confirmSetupCaptureAttachToRunningVM() {
			return exitError(1)
		}
		if !confirmRunningVM {
			fmt.Fprintln(os.Stderr, ":: Starting a new setup capture on the running VM.")
		}
		return startSetupCaptureOnRunningVM(store, running)
	}

	baseImagePath, err := setupCaptureBaseImage(store)
	if err != nil {
		return err
	}

	overlayPath := store.setupCaptureOverlayPath()
	_ = os.Remove(overlayPath)
	_ = store.clearSetupCaptureObservedEndpoints()
	if err := store.prepareSetupCaptureCommands(); err != nil {
		return err
	}
	if err := createQcow2Overlay(baseImagePath, overlayPath); err != nil {
		return fmt.Errorf("create capture overlay: %w", err)
	}

	meta := setupCaptureMetadata{
		Name:             setupCaptureName(store),
		BaseImagePath:    baseImagePath,
		OverlayImagePath: overlayPath,
	}
	if err := store.writeSetupCaptureMetadata(meta); err != nil {
		_ = os.Remove(overlayPath)
		return err
	}

	projectImagePathOverrideForNextBoot = overlayPath
	defer func() {
		projectImagePathOverrideForNextBoot = ""
	}()

	port, err := startPreparedProjectVM("", "")
	if err != nil {
		_ = store.clearSetupCaptureMetadata()
		_ = os.Remove(overlayPath)
		return err
	}

	rootKeyPath := filepath.Join(zaigDir(), "root-ssh.key")
	logCtx, stopDomainLog := context.WithCancel(context.Background())
	domainLog, closeDomainLog, err := startSetupCaptureDomainLog(logCtx, port, rootKeyPath, store.setupCaptureObservedEndpointsPath())
	if err != nil {
		stopDomainLog()
		return err
	}
	defer func() {
		stopDomainLog()
		_ = domainLog.Wait()
		_ = closeDomainLog()
	}()

	token, err := setupCaptureFirewallToken()
	if err != nil {
		return err
	}
	return withTemporaryCaptureAllowAllFirewallRule(port, rootKeyPath, token, func() error {
		return runProjectSetupCaptureShell(port, token)
	})
}

func handleActiveSetupCaptureStart(store projectStore, meta setupCaptureMetadata) error {
	if err := printSetupCaptureStartPreview(store, meta, 5); err != nil {
		return err
	}

	switch promptActiveSetupCaptureStartAction(meta) {
	case setupCaptureStartDiscard:
		if meta.OverlayImagePath == "" {
			fmt.Fprintln(os.Stderr, ":: Discarding this running-VM capture only clears capture metadata and logs.")
			fmt.Fprintln(os.Stderr, "   It does not undo changes already made in the VM.")
		}
		if _, err := discardSetupCaptureState(store, meta, false); err != nil {
			return err
		}
		return startNewSetupCapture(store, meta.OverlayImagePath != "")
	case setupCaptureStartContinue:
		return continueSetupCapture(store, meta)
	default:
		fmt.Fprintln(os.Stderr, ":: Capture start cancelled")
		return exitError(1)
	}
}

func printSetupCaptureStartPreview(store projectStore, meta setupCaptureMetadata, limit int) error {
	observed, err := setupCaptureObservedEndpoints(store, meta)
	if err != nil {
		return err
	}
	commands, err := setupCaptureCommands(store)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, ":: An active setup capture already exists for this project.\n")
	fmt.Fprintf(os.Stderr, "setup capture: %s\n", meta.Name)
	if meta.OverlayImagePath != "" {
		fmt.Fprintf(os.Stderr, "mode: capture overlay\n")
		fmt.Fprintf(os.Stderr, "overlay image: %s\n", filepath.Base(meta.OverlayImagePath))
	} else {
		fmt.Fprintf(os.Stderr, "mode: running VM\n")
		fmt.Fprintf(os.Stderr, "discard: clears capture metadata/logs only; VM changes remain\n")
	}
	if meta.StartedAt != "" {
		fmt.Fprintf(os.Stderr, "started: %s\n", meta.StartedAt)
	}
	fmt.Fprintln(os.Stderr, "proposed setup.firewall:")
	printLimitedSetupCapturePreviewLines(os.Stderr, observed, limit)
	fmt.Fprintln(os.Stderr, "recorded setup.script lines:")
	printLimitedSetupCapturePreviewLines(os.Stderr, setupCaptureScriptPreviewLines(commands), limit)
	return nil
}

func printLimitedSetupCapturePreviewLines(w io.Writer, lines []string, limit int) {
	if len(lines) == 0 {
		fmt.Fprintln(w, "  (none)")
		return
	}
	for index, line := range lines {
		if index >= limit {
			fmt.Fprintf(w, "  ... (%d more omitted)\n", len(lines)-limit)
			return
		}
		fmt.Fprintf(w, "  %s\n", line)
	}
}

func requireNoActiveSetupCapture(command string) error {
	store := currentProjectStore()
	meta, active, err := store.readSetupCaptureMetadata()
	if err != nil {
		return err
	}
	if !active {
		return nil
	}

	return activeSetupCaptureRefusalError(command, meta)
}

func activeSetupCaptureRefusalError(command string, meta setupCaptureMetadata) error {
	var message strings.Builder
	message.WriteString("project setup capture is active")
	if meta.Name != "" {
		fmt.Fprintf(&message, ": %s", meta.Name)
	}
	fmt.Fprintf(&message, "; accept or discard it before running %s\n", command)
	message.WriteString("   accept: zaigr project setup capture accept\n")
	message.WriteString("   discard: zaigr project setup capture discard")
	return fmt.Errorf("%s", message.String())
}

func setupCaptureScriptPreviewLines(commands []setupCaptureCommand) []string {
	lines := make([]string, 0, len(commands)*2)
	for _, command := range commands {
		lines = append(lines, command.Command)
		if command.HasExitStatus {
			lines = append(lines, fmt.Sprintf("# Returned %d", command.ExitStatus))
		}
		for _, endpoint := range command.NeededEndpoints {
			lines = append(lines, "# Needed access to "+endpoint)
		}
	}
	return lines
}

func promptActiveSetupCaptureStartAction(meta setupCaptureMetadata) setupCaptureStartAction {
	for {
		fmt.Fprintln(os.Stderr, "Choose: [d] discard active and start anew, [c] continue appending, [Enter] cancel")
		fmt.Fprint(os.Stderr, "> ")
		var answer string
		_, err := fmt.Scanln(&answer)
		if err != nil {
			return setupCaptureStartCancel
		}
		switch strings.ToLower(strings.TrimSpace(answer)) {
		case "d", "discard":
			return setupCaptureStartDiscard
		case "c", "continue":
			return setupCaptureStartContinue
		case "", "q", "cancel":
			return setupCaptureStartCancel
		default:
			fmt.Fprintf(os.Stderr, ":: Unknown choice %q\n", answer)
		}
	}
}

func startSetupCaptureOnRunningVM(store projectStore, running *runningVMInfo) error {
	if running.Port == "" {
		return fmt.Errorf("project VM is running but its SSH port is unknown")
	}
	_ = store.clearSetupCaptureObservedEndpoints()
	if err := store.prepareSetupCaptureCommands(); err != nil {
		return err
	}

	meta := setupCaptureMetadata{
		Name: setupCaptureName(store),
	}
	if err := store.writeSetupCaptureMetadata(meta); err != nil {
		return err
	}

	rootKeyPath := filepath.Join(zaigDir(), "root-ssh.key")
	logCtx, stopDomainLog := context.WithCancel(context.Background())
	domainLog, closeDomainLog, err := startSetupCaptureDomainLog(logCtx, running.Port, rootKeyPath, store.setupCaptureObservedEndpointsPath())
	if err != nil {
		_ = store.clearSetupCaptureMetadata()
		stopDomainLog()
		return err
	}
	defer func() {
		stopDomainLog()
		_ = domainLog.Wait()
		_ = closeDomainLog()
	}()

	token, err := setupCaptureFirewallToken()
	if err != nil {
		return err
	}
	return withTemporaryCaptureAllowAllFirewallRule(running.Port, rootKeyPath, token, func() error {
		return runProjectSetupCaptureShell(running.Port, token)
	})
}

func continueSetupCapture(store projectStore, meta setupCaptureMetadata) error {
	hasOverlay := meta.OverlayImagePath != ""
	if hasOverlay {
		if _, err := os.Stat(meta.OverlayImagePath); err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("capture overlay missing; discard and start capture again")
			}
			return fmt.Errorf("capture overlay: %w", err)
		}
	}

	if running, stale := detectRunningProjectVMWithMetadataInStore(store); stale {
		_ = store.clearRuntimeState()
	} else if running != nil {
		if hasOverlay && running.ImagePath != "" && running.ImagePath != meta.OverlayImagePath {
			return fmt.Errorf("active project VM is not running the capture overlay (%s); stop it before continuing this capture", filepath.Base(meta.OverlayImagePath))
		}
		return attachSetupCaptureShell(store, running.Port)
	}

	if !hasOverlay {
		return fmt.Errorf("cannot continue running-VM capture because the project VM is not running; discard and start again")
	}

	projectImagePathOverrideForNextBoot = meta.OverlayImagePath
	defer func() {
		projectImagePathOverrideForNextBoot = ""
	}()

	port, err := startPreparedProjectVM("", "")
	if err != nil {
		return err
	}
	return attachSetupCaptureShell(store, port)
}

func attachSetupCaptureShell(store projectStore, port string) error {
	rootKeyPath := filepath.Join(zaigDir(), "root-ssh.key")
	logCtx, stopDomainLog := context.WithCancel(context.Background())
	domainLog, closeDomainLog, err := startSetupCaptureDomainLog(logCtx, port, rootKeyPath, store.setupCaptureObservedEndpointsPath())
	if err != nil {
		stopDomainLog()
		return err
	}
	defer func() {
		stopDomainLog()
		_ = domainLog.Wait()
		_ = closeDomainLog()
	}()

	token, err := setupCaptureFirewallToken()
	if err != nil {
		return err
	}
	return withTemporaryCaptureAllowAllFirewallRule(port, rootKeyPath, token, func() error {
		return runProjectSetupCaptureShell(port, token)
	})
}

func confirmSetupCaptureAttachToRunningVM() bool {
	fmt.Fprintln(os.Stderr, ":: A project VM is already running.")
	fmt.Fprintln(os.Stderr, "   Capture will attach to the running VM.")
	fmt.Fprintln(os.Stderr, "   Discarding the capture will not undo changes made in that VM.")
	fmt.Fprint(os.Stderr, "Continue? [y/N] ")
	var answer string
	_, _ = fmt.Scanln(&answer)
	return strings.EqualFold(strings.TrimSpace(answer), "y") || strings.EqualFold(strings.TrimSpace(answer), "yes")
}

func cmdProjectSetupCaptureReview() error {
	if _, err := requireProject("project setup capture review"); err != nil {
		return err
	}

	store := currentProjectStore()
	meta, ok, err := store.readSetupCaptureMetadata()
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("no active setup capture to review — run 'zaigr project setup capture start' first")
	}
	hasOverlay := meta.OverlayImagePath != ""
	if hasOverlay {
		if _, err := os.Stat(meta.OverlayImagePath); err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("capture overlay missing; discard and start capture again")
			}
			return fmt.Errorf("capture overlay: %w", err)
		}
	}

	source := "stored"
	observed, err := setupCaptureObservedEndpoints(store, meta)
	if err != nil {
		return err
	}
	commands, err := setupCaptureCommands(store)
	if err != nil {
		return err
	}
	if running, stale := detectRunningProjectVMWithMetadataInStore(store); stale {
		_ = store.clearRuntimeState()
	} else if running != nil {
		if hasOverlay && running.ImagePath != "" && running.ImagePath != meta.OverlayImagePath {
			fmt.Fprintf(os.Stderr, ":: Active project VM is not using capture overlay: %s\n", running.ImagePath)
		} else {
			source = "live"
		}
	}
	meta.ObservedFirewall = observed
	_ = store.writeSetupCaptureMetadata(meta)

	script := buildCaptureSetupScript(meta.Name, observed, commands, meta.StartedAt)

	fmt.Printf("setup capture: %s\n", meta.Name)
	if hasOverlay {
		fmt.Printf("mode: capture overlay\n")
		fmt.Printf("overlay image: %s\n", filepath.Base(meta.OverlayImagePath))
	} else {
		fmt.Printf("mode: running VM\n")
	}
	fmt.Printf("started: %s\n", meta.StartedAt)
	fmt.Printf("observed endpoints (%s):\n", source)
	if len(observed) == 0 {
		fmt.Println("  (none)")
	} else {
		for _, endpoint := range observed {
			fmt.Printf("  %s\n", endpoint)
		}
	}

	fmt.Println("proposed setup.firewall:")
	if len(observed) == 0 {
		fmt.Println("  (none)")
	} else {
		for _, entry := range observed {
			fmt.Printf("  %s\n", entry)
		}
	}

	fmt.Println("proposed setup.script:")
	fmt.Println(script)
	return nil
}

func cmdProjectSetupCaptureAccept() error {
	if _, err := requireProject("project setup capture accept"); err != nil {
		return err
	}

	store := currentProjectStore()
	meta, ok, err := store.readSetupCaptureMetadata()
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("no active setup capture to accept — run 'zaigr project setup capture start' first")
	}
	hasOverlay := meta.OverlayImagePath != ""
	if hasOverlay {
		if _, err := os.Stat(meta.OverlayImagePath); err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("capture overlay missing; run 'zaigr project setup capture discard' to clear stale metadata")
			}
			return fmt.Errorf("capture overlay: %w", err)
		}
	}

	observed, err := setupCaptureObservedEndpoints(store, meta)
	if err != nil {
		return err
	}
	commands, err := setupCaptureCommands(store)
	if err != nil {
		return err
	}
	if len(commands) == 0 {
		return fmt.Errorf("setup capture has no captured commands; run commands in the capture shell before accepting")
	}
	running, stale := detectRunningProjectVMWithMetadataInStore(store)
	if stale {
		_ = store.clearRuntimeState()
	} else if hasOverlay && running != nil && running.ImagePath != "" && running.ImagePath != meta.OverlayImagePath {
		return fmt.Errorf("active project VM is not running the capture overlay (%s); stop or restart the capture shell first", filepath.Base(meta.OverlayImagePath))
	}
	meta.ObservedFirewall = observed
	_ = store.writeSetupCaptureMetadata(meta)

	script := buildCaptureSetupScript(meta.Name, observed, commands, meta.StartedAt)
	if err := writeSetupCaptureSetup(meta.Name, script, observed); err != nil {
		return err
	}

	var promotedImagePath string
	if hasOverlay {
		var err error
		promotedImagePath, err = acceptSetupCaptureOverlay(meta, script)
		if err != nil {
			return err
		}
	}
	if err := store.clearSetupCaptureMetadata(); err != nil {
		return err
	}
	if err := store.clearSetupCaptureObservedEndpoints(); err != nil {
		return err
	}
	if err := store.clearSetupCaptureCommands(); err != nil {
		return err
	}

	fmt.Printf(":: Accepted setup capture as %s\n", meta.Name)
	fmt.Printf(":: Updated setup definition: %s\n", filepath.Join(zaigDir(), "setups", meta.Name))
	if promotedImagePath != "" {
		fmt.Printf(":: Promoted capture overlay to project image: %s\n", filepath.Base(promotedImagePath))
	}
	return nil
}

func acceptSetupCaptureOverlay(meta setupCaptureMetadata, script string) (string, error) {
	committed, err := storeCommittedSetups()
	if err != nil {
		return "", err
	}

	oldImagePath, err := storeImagePathForSteps(committed)
	if err != nil {
		return "", err
	}

	updated := make([]string, 0, len(committed)+1)
	for _, step := range committed {
		if storeScriptBaseNameFromPath(step) == meta.Name {
			storeRemove(step)
			continue
		}
		updated = append(updated, step)
	}

	newStep, err := storeSaveScript(setupStateCommitted, []byte(script), meta.Name)
	if err != nil {
		return "", fmt.Errorf("record capture in committed setups: %w", err)
	}
	updated = append(updated, newStep)

	newImagePath, err := storeImagePathForSteps(updated)
	if err != nil {
		return "", err
	}

	if _, err := os.Stat(newImagePath); err == nil {
		if err := os.Remove(newImagePath); err != nil && !os.IsNotExist(err) {
			return "", fmt.Errorf("remove existing target image: %w", err)
		}
	}
	if err := os.Rename(meta.OverlayImagePath, newImagePath); err != nil {
		return "", fmt.Errorf("promote capture overlay: %w", err)
	}

	if oldImagePath != newImagePath {
		if err := os.Remove(oldImagePath); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, ":: Could not remove old image %s: %v\n", filepath.Base(oldImagePath), err)
		}
	}

	if err := currentProjectStore().clearProjectImageDirty(); err != nil {
		return "", err
	}
	return newImagePath, nil
}

func cmdProjectSetupCaptureDiscard() error {
	if _, err := requireProject("project setup capture discard"); err != nil {
		return err
	}

	store := currentProjectStore()
	meta, ok, err := store.readSetupCaptureMetadata()
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("no active setup capture to discard")
	}

	discarded, err := discardSetupCaptureState(store, meta, true)
	if err != nil {
		return err
	}
	if !discarded {
		return nil
	}

	fmt.Printf(":: Discarded setup capture\n")
	return nil
}

func discardSetupCaptureState(store projectStore, meta setupCaptureMetadata, prompt bool) (bool, error) {
	running, stale := detectRunningProjectVMWithMetadataInStore(store)
	if stale {
		_ = store.clearRuntimeState()
	}
	if meta.OverlayImagePath != "" && running != nil && running.ImagePath != "" && running.ImagePath != meta.OverlayImagePath {
		return false, fmt.Errorf("project VM is running from %s; stop it before discard", filepath.Base(running.ImagePath))
	}
	if meta.OverlayImagePath != "" && running != nil && running.ImagePath == meta.OverlayImagePath {
		if prompt {
			fmt.Fprintf(os.Stderr, "Discarding this capture will stop the capture VM and remove the capture record.\n")
			fmt.Fprint(os.Stderr, "Continue? [y/N] ")
			var answer string
			_, _ = fmt.Scanln(&answer)
			if !strings.EqualFold(strings.TrimSpace(answer), "y") && !strings.EqualFold(strings.TrimSpace(answer), "yes") {
				fmt.Fprintln(os.Stderr, ":: Discard cancelled")
				return false, nil
			}
		}
		if result, err := stopProjectVMInStore(store, false); err != nil {
			return false, fmt.Errorf("stop capture VM: %w", err)
		} else if result.State == projectVMStopStateStopped {
			fmt.Fprintf(os.Stderr, ":: Stopped capture VM before discard\n")
		}
	}

	if meta.OverlayImagePath != "" {
		if err := os.Remove(meta.OverlayImagePath); err != nil && !os.IsNotExist(err) {
			return false, fmt.Errorf("remove capture overlay: %w", err)
		}
	}
	if err := store.clearSetupCaptureMetadata(); err != nil {
		return false, err
	}
	if err := store.clearSetupCaptureObservedEndpoints(); err != nil {
		return false, err
	}
	if err := store.clearSetupCaptureCommands(); err != nil {
		return false, err
	}
	return true, nil
}

func runProjectSetupCaptureShell(port string, token string) error {
	args, err := projectSSHArgs(port, true)
	if err != nil {
		return err
	}
	args = append([]string{args[0], "-tt"}, args[1:]...)
	args = append(args, "bash -eu -c "+singleQuotedArg(setupCaptureShellCommand(token)))

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	cleanup, err := writeShellSessionMarker(currentProjectStore(), cmd.Process.Pid, true, port)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("track shell session: %w", err)
	}
	defer cleanup()
	return cmd.Wait()
}

func setupCaptureShellCommand(token string) string {
	rcfile := "/tmp/zaigr-setup-capture.bashrc"
	return "" +
		"agent_state=" + singleQuotedArg(setupCaptureGuestAgentStateDir) + "\n" +
		"commands_path=" + singleQuotedArg(setupCaptureGuestCommandsPath) + "\n" +
		"if ! mountpoint -q \"$agent_state\"; then\n" +
		"  echo \"setup capture command log mount not available: $agent_state\" >&2\n" +
		"  exit 1\n" +
		"fi\n" +
		"mkdir -p \"$(dirname \"$commands_path\")\"\n" +
		"touch \"$commands_path\"\n" +
		"cat > " + singleQuotedArg(rcfile) + " <<'EOF'\n" +
		"export HISTFILE=" + setupCaptureGuestHistoryPath + "\n" +
		"export ZAIGR_CAPTURE_COMMAND_LOG=" + setupCaptureGuestCommandsPath + "\n" +
		"export ZAIGR_SETUP_CAPTURE_TOKEN=" + token + "\n" +
		"export HISTSIZE=10000\n" +
		"export HISTFILESIZE=10000\n" +
		"unset HISTCONTROL\n" +
		"unset HISTIGNORE\n" +
		"set -o history\n" +
		"shopt -s histappend cmdhist lithist\n" +
		"history -c\n" +
		"history -r \"$HISTFILE\" 2>/dev/null || true\n" +
		"__zaigr_capture_started_ns=\n" +
		"__zaigr_capture_last_command=\n" +
		"__zaigr_capture_is_plumbing() {\n" +
		"  case \"$1\" in\n" +
		"    ''|history|history\\ *|PROMPT_COMMAND=*|PS1=*|export\\ HISTFILE=*|export\\ ZAIGR_CAPTURE_COMMAND_LOG=*|trap\\ *|__zaigr_capture_*) return 0 ;;\n" +
		"    *) return 1 ;;\n" +
		"  esac\n" +
		"}\n" +
		"__zaigr_capture_now_ns() { date +%s%N; }\n" +
		"__zaigr_capture_preexec() {\n" +
		"  local command=\"$BASH_COMMAND\"\n" +
		"  if __zaigr_capture_is_plumbing \"$command\"; then return; fi\n" +
		"  if [ -z \"$__zaigr_capture_started_ns\" ]; then\n" +
		"    __zaigr_capture_started_ns=\"$(__zaigr_capture_now_ns)\"\n" +
		"  fi\n" +
		"}\n" +
		"__zaigr_capture_prompt() {\n" +
		"  local status=\"$?\"\n" +
		"  local ended_ns command encoded started_ns\n" +
		"  ended_ns=\"$(__zaigr_capture_now_ns)\"\n" +
		"  command=\"$(HISTTIMEFORMAT= history 1 | sed 's/^ *[0-9][0-9]*[[:space:]]*//')\"\n" +
		"  if ! __zaigr_capture_is_plumbing \"$command\" && [ \"$command\" != \"$__zaigr_capture_last_command\" ]; then\n" +
		"    started_ns=\"$__zaigr_capture_started_ns\"\n" +
		"    if [ -z \"$started_ns\" ]; then started_ns=\"$ended_ns\"; fi\n" +
		"    encoded=\"$(printf '%s' \"$command\" | base64 | tr -d '\\n')\"\n" +
		"    printf 'v1\\t%s\\t%s\\t%s\\t%s\\n' \"$status\" \"$started_ns\" \"$ended_ns\" \"$encoded\" >> \"$ZAIGR_CAPTURE_COMMAND_LOG\"\n" +
		"    __zaigr_capture_last_command=\"$command\"\n" +
		"  fi\n" +
		"  __zaigr_capture_started_ns=\n" +
		"  history -a \"$HISTFILE\"\n" +
		"  history -n \"$HISTFILE\"\n" +
		"}\n" +
		"trap '__zaigr_capture_preexec' DEBUG\n" +
		"PROMPT_COMMAND='__zaigr_capture_prompt'\n" +
		"PS1='\\u@\\h:\\w# '\n" +
		"EOF\n" +
		"exec bash --rcfile " + singleQuotedArg(rcfile) + " -i"
}

func setupCaptureFirewallToken() (string, error) {
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", fmt.Errorf("generate setup capture firewall token: %w", err)
	}
	return hex.EncodeToString(token[:]), nil
}

func startSetupCaptureDomainLog(ctx context.Context, port string, rootKeyPath string, outputPath string) (*exec.Cmd, func() error, error) {
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return nil, nil, fmt.Errorf("create capture endpoint log dir: %w", err)
	}
	output, err := os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, nil, fmt.Errorf("open capture endpoint log: %w", err)
	}

	args := append(sshManagedOptions(), "-o", sshConnectTimeoutOption)
	args = append(args, "-i", rootKeyPath, "-p", port, "root@localhost", "/usr/local/sbin/zaigr-inside firewall domain-log")
	cmd := exec.CommandContext(ctx, "ssh", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = output.Close()
		return nil, nil, fmt.Errorf("open capture endpoint stream: %w", err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		_ = output.Close()
		return nil, nil, fmt.Errorf("start capture endpoint log: %w", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			_, _ = fmt.Fprintf(output, "%d %s\n", time.Now().UnixNano(), line)
		}
		if err := scanner.Err(); err != nil && !strings.Contains(err.Error(), "file already closed") {
			fmt.Fprintf(os.Stderr, ":: Capture endpoint log stopped: %v\n", err)
		}
	}()
	closeLog := func() error {
		<-done
		return output.Close()
	}
	return cmd, closeLog, nil
}

func setupCaptureObservedEndpoints(store projectStore, meta setupCaptureMetadata) ([]string, error) {
	entries := append([]string{}, meta.ObservedFirewall...)
	events, err := setupCaptureEndpointEvents(store)
	if err != nil {
		return nil, err
	}
	for _, event := range events {
		entries = append(entries, event.Endpoint)
	}
	return normalizedSetupCaptureEndpoints(entries), nil
}

func setupCaptureEndpointEvents(store projectStore) ([]setupCaptureEndpointEvent, error) {
	data, err := os.ReadFile(store.setupCaptureObservedEndpointsPath())
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("read capture observed endpoints: %w", err)
	}
	events := make([]setupCaptureEndpointEvent, 0)
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) == 3 {
				if parts[1] != "allowed" && parts[1] != "blocked" {
					continue
				}
				unixNano, parseErr := strconv.ParseInt(parts[0], 10, 64)
				if parseErr != nil {
					continue
				}
				events = append(events, setupCaptureEndpointEvent{UnixNano: unixNano, Endpoint: parts[2]})
				continue
			}
			if len(parts) != 2 {
				continue
			}
			if parts[0] != "allowed" && parts[0] != "blocked" {
				continue
			}
			events = append(events, setupCaptureEndpointEvent{Endpoint: parts[1]})
		}
	}
	return events, nil
}

func (store projectStore) prepareSetupCaptureCommands() error {
	if err := store.ensureAgentStateDir(); err != nil {
		return err
	}
	if err := store.clearSetupCaptureCommands(); err != nil {
		return err
	}
	path := store.setupCaptureCommandsPath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create setup capture command dir: %w", err)
	}
	if err := os.WriteFile(path, nil, 0600); err != nil {
		return fmt.Errorf("initialize setup capture command log: %w", err)
	}
	return nil
}

func setupCaptureCommands(store projectStore) ([]setupCaptureCommand, error) {
	commands, err := readSetupCaptureCommandsFile(store.setupCaptureCommandsPath())
	if err != nil {
		return nil, err
	}
	if len(commands) > 0 {
		events, err := setupCaptureEndpointEvents(store)
		if err != nil {
			return nil, err
		}
		attachSetupCaptureCommandEndpoints(commands, events)
		return commands, nil
	}

	legacyCommands, err := readSetupCaptureCommandsFile(store.setupCaptureLegacyCommandsPath())
	if err != nil {
		return nil, err
	}
	events, err := setupCaptureEndpointEvents(store)
	if err != nil {
		return nil, err
	}
	attachSetupCaptureCommandEndpoints(legacyCommands, events)
	return legacyCommands, nil
}

func readSetupCaptureCommandsFile(path string) ([]setupCaptureCommand, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read capture commands: %w", err)
	}
	commands := make([]setupCaptureCommand, 0)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		command, ok := parseSetupCaptureCommandLogLine(line)
		if !ok {
			continue
		}
		commands = append(commands, command)
	}
	return commands, nil
}

func parseSetupCaptureCommandLogLine(line string) (setupCaptureCommand, bool) {
	parts := strings.Split(line, "\t")
	if len(parts) == 5 && parts[0] == "v1" {
		exitStatus, err := strconv.Atoi(parts[1])
		if err != nil {
			return setupCaptureCommand{}, false
		}
		startedUnixNano, err := strconv.ParseInt(parts[2], 10, 64)
		if err != nil {
			return setupCaptureCommand{}, false
		}
		endedUnixNano, err := strconv.ParseInt(parts[3], 10, 64)
		if err != nil {
			return setupCaptureCommand{}, false
		}
		decoded, err := base64.StdEncoding.DecodeString(parts[4])
		if err != nil {
			return setupCaptureCommand{}, false
		}
		command := strings.TrimSpace(string(decoded))
		if setupCaptureCommandIsPlumbing(command) {
			return setupCaptureCommand{}, false
		}
		return setupCaptureCommand{
			Command:         command,
			ExitStatus:      exitStatus,
			HasExitStatus:   true,
			StartedUnixNano: startedUnixNano,
			EndedUnixNano:   endedUnixNano,
		}, true
	}

	command := strings.TrimSpace(line)
	if setupCaptureCommandIsPlumbing(command) {
		return setupCaptureCommand{}, false
	}
	return setupCaptureCommand{Command: command}, true
}

func setupCaptureCommandIsPlumbing(command string) bool {
	command = strings.TrimSpace(command)
	if command == "" || command == "exit" || command == "logout" || command == "history" {
		return true
	}
	if strings.HasPrefix(command, "history -r ") ||
		strings.HasPrefix(command, "history -c") ||
		strings.HasPrefix(command, "history -a ") ||
		strings.HasPrefix(command, "history -n ") ||
		strings.HasPrefix(command, "PROMPT_COMMAND=") ||
		strings.HasPrefix(command, "PS1=") ||
		strings.HasPrefix(command, "export HISTFILE=") ||
		strings.HasPrefix(command, "export HISTSIZE=") ||
		strings.HasPrefix(command, "export HISTFILESIZE=") ||
		strings.HasPrefix(command, "unset HISTCONTROL") ||
		strings.HasPrefix(command, "unset HISTIGNORE") ||
		strings.HasPrefix(command, "set -o history") ||
		strings.HasPrefix(command, "shopt -s histappend") ||
		strings.HasPrefix(command, "export ZAIGR_CAPTURE_COMMAND_LOG=") ||
		strings.HasPrefix(command, "trap '__zaigr_capture_preexec' DEBUG") ||
		strings.HasPrefix(command, "__zaigr_capture_") {
		return true
	}
	return false
}

func attachSetupCaptureCommandEndpoints(commands []setupCaptureCommand, events []setupCaptureEndpointEvent) {
	for commandIndex := range commands {
		command := &commands[commandIndex]
		if command.StartedUnixNano == 0 || command.EndedUnixNano == 0 {
			continue
		}
		seen := make(map[string]struct{})
		for _, event := range events {
			if event.UnixNano == 0 || event.UnixNano < command.StartedUnixNano || event.UnixNano > command.EndedUnixNano {
				continue
			}
			if _, ok := seen[event.Endpoint]; ok {
				continue
			}
			seen[event.Endpoint] = struct{}{}
			command.NeededEndpoints = append(command.NeededEndpoints, event.Endpoint)
		}
		sort.Strings(command.NeededEndpoints)
	}
}

func normalizedSetupCaptureEndpoints(entries []string) []string {
	seen := make(map[string]struct{}, len(entries))
	normalized := make([]string, 0, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if _, ok := seen[entry]; ok {
			continue
		}
		seen[entry] = struct{}{}
		normalized = append(normalized, entry)
	}
	sort.Strings(normalized)
	return normalized
}

func setupCaptureName(store projectStore) string {
	return "capture-" + store.Hash
}

func setupCaptureBaseImage(store projectStore) (string, error) {
	imagePath, err := store.imagePath()
	if err != nil {
		return "", err
	}

	if _, err := os.Stat(imagePath); err == nil {
		return imagePath, nil
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("stat project image %s: %w", filepath.Base(imagePath), err)
	}

	steps, err := store.committedSetups()
	if err != nil {
		return "", err
	}
	if len(steps) > 0 {
		return "", fmt.Errorf("project image missing: %s; rebuild project image before starting capture", filepath.Base(imagePath))
	}

	disk, _ := resolveDisk("")
	wipPath := imagePath + ".wip"
	if err := buildImageFromBase(wipPath, disk); err != nil {
		_ = os.Remove(wipPath)
		return "", fmt.Errorf("build project base image: %w", err)
	}
	if err := os.Rename(wipPath, imagePath); err != nil {
		_ = os.Remove(wipPath)
		return "", fmt.Errorf("rename base image: %w", err)
	}
	if err := currentProjectStore().writeBaseImageVersion(baseRootfsVersion()); err != nil {
		return "", err
	}
	return imagePath, nil
}

func writeSetupCaptureSetup(name string, setupScript string, firewallEntries []string) error {
	root := filepath.Join(zaigDir(), "setups", name)
	if err := os.MkdirAll(root, 0755); err != nil {
		return fmt.Errorf("create setup root: %w", err)
	}

	scriptPath := filepath.Join(root, "setup.script")
	if err := os.WriteFile(scriptPath, []byte(setupScript), 0644); err != nil {
		return fmt.Errorf("write captured setup script: %w", err)
	}

	sort.Strings(firewallEntries)
	if len(firewallEntries) == 0 {
		firewallEntries = []string{"# no endpoints observed"}
	}
	firewallPath := filepath.Join(root, "setup.firewall")
	if err := os.WriteFile(firewallPath, []byte(strings.Join(firewallEntries, "\n")+"\n"), 0644); err != nil {
		return fmt.Errorf("write captured setup firewall: %w", err)
	}
	return nil
}

func buildCaptureSetupScript(name string, observed []string, commands []setupCaptureCommand, startedAt string) string {
	var script strings.Builder
	script.WriteString("#!/bin/bash\n")
	script.WriteString("set -eu\n\n")
	script.WriteString(fmt.Sprintf("# Captured setup: %s\n", name))
	if startedAt != "" {
		script.WriteString(fmt.Sprintf("# Captured: %s\n", startedAt))
	}
	if len(observed) > 0 {
		script.WriteString("# Observed domains during capture:\n")
		for _, endpoint := range observed {
			script.WriteString("# " + endpoint + "\n")
		}
	}
	script.WriteString("\n")
	if len(commands) == 0 {
		script.WriteString("# No commands captured yet.\n")
		script.WriteString("# Run commands in the capture shell, then review again.\n")
		script.WriteString(":\n")
		return script.String()
	}
	for _, command := range commands {
		script.WriteString(command.Command)
		script.WriteByte('\n')
		if command.HasExitStatus {
			script.WriteString(fmt.Sprintf("# Returned %d\n", command.ExitStatus))
		}
		for _, endpoint := range command.NeededEndpoints {
			script.WriteString("# Needed access to " + endpoint + "\n")
		}
	}
	return script.String()
}
