package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()

	original := os.Stderr
	readFile, writeFile, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stderr pipe: %v", err)
	}
	os.Stderr = writeFile

	done := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, readFile)
		done <- buf.String()
	}()

	fn()

	_ = writeFile.Close()
	os.Stderr = original
	output := <-done
	_ = readFile.Close()
	return output
}

func TestAwaitingCommitStartupPromptListsUpToFourSetups(t *testing.T) {
	dir := t.TempDir()
	awaiting := []string{
		filepath.Join(dir, "001-python.sh"),
		filepath.Join(dir, "002-go.sh"),
		filepath.Join(dir, "003-nodejs.sh"),
		filepath.Join(dir, "004-codex.sh"),
	}

	output := captureStderr(t, func() {
		printAwaitingCommitStartupPrompt(awaiting)
	})

	for _, want := range []string{
		":: 4 setups are awaiting image commit:",
		"   - python",
		"   - go",
		"   - nodejs",
		"   - codex",
		"Save these setups to the project image before starting this VM?",
		"Action [c/d]: ",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("prompt missing %q:\n%s", want, output)
		}
	}
	if strings.Contains(output, "[s] show") {
		t.Fatalf("prompt should not offer show when every setup is already listed:\n%s", output)
	}
	if strings.Contains(output, "... ") {
		t.Fatalf("prompt should not truncate four setups:\n%s", output)
	}
}

func TestAwaitingCommitStartupPromptSingleSetupHasNoShow(t *testing.T) {
	dir := t.TempDir()
	awaiting := []string{
		filepath.Join(dir, "001-python.sh"),
	}

	output := captureStderr(t, func() {
		printAwaitingCommitStartupPrompt(awaiting)
	})

	for _, want := range []string{
		":: 1 setup is awaiting image commit:",
		"   - python",
		"Save this setup to the project image before starting this VM?",
		"[d] discard  Forget this setup awaiting image commit and continue",
		"Action [c/d]: ",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("prompt missing %q:\n%s", want, output)
		}
	}
	if strings.Contains(output, "[s] show") {
		t.Fatalf("single-setup prompt should not offer show:\n%s", output)
	}
}

func TestAwaitingCommitStartupPromptTruncatesAfterFourSetups(t *testing.T) {
	dir := t.TempDir()
	awaiting := []string{
		filepath.Join(dir, "001-python.sh"),
		filepath.Join(dir, "002-go.sh"),
		filepath.Join(dir, "003-nodejs.sh"),
		filepath.Join(dir, "004-codex.sh"),
		filepath.Join(dir, "005-claude.sh"),
	}

	output := captureStderr(t, func() {
		printAwaitingCommitStartupPrompt(awaiting)
	})

	for _, want := range []string{
		":: 5 setups are awaiting image commit:",
		"   - python",
		"   - go",
		"   - nodejs",
		"   - codex",
		"   ... 1 more",
		"[s] show     Show all",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("prompt missing %q:\n%s", want, output)
		}
	}
	if strings.Contains(output, "- claude") {
		t.Fatalf("prompt should not list fifth setup inline:\n%s", output)
	}
}

func TestAwaitingCommitImageIssuePromptShowsWarningBeforeActions(t *testing.T) {
	dir := t.TempDir()
	awaiting := []string{
		filepath.Join(dir, "001-release-tools.sh"),
		filepath.Join(dir, "002-kernel-mmdebstrap.sh"),
		filepath.Join(dir, "003-python.sh"),
		filepath.Join(dir, "004-go.sh"),
		filepath.Join(dir, "005-nodejs.sh"),
	}
	issue := awaitingCommitProjectImageIssue{
		ExpectedProjectImage: "image-abc1234.qcow2",
	}

	output := captureStderr(t, func() {
		printAwaitingCommitImageIssueStartupPrompt(awaiting, issue)
	})

	for _, want := range []string{
		":: 5 setups are awaiting image commit:",
		"   - release-tools",
		"   - kernel-mmdebstrap",
		"   - python",
		"   - go",
		"   ... 1 more",
		"warning: the project image cannot be found.",
		"  expected image: image-abc1234.qcow2",
		"  these setups cannot be saved without rebuilding the project image",
		"[r] rebuild & commit  Rebuild from current base image and commit these setups",
		"[d] discard           Forget these setups awaiting image commit and continue",
		"[s] show              Show all",
		"[Enter] cancel",
		"Action [r/d/s]: ",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("prompt missing %q:\n%s", want, output)
		}
	}
	if strings.Contains(output, "[i] ignore") || strings.Contains(output, "available project image") {
		t.Fatalf("image issue prompt should not offer unknown image selection:\n%s", output)
	}

	if strings.Contains(output, "Save these setups") {
		t.Fatalf("image issue prompt should not ask the normal commit question:\n%s", output)
	}
}
