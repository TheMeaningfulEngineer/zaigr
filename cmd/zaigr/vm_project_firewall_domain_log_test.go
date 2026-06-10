package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStreamProjectFirewallDomainLogDelegatesToInsideHelper(t *testing.T) {
	tempDir := t.TempDir()
	binDir := filepath.Join(tempDir, "bin")
	if err := os.Mkdir(binDir, 0755); err != nil {
		t.Fatal(err)
	}

	argsPath := filepath.Join(tempDir, "ssh-args")
	t.Setenv("ZAIGR_TEST_SSH_ARGS", argsPath)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	fakeSSH := filepath.Join(binDir, "ssh")
	if err := os.WriteFile(fakeSSH, []byte(`#!/bin/sh
printf '%s\n' "$@" > "$ZAIGR_TEST_SSH_ARGS"
found=
for arg in "$@"; do
    if [ "$arg" = "/usr/local/sbin/zaigr-inside firewall domain-log" ]; then
        found=1
    fi
done
if [ "$found" != "1" ]; then
    echo "missing zaigr-inside domain-log delegation" >&2
    exit 42
fi
printf '%s\n' "allowed chatgpt.com" "blocked api.github.com"
`), 0755); err != nil {
		t.Fatal(err)
	}

	oldStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	runErr := streamProjectFirewallDomainLog("10022", "/tmp/root.key")
	_ = writer.Close()
	os.Stdout = oldStdout

	output, readErr := io.ReadAll(reader)
	_ = reader.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if runErr != nil {
		t.Fatal(runErr)
	}

	wantOutput := "allowed chatgpt.com\nblocked api.github.com\n"
	if string(output) != wantOutput {
		t.Fatalf("domain log output:\n%s\nwant:\n%s", output, wantOutput)
	}

	argsBytes, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	args := "\n" + string(argsBytes)
	for _, want := range []string{
		"\n-i\n/tmp/root.key\n",
		"\n-p\n10022\n",
		"\nroot@localhost\n",
		"\n/usr/local/sbin/zaigr-inside firewall domain-log\n",
	} {
		if !strings.Contains(args, want) {
			t.Fatalf("ssh args missing %q:\n%s", strings.TrimSpace(want), argsBytes)
		}
	}
	if strings.Contains(string(argsBytes), "tail -n 0") {
		t.Fatalf("domain-log must delegate to zaigr-inside, got ssh args:\n%s", argsBytes)
	}
}
