package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// readGuestIdentityFromImage inspects the selected disk, including any qcow2
// backing chain. It does not assume that a project or manifest still describes
// the account inside an image modified by a root shell or custom setup.
func readGuestIdentityFromImage(imagePath string) (int, int, error) {
	// The sparse raw copy can occupy substantial disk space. Keep it on the
	// selected image's filesystem rather than the host's potentially small tmpfs.
	temp, err := os.CreateTemp(filepath.Dir(imagePath), ".zaigr-identity-*.raw")
	if err != nil {
		return 0, 0, fmt.Errorf("create guest identity probe: %w", err)
	}
	raw := temp.Name()
	_ = temp.Close()
	defer func() { _ = os.Remove(raw) }()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, findTool("qemu-img", "/usr/bin/qemu-img"), "convert", "-f", "qcow2", "-O", "raw", "-S", "4k", imagePath, raw).CombinedOutput()
	if err != nil {
		return 0, 0, fmt.Errorf("read selected VM image identity: qemu-img convert: %w: %s", err, strings.TrimSpace(string(out)))
	}
	// debugfs does not replay an ext4 journal. QEMU can leave committed
	// metadata in that journal even after a clean VM shutdown. Replay only on
	// this disposable raw copy, never on the selected qcow2 or its backing chain.
	fsckOutput, fsckErr := exec.CommandContext(ctx, findTool("e2fsck", "/usr/sbin/e2fsck"), "-p", "-E", "journal_only", raw).CombinedOutput()
	if fsckErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(fsckErr, &exitErr) || exitErr.ExitCode() != 1 {
			return 0, 0, fmt.Errorf("replay selected VM image journal on disposable copy: %w: %s", fsckErr, strings.TrimSpace(string(fsckOutput)))
		}
	}
	if err := ctx.Err(); err != nil {
		return 0, 0, fmt.Errorf("read selected VM image identity deadline: %w", err)
	}
	debugfs := exec.CommandContext(ctx, findTool("debugfs", "/usr/sbin/debugfs"), "-R", "cat /etc/passwd", raw)
	var passwd bytes.Buffer
	var diagnostic bytes.Buffer
	debugfs.Stdout = &passwd
	debugfs.Stderr = &diagnostic
	err = debugfs.Run()
	if err != nil {
		return 0, 0, fmt.Errorf("read selected VM image /etc/passwd: %w: %s", err, strings.TrimSpace(diagnostic.String()))
	}
	for _, line := range strings.Split(passwd.String(), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 7 || fields[0] != "user" {
			continue
		}
		uid, uidErr := strconv.Atoi(fields[2])
		gid, gidErr := strconv.Atoi(fields[3])
		if uidErr != nil || gidErr != nil || uid <= 0 || gid <= 0 {
			return 0, 0, fmt.Errorf("selected VM image has invalid user UID/GID")
		}
		return uid, gid, nil
	}
	detail := strings.TrimSpace(diagnostic.String())
	if len(detail) > 512 {
		detail = detail[:512]
	}
	return 0, 0, fmt.Errorf("selected VM image /etc/passwd contains no user account (debugfs stdout %d bytes; stderr: %q)", passwd.Len(), detail)
}
