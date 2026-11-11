package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// guestIdentityRecordName is the file, next to an image, that remembers the
// guest user's IDs as the guest reported them right before a clean shutdown.
const guestIdentityRecordName = ".guest-identity.json"

// guestImageFile identifies one file of an image's qcow2 chain by the stat
// fields that change whenever the file is written or replaced.
type guestImageFile struct {
	Path  string `json:"path"`
	Dev   uint64 `json:"dev"`
	Ino   uint64 `json:"ino"`
	Size  int64  `json:"size"`
	MTime int64  `json:"mtime_ns"`
}

type guestIdentityRecord struct {
	Chain []guestImageFile `json:"chain"`
	UID   int              `json:"uid"`
	GID   int              `json:"gid"`
}

// readGuestUserIDs asks the running guest for the user account's IDs, read
// from /etc/passwd as the image probe reads them.
func readGuestUserIDs(endpoint vmControlEndpoint) (int, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var out bytes.Buffer
	if err := runVMGuestCommand(ctx, endpoint, "root", `awk -F: '$1 == "user" { print $3, $4; exit }' /etc/passwd`, nil, &out, io.Discard); err != nil {
		return 0, 0, err
	}
	fields := strings.Fields(out.String())
	if len(fields) != 2 {
		return 0, 0, fmt.Errorf("guest /etc/passwd has no user account")
	}
	uid, uidErr := strconv.Atoi(fields[0])
	gid, gidErr := strconv.Atoi(fields[1])
	if uidErr != nil || gidErr != nil || uid <= 0 || gid <= 0 {
		return 0, 0, fmt.Errorf("guest user has invalid UID/GID")
	}
	return uid, gid, nil
}

// rememberGuestIdentity records the IDs the guest reported before a clean
// shutdown, for the image QEMU has just closed.
func rememberGuestIdentity(imagePath string, uid, gid int) error {
	chain, err := imageChainFiles(imagePath)
	if err != nil {
		return err
	}
	body, err := json.Marshal(guestIdentityRecord{Chain: chain, UID: uid, GID: gid})
	if err != nil {
		return err
	}
	return writeFileAtomically(filepath.Join(filepath.Dir(imagePath), guestIdentityRecordName), body, 0600)
}

// rememberedGuestIdentity returns the recorded IDs if no file of the image's
// chain has been written or replaced since they were recorded.
func rememberedGuestIdentity(imagePath string) (int, int, bool) {
	body, err := os.ReadFile(filepath.Join(filepath.Dir(imagePath), guestIdentityRecordName))
	if err != nil {
		return 0, 0, false
	}
	var record guestIdentityRecord
	if err := json.Unmarshal(body, &record); err != nil || record.UID <= 0 || record.GID <= 0 {
		return 0, 0, false
	}
	chain, err := imageChainFiles(imagePath)
	if err != nil || len(chain) != len(record.Chain) {
		return 0, 0, false
	}
	for i, file := range chain {
		// A renamed image is still the same file, so the path doesn't count.
		want := record.Chain[i]
		if file.Dev != want.Dev || file.Ino != want.Ino || file.Size != want.Size || file.MTime != want.MTime {
			return 0, 0, false
		}
	}
	return record.UID, record.GID, true
}

// imageChainFiles lists imagePath and the qcow2 backing files beneath it.
func imageChainFiles(imagePath string) ([]guestImageFile, error) {
	var chain []guestImageFile
	for path := imagePath; path != ""; {
		if len(chain) == 8 {
			return nil, fmt.Errorf("qcow2 backing chain of %s is too deep", imagePath)
		}
		var st syscall.Stat_t
		if err := syscall.Stat(path, &st); err != nil {
			return nil, fmt.Errorf("stat %s: %w", path, err)
		}
		chain = append(chain, guestImageFile{Path: path, Dev: uint64(st.Dev), Ino: st.Ino, Size: st.Size, MTime: st.Mtim.Nano()})
		backing, err := qcow2BackingFile(path)
		if err != nil {
			return nil, err
		}
		if backing != "" && !filepath.IsAbs(backing) {
			backing = filepath.Join(filepath.Dir(path), backing)
		}
		path = backing
	}
	return chain, nil
}

// qcow2BackingFile reads the backing file name from a qcow2 header, or ""
// when the image has none.
func qcow2BackingFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	header := make([]byte, 20)
	if _, err := io.ReadFull(f, header); err != nil {
		return "", fmt.Errorf("read qcow2 header of %s: %w", path, err)
	}
	if string(header[:4]) != "QFI\xfb" {
		return "", fmt.Errorf("%s is not a qcow2 image", path)
	}
	offset := binary.BigEndian.Uint64(header[8:16])
	size := binary.BigEndian.Uint32(header[16:20])
	if offset == 0 || size == 0 {
		return "", nil
	}
	if size > 1023 {
		return "", fmt.Errorf("qcow2 backing file name of %s is too long", path)
	}
	name := make([]byte, size)
	if _, err := f.ReadAt(name, int64(offset)); err != nil {
		return "", fmt.Errorf("read qcow2 backing file name of %s: %w", path, err)
	}
	if strings.HasPrefix(string(name), "json:") {
		return "", fmt.Errorf("qcow2 backing file of %s uses an unsupported json: name", path)
	}
	return string(name), nil
}

// readGuestIdentityFromImage inspects the selected disk, including any qcow2
// backing chain. It does not assume that a project or manifest still describes
// the account inside an image modified by a root shell or custom setup. It
// skips the full inspection only when the guest itself reported the IDs right
// before a clean shutdown and no file of the chain has changed since.
func readGuestIdentityFromImage(imagePath string) (int, int, error) {
	if uid, gid, ok := rememberedGuestIdentity(imagePath); ok {
		logDebug("using guest identity recorded at the last clean shutdown", "image", imagePath, "uid", uid, "gid", gid)
		return uid, gid, nil
	}
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
