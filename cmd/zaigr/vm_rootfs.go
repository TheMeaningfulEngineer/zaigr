package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/klauspost/compress/zstd"
)

// buildImageFromEmbeddedBase prepares a reusable base whose filesystem already
// has the requested project capacity.
func buildImageFromEmbeddedBase(outputPath string, disk string) error {
	logInfo("building shared image from embedded base rootfs", "output", outputPath, "disk", disk)
	rawPath := outputPath + ".raw-tmp"
	defer func() { _ = os.Remove(rawPath) }()
	if err := decompressZstd(embeddedRootfs, rawPath); err != nil {
		return fmt.Errorf("decompress rootfs: %w", err)
	}
	if out, err := exec.Command("truncate", "-s", disk, rawPath).CombinedOutput(); err != nil {
		return fmt.Errorf("resize shared base file: %s", strings.TrimSpace(string(out)))
	}
	e2fsck := findTool("e2fsck", "/sbin/e2fsck")
	if out, err := exec.Command(e2fsck, "-f", "-y", rawPath).CombinedOutput(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() > 1 {
			return fmt.Errorf("check shared base filesystem: %s", strings.TrimSpace(string(out)))
		}
	}
	resize2fs := findTool("resize2fs", "/sbin/resize2fs")
	if out, err := exec.Command(resize2fs, rawPath).CombinedOutput(); err != nil {
		return fmt.Errorf("resize shared base filesystem: %s", strings.TrimSpace(string(out)))
	}
	return convertRawToQcow2(rawPath, outputPath)
}

// convertRawToQcow2 converts a raw disk image to qcow2 format.
// Runs e2fsck first to replay any dirty journal entries.
func convertRawToQcow2(rawPath, qcow2Path string) error {
	logDebug("converting raw image to qcow2", "raw", rawPath, "qcow2", qcow2Path)
	e2fsck := findTool("e2fsck", "/sbin/e2fsck")
	if out, err := exec.Command(e2fsck, "-f", "-y", rawPath).CombinedOutput(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() > 1 {
			return fmt.Errorf("e2fsck before convert: %s", strings.TrimSpace(string(out)))
		}
	}
	qemuImg := findTool("qemu-img", "/usr/bin/qemu-img")
	out, err := exec.Command(qemuImg, "convert", "-f", "raw", "-O", "qcow2", rawPath, qcow2Path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("qemu-img convert: %s", strings.TrimSpace(string(out)))
	}
	logDebug("raw image converted to qcow2", "qcow2", qcow2Path)
	return nil
}

// createQcow2Overlay creates a qcow2 overlay backed by an existing qcow2 image.
// The overlay is instant to create and only stores the delta.
func createQcow2Overlay(backingPath, overlayPath string) error {
	logDebug("creating qcow2 overlay", "backing", backingPath, "overlay", overlayPath)
	abs, err := filepath.Abs(backingPath)
	if err != nil {
		return fmt.Errorf("resolve backing path: %w", err)
	}
	qemuImg := findTool("qemu-img", "/usr/bin/qemu-img")
	out, err := exec.Command(qemuImg, "create", "-f", "qcow2", "-b", abs, "-F", "qcow2", overlayPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("qemu-img create overlay: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func decompressZstd(compressed []byte, outPath string) error {
	reader, err := zstd.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return fmt.Errorf("init zstd reader: %w", err)
	}
	defer reader.Close()

	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, reader); err != nil {
		_ = out.Close()
		return fmt.Errorf("decompress: %w", err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close decompressed image: %w", err)
	}
	return nil
}

// removeGlob removes all files matching a glob pattern.
func removeGlob(pattern string) error {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return err
	}
	for _, m := range matches {
		if err := os.Remove(m); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// findTool looks up a command in PATH, falling back to a known absolute path.
func findTool(name, fallback string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return fallback
}

func ensureKernel(noCache bool) (string, error) {
	return ensureKernelWithWriter(noCache, os.Stdout)
}

func ensureKernelQuiet(noCache bool) (string, error) {
	return ensureKernelWithWriter(noCache, io.Discard)
}

func ensureKernelWithWriter(noCache bool, out io.Writer) (string, error) {
	ver := embeddedVersion(embeddedKernel, "zaigr-")
	path := filepath.Join(zaigDir(), fmt.Sprintf("bzImage-%s", ver))

	if !noCache {
		if _, err := os.Stat(path); err == nil {
			logDebug("using cached kernel", "path", path)
			if _, err := fmt.Fprintf(out, ":: Kernel cached at %s\n", path); err != nil {
				return "", fmt.Errorf("print cached kernel path: %w", err)
			}
			return path, nil
		}
	}

	if err := os.MkdirAll(zaigDir(), 0755); err != nil {
		return "", err
	}
	if err := removeGlob(filepath.Join(zaigDir(), "bzImage-*")); err != nil {
		return "", fmt.Errorf("remove stale cached kernels: %w", err)
	}
	if _, err := fmt.Fprintf(out, ":: Extracting kernel to %s ...\n", path); err != nil {
		return "", fmt.Errorf("print kernel extraction path: %w", err)
	}
	logInfo("extracting embedded kernel", "path", path)
	if err := os.WriteFile(path, embeddedKernel, 0644); err != nil {
		return "", err
	}
	return path, nil
}

func ensureRootSSHKey() (privPath string, pubKey string, err error) {
	return ensureSSHKey(rootSSHKeyPath(), "zaigr-root")
}

func ensureUserSSHKey() (privPath string, pubKey string, err error) {
	return ensureSSHKey(userSSHKeyPath(), "zaigr-user")
}

func rootSSHKeyPath() string {
	return filepath.Join(zaigDir(), "root-ssh.key")
}

func userSSHKeyPath() string {
	return filepath.Join(zaigDir(), "user-ssh.key")
}

// ensureSSHKey generates an ed25519 keypair if one does not already exist.
func ensureSSHKey(privPath string, comment string) (string, string, error) {
	pubPath := privPath + ".pub"

	if err := os.MkdirAll(filepath.Dir(privPath), 0755); err != nil {
		return "", "", err
	}
	lock, err := os.OpenFile(privPath+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return "", "", fmt.Errorf("open SSH key lock: %w", err)
	}
	defer func() { _ = lock.Close() }()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return "", "", fmt.Errorf("lock SSH key generation: %w", err)
	}
	defer func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) }()

	if _, err := os.Stat(privPath); err == nil {
		logDebug("using existing SSH key", "path", privPath)
		pub, err := os.ReadFile(pubPath)
		if err != nil {
			return "", "", fmt.Errorf("read SSH public key: %w", err)
		}
		return privPath, strings.TrimSpace(string(pub)), nil
	}

	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-f", privPath, "-N", "", "-C", comment)
	logInfo("generating SSH key", "path", privPath, "comment", comment)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("ssh-keygen: %s", strings.TrimSpace(string(out)))
	}

	pub, err2 := os.ReadFile(pubPath)
	if err2 != nil {
		return "", "", fmt.Errorf("read generated SSH public key: %w", err2)
	}
	return privPath, strings.TrimSpace(string(pub)), nil
}
