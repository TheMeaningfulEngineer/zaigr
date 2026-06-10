package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// buildImageFromBase decompresses the embedded base rootfs, resizes it, and
// converts it to qcow2 at outputPath. The caller is responsible for cleanup on error.
func buildImageFromBase(outputPath, disk string) error {
	logInfo("building image from embedded base rootfs", "output", outputPath, "disk", disk)
	// Decompress to a temporary raw file, resize, then convert to qcow2.
	rawPath := outputPath + ".raw-tmp"
	defer os.Remove(rawPath)

	if err := decompressZstd(embeddedRootfs, rawPath); err != nil {
		return fmt.Errorf("decompress rootfs: %w", err)
	}
	logDebug("embedded rootfs decompressed", "raw_path", rawPath)
	if out, err := exec.Command("truncate", "-s", disk, rawPath).CombinedOutput(); err != nil {
		return fmt.Errorf("truncate: %s", strings.TrimSpace(string(out)))
	}
	logDebug("raw image truncated", "raw_path", rawPath, "disk", disk)
	e2fsck := findTool("e2fsck", "/sbin/e2fsck")
	if out, err := exec.Command(e2fsck, "-f", "-y", rawPath).CombinedOutput(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() > 1 {
			return fmt.Errorf("e2fsck: %s", strings.TrimSpace(string(out)))
		}
	}
	resize2fs := findTool("resize2fs", "/sbin/resize2fs")
	if out, err := exec.Command(resize2fs, rawPath).CombinedOutput(); err != nil {
		return fmt.Errorf("resize2fs: %s", strings.TrimSpace(string(out)))
	}
	logDebug("rootfs resized", "raw_path", rawPath)
	return convertRawToQcow2(rawPath, outputPath)
}

// convertRawToQcow2 converts a raw disk image to qcow2 format.
// Runs e2fsck first to replay any dirty journal entries.
func convertRawToQcow2(rawPath, qcow2Path string) error {
	logDebug("converting raw image to qcow2", "raw", rawPath, "qcow2", qcow2Path)
	e2fsck := findTool("e2fsck", "/sbin/e2fsck")
	if out, err := exec.Command(e2fsck, "-f", "-y", rawPath).CombinedOutput(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() > 1 {
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

// flattenQcow2 creates a standalone qcow2 from an overlay chain.
func flattenQcow2(srcPath, dstPath string) error {
	logDebug("flattening qcow2 image", "src", srcPath, "dst", dstPath)
	qemuImg := findTool("qemu-img", "/usr/bin/qemu-img")
	out, err := exec.Command(qemuImg, "convert", "-f", "qcow2", "-O", "qcow2", srcPath, dstPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("qemu-img convert: %s", strings.TrimSpace(string(out)))
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
	defer out.Close()

	if _, err := io.Copy(out, reader); err != nil {
		return fmt.Errorf("decompress: %w", err)
	}
	return nil
}

// removeGlob removes all files matching a glob pattern.
func removeGlob(pattern string) {
	matches, _ := filepath.Glob(pattern)
	for _, m := range matches {
		os.Remove(m)
	}
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
			fmt.Fprintf(out, ":: Kernel cached at %s\n", path)
			return path, nil
		}
	}

	if err := os.MkdirAll(zaigDir(), 0755); err != nil {
		return "", err
	}
	removeGlob(filepath.Join(zaigDir(), "bzImage-*"))
	fmt.Fprintf(out, ":: Extracting kernel to %s ...\n", path)
	logInfo("extracting embedded kernel", "path", path)
	if err := os.WriteFile(path, embeddedKernel, 0644); err != nil {
		return "", err
	}
	return path, nil
}

// ensureRootSSHKey generates an ed25519 keypair for root SSH access if one
// doesn't already exist. Returns the private key path and the public key content.
func ensureRootSSHKey() (privPath string, pubKey string, err error) {
	privPath = filepath.Join(zaigDir(), "root-ssh.key")
	pubPath := privPath + ".pub"

	if _, err := os.Stat(privPath); err == nil {
		logDebug("using existing root SSH key", "path", privPath)
		pub, err := os.ReadFile(pubPath)
		if err != nil {
			return "", "", fmt.Errorf("read root SSH pubkey: %w", err)
		}
		return privPath, strings.TrimSpace(string(pub)), nil
	}

	if err := os.MkdirAll(zaigDir(), 0755); err != nil {
		return "", "", err
	}

	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-f", privPath, "-N", "", "-C", "zaigr-root")
	logInfo("generating root SSH key", "path", privPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("ssh-keygen: %s", strings.TrimSpace(string(out)))
	}

	pub, err2 := os.ReadFile(pubPath)
	if err2 != nil {
		return "", "", fmt.Errorf("read generated pubkey: %w", err2)
	}
	return privPath, strings.TrimSpace(string(pub)), nil
}

func ensureBaseRootfs(noCache bool) (string, error) {
	ver := baseRootfsVersion()
	path := filepath.Join(zaigDir(), fmt.Sprintf("base-rootfs-%s.img", ver))

	if !noCache {
		if _, err := os.Stat(path); err == nil {
			logDebug("using cached base rootfs", "path", path)
			fmt.Printf(":: Base rootfs cached at %s\n", path)
			return path, nil
		}
	}

	if err := os.MkdirAll(zaigDir(), 0755); err != nil {
		return "", err
	}
	removeGlob(filepath.Join(zaigDir(), "base-rootfs-*.img"))
	fmt.Printf(":: Decompressing base image to %s ...\n", path)
	logInfo("decompressing embedded base rootfs", "path", path)
	if err := decompressZstd(embeddedRootfs, path); err != nil {
		return "", err
	}
	return path, nil
}
