package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/sys/unix"
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
	digest := sha256.Sum256(embeddedKernel)
	path := filepath.Join(zaigDir(), fmt.Sprintf("bzImage-%s-%x", ver, digest))

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

func virtiofsdVersion() string { return strings.TrimSpace(embeddedVirtiofsdVersion) }

func ensureVirtiofsdWithWriter(noCache bool, out io.Writer) (string, error) {
	digest := sha256.Sum256(embeddedVirtiofsd)
	path := filepath.Join(zaigDir(), fmt.Sprintf("virtiofsd-%s-%x", virtiofsdVersion(), digest))
	if err := os.MkdirAll(zaigDir(), 0755); err != nil {
		return "", fmt.Errorf("create virtiofsd cache: %w", err)
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return "", fmt.Errorf("open virtiofsd extraction lock: %w", err)
	}
	defer func() { _ = lock.Close() }()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return "", fmt.Errorf("lock virtiofsd extraction: %w", err)
	}
	if !noCache {
		if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() && info.Mode().Perm() == 0755 {
			if cached, err := os.ReadFile(path); err == nil && sha256.Sum256(cached) == digest {
				_, _ = fmt.Fprintf(out, ":: Virtiofsd cached at %s\n", path)
				return path, nil
			}
		}
	}
	tmp, err := os.CreateTemp(zaigDir(), ".virtiofsd-*")
	if err != nil {
		return "", fmt.Errorf("create temporary virtiofsd: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err = tmp.Write(embeddedVirtiofsd); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("write virtiofsd: %w", err)
	}
	if err = tmp.Chmod(0755); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("chmod virtiofsd: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("sync virtiofsd: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return "", fmt.Errorf("close virtiofsd: %w", err)
	}
	if err = os.Rename(tmpPath, path); err != nil {
		return "", fmt.Errorf("publish virtiofsd: %w", err)
	}
	_, _ = fmt.Fprintf(out, ":: Virtiofsd extracted to %s\n", path)
	return path, nil
}

func ensureSlirp4netnsWithWriter(noCache bool, out io.Writer) (string, error) {
	digest := sha256.Sum256(embeddedSlirp4netns)
	version := strings.TrimSpace(embeddedSlirp4netnsVersion)
	if version == "" {
		return "", errors.New("embedded slirp4netns version is empty")
	}
	path := filepath.Join(zaigDir(), fmt.Sprintf("slirp4netns-%s-%x", version, digest))
	if err := os.MkdirAll(zaigDir(), 0755); err != nil {
		return "", fmt.Errorf("create slirp4netns cache: %w", err)
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return "", fmt.Errorf("open slirp4netns extraction lock: %w", err)
	}
	defer func() { _ = lock.Close() }()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return "", fmt.Errorf("lock slirp4netns extraction: %w", err)
	}
	if !noCache {
		if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() && info.Mode().Perm() == 0755 {
			if cached, err := os.ReadFile(path); err == nil && sha256.Sum256(cached) == digest {
				_, _ = fmt.Fprintf(out, ":: Slirp4netns cached at %s\n", path)
				return path, nil
			}
		}
	}
	tmp, err := os.CreateTemp(zaigDir(), ".slirp4netns-*")
	if err != nil {
		return "", fmt.Errorf("create temporary slirp4netns: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err = tmp.Write(embeddedSlirp4netns); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("write slirp4netns: %w", err)
	}
	if err = tmp.Chmod(0755); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("chmod slirp4netns: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("sync slirp4netns: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return "", fmt.Errorf("close slirp4netns: %w", err)
	}
	if err = os.Rename(tmpPath, path); err != nil {
		return "", fmt.Errorf("publish slirp4netns: %w", err)
	}
	_, _ = fmt.Fprintf(out, ":: Slirp4netns extracted to %s\n", path)
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
	directory := filepath.Dir(privPath)

	if filepath.Clean(privPath) != filepath.Join(filepath.Clean(zaigDir()), filepath.Base(privPath)) ||
		(filepath.Base(privPath) != filepath.Base(rootSSHKeyPath()) && filepath.Base(privPath) != filepath.Base(userSSHKeyPath())) {
		return "", "", errors.New("SSH private key path is outside the protected ~/.zaigr key locations")
	}
	if err := os.MkdirAll(directory, 0755); err != nil {
		return "", "", err
	}
	keyDirectory, err := openAndTightenSSHKeyDirectory(directory)
	if err != nil {
		return "", "", err
	}
	defer keyDirectory.Close()
	lock, err := openSSHKeyLock(keyDirectory, filepath.Base(privPath)+".lock")
	if err != nil {
		return "", "", fmt.Errorf("open SSH key lock: %w", err)
	}
	defer func() { _ = lock.Close() }()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return "", "", fmt.Errorf("lock SSH key generation: %w", err)
	}
	defer func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) }()
	if err := verifySSHKeyDirectoryIdentity(keyDirectory, directory); err != nil {
		return "", "", err
	}

	if _, err := os.Lstat(privPath); err == nil {
		if err := validateProtectedSSHPrivateKey(privPath); err != nil {
			return "", "", fmt.Errorf("validate existing SSH private key: %w", err)
		}
		logDebug("using existing SSH key", "path", privPath)
		pub, err := readSSHKeyPublic(keyDirectory, filepath.Base(pubPath))
		if err != nil {
			return "", "", fmt.Errorf("read SSH public key: %w", err)
		}
		if err := verifySSHKeyDirectoryIdentity(keyDirectory, directory); err != nil {
			return "", "", err
		}
		return privPath, pub, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", "", fmt.Errorf("inspect existing SSH private key: %w", err)
	}
	if _, err := os.Lstat(pubPath); err == nil {
		return "", "", fmt.Errorf("SSH public key %q exists without its private key; refusing to overwrite or follow it", pubPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", "", fmt.Errorf("inspect orphaned SSH public key %q: %w", pubPath, err)
	}

	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-f", privPath, "-N", "", "-C", comment)
	logInfo("generating SSH key", "path", privPath, "comment", comment)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("ssh-keygen: %s", strings.TrimSpace(string(out)))
	}

	if err := validateProtectedSSHPrivateKey(privPath); err != nil {
		return "", "", fmt.Errorf("validate generated SSH private key: %w", err)
	}
	pub, err2 := readSSHKeyPublic(keyDirectory, filepath.Base(pubPath))
	if err2 != nil {
		return "", "", fmt.Errorf("read generated SSH public key: %w", err2)
	}
	if err := verifySSHKeyDirectoryIdentity(keyDirectory, directory); err != nil {
		return "", "", err
	}
	return privPath, pub, nil
}

func sshKeyDirectoryOwnershipError(path string, foundUID, mode uint32) error {
	return fmt.Errorf(
		"protected SSH key directory %q is unsafe: found uid=%d mode=%04o; expected uid=%d with group/other write bits clear (mask 0022). Zaigr only removes those write bits automatically when the directory is already owned by the current user; inspect foreign ownership and directory contents before correcting it",
		path,
		foundUID,
		mode&07777,
		os.Getuid(),
	)
}

func openAndTightenSSHKeyDirectory(path string) (*os.File, error) {
	root := filepath.Clean(zaigDir())
	path = filepath.Clean(path)
	if path != root {
		return nil, fmt.Errorf("SSH key directory %q is not the protected directory %q", path, root)
	}
	canonical, err := canonicalPathWithMissingSuffix(root)
	if err != nil {
		return nil, fmt.Errorf("resolve protected SSH key directory %q: %w", root, err)
	}
	if canonical != root {
		return nil, fmt.Errorf("protected SSH key directory %q resolves to %q; symlinks and path aliases are not accepted", root, canonical)
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open protected SSH key directory %q without following symlinks: %w", root, err)
	}
	directory := os.NewFile(uintptr(fd), "zaigr-protected-ssh-key-directory")
	if err := verifySSHKeyDirectoryIdentity(directory, root); err != nil {
		_ = directory.Close()
		return nil, err
	}
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		_ = directory.Close()
		return nil, fmt.Errorf("inspect protected SSH key directory %q: %w", root, err)
	}
	if before.Mode&unix.S_IFMT != unix.S_IFDIR || before.Uid != uint32(os.Getuid()) {
		_ = directory.Close()
		return nil, sshKeyDirectoryOwnershipError(root, before.Uid, before.Mode)
	}
	if before.Mode&0022 != 0 {
		mode := before.Mode &^ uint32(0022)
		if err := unix.Fchmod(fd, mode); err != nil {
			_ = directory.Close()
			return nil, fmt.Errorf("tighten protected SSH key directory %q from mode %04o: %w", root, before.Mode&07777, err)
		}
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil {
		_ = directory.Close()
		return nil, fmt.Errorf("recheck protected SSH key directory %q: %w", root, err)
	}
	if before.Dev != after.Dev || before.Ino != after.Ino || before.Uid != after.Uid || after.Uid != uint32(os.Getuid()) || after.Mode&unix.S_IFMT != unix.S_IFDIR || after.Mode&0022 != 0 {
		_ = directory.Close()
		return nil, sshKeyDirectoryOwnershipError(root, after.Uid, after.Mode)
	}
	if err := verifySSHKeyDirectoryIdentity(directory, root); err != nil {
		_ = directory.Close()
		return nil, err
	}
	if before.Mode&0022 != 0 {
		fmt.Fprintf(os.Stderr, ":: Secured SSH key directory %s: mode %04o -> %04o (removed group/other write bits)\n", root, before.Mode&07777, after.Mode&07777)
	}
	return directory, nil
}

func verifySSHKeyDirectoryIdentity(directory *os.File, expectedPath string) error {
	if directory == nil {
		return errors.New("protected SSH key directory handle is missing")
	}
	fdPath := fmt.Sprintf("/proc/self/fd/%d", directory.Fd())
	resolved, err := filepath.EvalSymlinks(fdPath)
	if err != nil || filepath.Clean(resolved) != filepath.Clean(expectedPath) {
		return fmt.Errorf("protected SSH key directory %q changed identity while opening", expectedPath)
	}
	canonical, err := canonicalPathWithMissingSuffix(expectedPath)
	if err != nil || canonical != filepath.Clean(expectedPath) {
		return fmt.Errorf("protected SSH key directory %q is no longer canonical", expectedPath)
	}
	return nil
}

func openSSHKeyLock(directory *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, fmt.Errorf("open %s without following symlinks: %w", name, err)
	}
	lock := os.NewFile(uintptr(fd), name)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("inspect %s: %w", name, err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 || stat.Mode&0022 != 0 {
		_ = lock.Close()
		return nil, fmt.Errorf("SSH key lock %q must be a current-user-owned, single-link regular file without group/other write access (found uid %d, mode %04o)", name, stat.Uid, stat.Mode&07777)
	}
	return lock, nil
}

func readSSHKeyPublic(directory *os.File, name string) (string, error) {
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return "", err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 || stat.Mode&0022 != 0 {
		return "", fmt.Errorf("SSH public key %q must be a current-user-owned, single-link regular file without group/other write access (found uid %d, mode %04o)", name, stat.Uid, stat.Mode&07777)
	}
	data, err := io.ReadAll(io.LimitReader(file, 64*1024+1))
	if err != nil {
		return "", err
	}
	if len(data) > 64*1024 {
		return "", fmt.Errorf("SSH public key %q exceeds 64 KiB", name)
	}
	return strings.TrimSpace(string(data)), nil
}
