package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const directSetupStagingPrefix = ".setup-run-"

type heldProjectLock struct {
	file *os.File
}

type projectMutationLock struct {
	held []heldProjectLock
}

func projectLocksDir() (string, error) {
	lockDir := filepath.Join(zaigDir(), "project-locks")
	if err := os.MkdirAll(lockDir, 0755); err != nil {
		return "", fmt.Errorf("create project lock directory: %w", err)
	}
	return lockDir, nil
}

func projectLockHash(store projectStore) string {
	if store.Hash != "" {
		return store.Hash
	}
	return filepath.Base(store.Path)
}

func acquireProjectFileLock(store projectStore, suffix string, operation string, exclusive bool) (heldProjectLock, error) {
	lockDir, err := projectLocksDir()
	if err != nil {
		return heldProjectLock{}, err
	}
	hash := projectLockHash(store)
	lockPath := filepath.Join(lockDir, hash+suffix+".lock")
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return heldProjectLock{}, fmt.Errorf("open project operation lock: %w", err)
	}
	mode := syscall.LOCK_SH | syscall.LOCK_NB
	if exclusive {
		mode = syscall.LOCK_EX | syscall.LOCK_NB
	}
	if err := syscall.Flock(int(file.Fd()), mode); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			active := projectFileLockHolder(file)
			_ = file.Close()
			if active == "" {
				active = "another project operation (lock owner details unavailable)"
			}
			return heldProjectLock{}, fmt.Errorf("cannot run %s: %s is running in another terminal", operation, active)
		}
		_ = file.Close()
		return heldProjectLock{}, fmt.Errorf("lock project for %s: %w", operation, err)
	}

	return heldProjectLock{file: file}, nil
}

func projectFileLockHolder(file *os.File) string {
	if file == nil {
		return ""
	}
	info, err := file.Stat()
	if err != nil {
		return ""
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	locks, err := os.ReadFile("/proc/locks")
	if err != nil {
		return ""
	}
	deviceMajor := linuxDeviceMajor(uint64(stat.Dev))
	deviceMinor := linuxDeviceMinor(uint64(stat.Dev))
	for _, line := range strings.Split(string(locks), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || fields[1] != "FLOCK" {
			continue
		}
		identity := strings.Split(fields[5], ":")
		if len(identity) != 3 {
			continue
		}
		major, majorErr := strconv.ParseUint(identity[0], 16, 32)
		minor, minorErr := strconv.ParseUint(identity[1], 16, 32)
		inode, inodeErr := strconv.ParseUint(identity[2], 10, 64)
		pid, pidErr := strconv.Atoi(fields[4])
		if majorErr != nil || minorErr != nil || inodeErr != nil || pidErr != nil {
			continue
		}
		if uint32(major) != deviceMajor || uint32(minor) != deviceMinor || inode != stat.Ino {
			continue
		}
		invocation := processInvocation(pid)
		if invocation == "" {
			return fmt.Sprintf("PID %d", pid)
		}
		return fmt.Sprintf("PID %d: %s", pid, invocation)
	}
	return ""
}

func linuxDeviceMajor(device uint64) uint32 {
	return uint32((device>>8)&0xfff | (device>>32)&0xfffff000)
}

func linuxDeviceMinor(device uint64) uint32 {
	return uint32(device&0xff | (device>>12)&0xffffff00)
}

func processInvocation(pid int) string {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return ""
	}
	arguments := strings.Fields(strings.ReplaceAll(string(data), "\x00", " "))
	return strings.Join(arguments, " ")
}

func acquireProjectOperationLock(store projectStore, operation string, exclusive bool, allowCapture bool) (*projectMutationLock, error) {
	if !allowCapture {
		if err := requireNoActiveSetupCaptureForStore(store, "zaigr "+operation); err != nil {
			return nil, err
		}
	}
	held, err := acquireProjectFileLock(store, "", operation, exclusive)
	if err != nil {
		return nil, err
	}
	lock := &projectMutationLock{held: []heldProjectLock{held}}
	if !allowCapture {
		if err := requireNoActiveSetupCaptureForStore(store, "zaigr "+operation); err != nil {
			_ = lock.release()
			return nil, err
		}
	}
	return lock, nil
}

// acquireProjectMutationLock is the shared project gate used by ordinary
// commands. Image replacement and VM transitions use the exclusive variant.
func acquireProjectMutationLock(store projectStore, operation string) (*projectMutationLock, error) {
	return acquireProjectOperationLock(store, operation, false, false)
}

func acquireExclusiveProjectMutationLock(store projectStore, operation string, allowCapture bool) (*projectMutationLock, error) {
	return acquireProjectOperationLock(store, operation, true, allowCapture)
}

func acquireProjectWorkflowLock(store projectStore, operation string) (heldProjectLock, error) {
	return acquireProjectFileLock(store, ".setup-capture", operation, true)
}

func lockCurrentProject(operation string) (*projectMutationLock, error) {
	return acquireProjectMutationLock(currentProjectStore(), operation)
}

func lockCurrentProjectAllowCapture(operation string) (*projectMutationLock, error) {
	return acquireProjectOperationLock(currentProjectStore(), operation, false, true)
}

func lockCurrentProjectExclusive(operation string) (*projectMutationLock, error) {
	return acquireExclusiveProjectMutationLock(currentProjectStore(), operation, false)
}

func (lock *projectMutationLock) lockFirewallIPMutation(store projectStore, operation string) error {
	held, err := acquireProjectFileLock(store, ".firewall-ips", operation, true)
	if err != nil {
		return err
	}
	lock.held = append(lock.held, held)
	return nil
}

func lockCurrentProjectSetup(operation string) (*projectMutationLock, error) {
	store := currentProjectStore()
	lock, err := acquireProjectOperationLock(store, operation, false, false)
	if err != nil {
		return nil, err
	}
	workflow, err := acquireProjectWorkflowLock(store, operation)
	if err != nil {
		_ = lock.release()
		return nil, err
	}
	lock.held = append(lock.held, workflow)
	// Capture can become active between acquiring the project gate and the
	// setup/capture lock. Recheck after the conflict lock is authoritative.
	if err := requireNoActiveSetupCaptureForStore(store, "zaigr "+operation); err != nil {
		_ = lock.release()
		return nil, err
	}
	return lock, nil
}

func lockCurrentProjectCapture(operation string) (*projectMutationLock, error) {
	store := currentProjectStore()
	lock, err := acquireProjectOperationLock(store, operation, false, true)
	if err != nil {
		return nil, err
	}
	workflow, err := acquireProjectWorkflowLock(store, operation)
	if err != nil {
		_ = lock.release()
		return nil, err
	}
	lock.held = append(lock.held, workflow)
	return lock, nil
}

func (lock *projectMutationLock) recover(store projectStore, operation string) error {
	if err := recoverLegacyCleanTransaction(store); err != nil {
		return fmt.Errorf("recover interrupted legacy clean before %s: %w", operation, err)
	}
	if err := recoverProjectReplacementTransaction(store); err != nil {
		return fmt.Errorf("recover interrupted project transaction before %s: %w", operation, err)
	}
	if err := recoverProjectMetadataTransaction(store); err != nil {
		return fmt.Errorf("recover interrupted project metadata transaction before %s: %w", operation, err)
	}
	if err := resolveInterruptedDirectSetup(store); err != nil {
		return fmt.Errorf("resolve interrupted direct setup before %s: %w", operation, err)
	}
	if err := recoverStaleDirectSetupStaging(store); err != nil {
		return fmt.Errorf("recover stale direct setup staging before %s: %w", operation, err)
	}
	if err := recoverStaleSetupCaptureOverlay(store); err != nil {
		return fmt.Errorf("recover stale setup capture before %s: %w", operation, err)
	}
	return nil
}

func recoverStaleDirectSetupStaging(store projectStore) error {
	entries, err := os.ReadDir(store.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read project store: %w", err)
	}

	storePath := filepath.Clean(store.Path)
	removed := false
	for _, entry := range entries {
		name := entry.Name()
		if !validDirectSetupStagingName(name) {
			continue
		}
		path := filepath.Join(storePath, name)
		if filepath.Dir(path) != storePath || filepath.Base(path) != name {
			continue
		}
		info, err := os.Lstat(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("inspect stale setup staging directory %s: %w", name, err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("remove stale setup staging directory %s: %w", name, err)
		}
		removed = true
	}
	if removed {
		return syncDirectory(storePath)
	}
	return nil
}

func validDirectSetupStagingName(name string) bool {
	suffix, ok := strings.CutPrefix(name, directSetupStagingPrefix)
	if !ok || suffix == "" || len(suffix) > 10 {
		return false
	}
	return strings.IndexFunc(suffix, func(r rune) bool { return r < '0' || r > '9' }) == -1
}

func recoverStaleSetupCaptureOverlay(store projectStore) error {
	_, active, err := store.readSetupCaptureMetadata()
	if err != nil || active {
		return err
	}
	overlayPath := store.setupCaptureOverlayPath()
	if err := os.Remove(overlayPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove unreferenced capture overlay: %w", err)
	}
	return nil
}

func (lock *projectMutationLock) release() error {
	if lock == nil {
		return nil
	}
	var firstErr error
	for index := len(lock.held) - 1; index >= 0; index-- {
		held := &lock.held[index]
		if held.file == nil {
			continue
		}
		if err := syscall.Flock(int(held.file.Fd()), syscall.LOCK_UN); err != nil && firstErr == nil {
			firstErr = err
		}
		if err := held.file.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		held.file = nil
	}
	lock.held = nil
	return firstErr
}

func (lock *projectMutationLock) releaseWithWarning() {
	if err := lock.release(); err != nil {
		logWarn("failed to release project operation lock", "error", err)
	}
}
