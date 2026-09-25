package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const hostAccessVersion = 1
const hostAccessDeviceLimit = 2

type hostAccessPort struct {
	Host int `json:"host"`
	VM   int `json:"vm"`
}

type hostDeviceIdentity struct {
	Device  uint64           `json:"device"`
	Inode   uint64           `json:"inode"`
	Rdev    uint64           `json:"rdev"`
	Created syscall.Timespec `json:"changed"`
	Stable  string           `json:"stable,omitempty"`
}

type hostAccessDevice struct {
	Path      string             `json:"path"`
	Resolved  string             `json:"resolved"`
	Identity  hostDeviceIdentity `json:"identity"`
	Transport string             `json:"transport"`
}

type hostAccessGrants struct {
	Version int                `json:"version"`
	Ports   []hostAccessPort   `json:"ports"`
	Devices []hostAccessDevice `json:"devices"`
}

func (store projectStore) hostAccessPath() string {
	return filepath.Join(store.Path, "host-access.json")
}

func decodeHostAccess(data []byte, value any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("unexpected trailing data")
	}
	return nil
}

func (store projectStore) hostAccess() (hostAccessGrants, error) {
	g := hostAccessGrants{Version: hostAccessVersion, Ports: []hostAccessPort{}, Devices: []hostAccessDevice{}}
	data, err := os.ReadFile(store.hostAccessPath())
	if os.IsNotExist(err) {
		return g, nil
	}
	g = hostAccessGrants{}
	if err == nil {
		err = decodeHostAccess(data, &g)
	}
	if err == nil {
		err = g.validate()
	}
	if err != nil {
		return g, fmt.Errorf("read host-access grants for project %s: %w", store.Hash, err)
	}
	return g, nil
}

func (g hostAccessGrants) validate() error {
	if g.Version != hostAccessVersion || g.Ports == nil || g.Devices == nil {
		return fmt.Errorf("unsupported or incomplete host-access metadata (version %d)", g.Version)
	}
	seen := map[int]bool{}
	for _, p := range g.Ports {
		if p.Host < 1 || p.Host > 65535 || p.VM < 1 || p.VM > 65535 || seen[p.Host] {
			return fmt.Errorf("invalid or duplicate port mapping")
		}
		seen[p.Host] = true
	}
	paths := map[string]bool{}
	if len(g.Devices) > hostAccessDeviceLimit {
		return fmt.Errorf("too many saved serial devices")
	}
	for _, d := range g.Devices {
		if !validHostDevicePath(d.Path) || !validHostDevicePath(d.Resolved) || paths[d.Path] || d.Identity.Rdev == 0 || d.Identity.Inode == 0 || d.Transport != "isa-uart" {
			return fmt.Errorf("invalid or duplicate device record")
		}
		paths[d.Path] = true
	}
	return nil
}

func (store projectStore) writeHostAccess(g hostAccessGrants) error {
	if err := g.validate(); err != nil {
		return err
	}
	sort.Slice(g.Ports, func(i, j int) bool { return g.Ports[i].Host < g.Ports[j].Host })
	sort.Slice(g.Devices, func(i, j int) bool { return g.Devices[i].Path < g.Devices[j].Path })
	data, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomically(store.hostAccessPath(), append(data, '\n'), 0600)
}

func parseHostAccessPort(raw string) (int, error) {
	if raw == "" || strings.IndexFunc(raw, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return 0, fmt.Errorf("port must be a decimal integer in 1–65535")
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("port must be a decimal integer in 1–65535")
	}
	return n, nil
}

func validHostDevicePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/" && !strings.ContainsAny(path, "\x00\r\n\t")
}

func hostDeviceStableIdentity(rdev uint64) string {
	path, err := filepath.EvalSymlinks(fmt.Sprintf("/sys/dev/char/%d:%d/device", linuxDeviceMajor(rdev), linuxDeviceMinor(rdev)))
	if err != nil {
		return ""
	}
	var usbInterface, usbPort string
	for strings.HasPrefix(path, "/sys/devices/") {
		if value, err := os.ReadFile(filepath.Join(path, "bInterfaceNumber")); err == nil {
			usbInterface = strings.TrimSpace(string(value))
		}
		if value, err := os.ReadFile(filepath.Join(path, "port_number")); err == nil {
			usbPort = strings.TrimSpace(string(value))
		}
		serial, serialErr := os.ReadFile(filepath.Join(path, "serial"))
		vendor, vendorErr := os.ReadFile(filepath.Join(path, "idVendor"))
		product, productErr := os.ReadFile(filepath.Join(path, "idProduct"))
		if serialErr == nil && vendorErr == nil && productErr == nil && strings.TrimSpace(string(serial)) != "" && usbInterface != "" {
			return strings.TrimSpace(string(vendor)) + ":" + strings.TrimSpace(string(product)) + ":" + strings.TrimSpace(string(serial)) + ":interface=" + usbInterface + ":port=" + usbPort
		}
		path = filepath.Dir(path)
	}
	return ""
}

func hostIdentity(info os.FileInfo) (hostDeviceIdentity, error) {
	if info.Mode()&os.ModeCharDevice == 0 {
		return hostDeviceIdentity{}, fmt.Errorf("not a supported serial character device")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return hostDeviceIdentity{}, fmt.Errorf("device identity unavailable")
	}
	major, minor := linuxDeviceMajor(stat.Rdev), linuxDeviceMinor(stat.Rdev)
	supported := major == 188 || major == 166 || (major == 4 && minor >= 64) || (major >= 136 && major <= 143)
	if !supported {
		return hostDeviceIdentity{}, fmt.Errorf("unsupported device; use a serial TTY (ttyUSB, ttyACM, ttyS, or PTY)")
	}
	return hostDeviceIdentity{Device: uint64(stat.Dev), Inode: stat.Ino, Rdev: stat.Rdev, Created: stat.Ctim, Stable: hostDeviceStableIdentity(stat.Rdev)}, nil
}

func sameHostDevice(a, b hostDeviceIdentity) bool {
	if a.Stable != "" {
		return a.Stable == b.Stable
	}
	return sameHostDeviceNode(a, b)
}

func sameHostDeviceNode(a, b hostDeviceIdentity) bool {
	return a.Device == b.Device && a.Inode == b.Inode && a.Rdev == b.Rdev && a.Created == b.Created
}

// Retain and validate the opened file before QEMU reopens this exact inode via
// /proc/<our-pid>/fd/<fd>. Never reopen the user-controlled symlink in QEMU.
func openHostAccessDevice(store projectStore, path string, expected *hostDeviceIdentity) (hostAccessDevice, *os.File, error) {
	d := hostAccessDevice{Path: path, Transport: "isa-uart"}
	if !validHostDevicePath(path) {
		return d, nil, fmt.Errorf("device must be an absolute, clean path without control characters")
	}
	// O_PATH pins the inode without opening the serial endpoint. Check this
	// pinned identity and its owner before the first open that can affect hardware.
	const oPath = 0x200000
	pinned, err := os.OpenFile(path, oPath, 0)
	if err != nil {
		return d, nil, err
	}
	defer func() { _ = pinned.Close() }()
	pinnedPath := fmt.Sprintf("/proc/self/fd/%d", pinned.Fd())
	resolved, err := os.Readlink(pinnedPath)
	if err != nil {
		return d, nil, err
	}
	before, err := pinned.Stat()
	if err != nil {
		return d, nil, err
	}
	identity, err := hostIdentity(before)
	if err != nil {
		return d, nil, err
	}
	if expected != nil && !sameHostDevice(*expected, identity) {
		return d, nil, fmt.Errorf("device identity changed; remove and allow it again to authorize the replacement")
	}
	d.Resolved, d.Identity = resolved, identity
	if err := requireHostDeviceOwner(store, d); err != nil {
		return d, nil, err
	}
	f, err := os.OpenFile(pinnedPath, os.O_RDWR|syscall.O_NOCTTY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return d, nil, err
	}
	fail := func(err error) (hostAccessDevice, *os.File, error) { _ = f.Close(); return d, nil, err }
	info, err := f.Stat()
	if err != nil {
		return fail(err)
	}
	opened, err := hostIdentity(info)
	if err != nil {
		return fail(err)
	}
	if !os.SameFile(before, info) || !sameHostDevice(identity, opened) {
		return fail(fmt.Errorf("device changed while opening; retry with a stable device path"))
	}
	var settings syscall.Termios
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), syscall.TCGETS, uintptr(unsafe.Pointer(&settings))); errno != 0 {
		return fail(fmt.Errorf("device does not support serial settings: %v", errno))
	}
	d.Resolved, d.Identity = resolved, opened
	return d, f, nil
}

func (lock *projectMutationLock) lockHostAccess(store projectStore, operation string) error {
	held, err := acquireProjectFileLock(store, ".host-access", operation, true)
	if err != nil {
		return err
	}
	lock.held = append(lock.held, held)
	return nil
}

func (lock *projectMutationLock) lockHostDeviceOwners() error {
	// One account-wide lock, after the project gate and host-access lock. Wait
	// briefly so competing claims can report the resulting owner, not a race.
	dir, err := projectLocksDir()
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, ".host-device-owners.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			lock.held = append(lock.held, heldProjectLock{file: f})
			return nil
		}
		if err != syscall.EWOULDBLOCK || time.Now().After(deadline) {
			_ = f.Close()
			return fmt.Errorf("host device ownership is busy: %w", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func hostAccessOwnerLabel(store projectStore) string {
	path, _, err := store.readProjectPath()
	if err != nil || path == "" {
		path = unknownProjectPathLabel
	}
	return fmt.Sprintf("%s (project %s)", path, store.Hash)
}

func requireHostDeviceOwner(store projectStore, device hostAccessDevice) error {
	entries, err := os.ReadDir(projectStoreRoot())
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		// A legacy-clean backup can be the sole authoritative store while its
		// replacement is being published. Conservatively retain those claims.
		hash := strings.TrimSuffix(entry.Name(), ".legacy-clean-transaction-old")
		if hash == store.Hash {
			continue
		}
		other := projectStore{Hash: hash, Path: filepath.Join(projectStoreRoot(), entry.Name())}
		grants, err := other.hostAccess()
		if err != nil {
			return fmt.Errorf("cannot verify device ownership: %w", err)
		}
		for _, claimed := range grants.Devices {
			if claimed.Path == device.Path || claimed.Resolved == device.Resolved || claimed.Identity.Rdev == device.Identity.Rdev || (claimed.Identity.Stable != "" && claimed.Identity.Stable == device.Identity.Stable) {
				return fmt.Errorf("device %s is reserved by %s; remove its grant there first", device.Path, hostAccessOwnerLabel(other))
			}
		}
	}
	return nil
}

func preserveHostAccessGrants(source, destination projectStore) error {
	g, err := source.hostAccess()
	if err != nil {
		return err
	}
	if _, err := os.Stat(source.hostAccessPath()); os.IsNotExist(err) {
		return nil
	}
	return destination.writeHostAccess(g)
}

// Delete the authoritative grants last. If removal of other store contents
// fails, the reservation remains visible to ownership scans.
func removeProjectStorePreservingHostClaims(path string) error {
	claimPath := filepath.Join(path, "host-access.json")
	claims, err := os.ReadFile(claimPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() != "host-access.json" {
			if err := os.RemoveAll(filepath.Join(path, entry.Name())); err != nil {
				return err
			}
		}
	}
	if err := os.Remove(claimPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Remove(path); err != nil {
		if claims != nil {
			return errors.Join(err, writeFileAtomically(claimPath, claims, 0600))
		}
		return err
	}
	return nil
}
