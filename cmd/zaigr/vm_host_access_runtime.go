package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const hostAccessGuestHelper = "/usr/local/lib/zaigr/host-access"

type hostAccessRuntimeDevice struct {
	Path          string              `json:"path"`
	Target        string              `json:"target"`
	Backend       string              `json:"backend"`
	Active        bool                `json:"active"`
	Error         string              `json:"error,omitempty"`
	Identity      *hostDeviceIdentity `json:"identity,omitempty"`
	GrantIdentity hostDeviceIdentity  `json:"grant_identity"`
}

type hostAccessRuntime struct {
	Version int                       `json:"version"`
	Devices []hostAccessRuntimeDevice `json:"devices"`
}

func (store projectStore) readHostAccessRuntime() (hostAccessRuntime, error) {
	r := hostAccessRuntime{}
	data, err := os.ReadFile(filepath.Join(store.runtimeDir(), "host-access.json"))
	if err == nil {
		err = decodeHostAccess(data, &r)
	}
	if err == nil && (r.Version != hostAccessVersion || r.Devices == nil) {
		err = fmt.Errorf("invalid host-access runtime metadata")
	}
	seen := map[string]bool{}
	for i, d := range r.Devices {
		if !validHostDevicePath(d.Path) || seen[d.Path] || i >= hostAccessDeviceLimit || d.GrantIdentity.Inode == 0 || d.GrantIdentity.Rdev == 0 ||
			d.Target != fmt.Sprintf("/dev/ttyS%d", i+1) || d.Backend != fmt.Sprintf("zaigr-host-uart%d", i+1) ||
			(d.Active && (d.Error != "" || d.Identity == nil || d.Identity.Inode == 0 || d.Identity.Rdev == 0)) || (!d.Active && d.Error == "") {
			err = fmt.Errorf("invalid host-access runtime device metadata")
		}
		seen[d.Path] = true
	}
	return r, err
}

func (store projectStore) writeHostAccessRuntime(r hostAccessRuntime) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return writeFileAtomically(filepath.Join(store.runtimeDir(), "host-access.json"), append(data, '\n'), 0600)
}

func hostAccessGuestCommand(port string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	quoted := []string{singleQuotedArg(hostAccessGuestHelper)}
	for _, arg := range args {
		quoted = append(quoted, singleQuotedArg(arg))
	}
	ssh := append(sshPresetOptions(), "-o", sshConnectTimeoutOption, "-o", "IdentitiesOnly=yes", "-i", rootSSHKeyPath(), "-p", port, "root@localhost", strings.Join(quoted, " "))
	cmd := exec.CommandContext(ctx, "ssh", ssh...)
	cmd.Env = presetSSHEnvironment()
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("guest host-access inspection timed out")
	}
	if err != nil {
		return nil, fmt.Errorf("guest host-access helper failed: %s (%w); rebuild an outdated project with 'zaigr project rebuild'", strings.TrimSpace(string(out)), err)
	}
	return out, nil
}

func hostAccessQEMUDevices(g hostAccessGrants) []string {
	var args []string
	for i := range g.Devices {
		id := fmt.Sprintf("zaigr-host-uart%d", i+1)
		args = append(args, "-chardev", "null,id="+id, "-device", fmt.Sprintf("isa-serial,index=%d,chardev=%s", i+1, id))
	}
	return args
}

// Called only by normal project startup, never by setup/image/rebuild VMs.
func activateHostAccess(store projectStore, port string, grants hostAccessGrants, lock *projectMutationLock) error {
	q, err := openHostAccessQMP(store)
	if err != nil {
		return err
	}
	defer func() { _ = q.conn.Close() }()
	for _, p := range grants.Ports {
		if err := q.applyPort(p, port, false); err != nil {
			fmt.Fprintf(os.Stderr, "warning: saved host port %d is Unavailable: %v%s\n", p.Host, err, hostPortOwnerHint(store, p.Host))
		}
	}
	r := hostAccessRuntime{Version: hostAccessVersion, Devices: []hostAccessRuntimeDevice{}}
	for i, d := range grants.Devices {
		r.Devices = append(r.Devices, hostAccessRuntimeDevice{Path: d.Path, GrantIdentity: d.Identity, Target: fmt.Sprintf("/dev/ttyS%d", i+1), Backend: fmt.Sprintf("zaigr-host-uart%d", i+1), Error: "activation was interrupted; restart the VM"})
	}
	// Record all boot-time devices before a backend can be opened. Pending grants
	// added later must never be mistaken for a partially activated boot device.
	if err := store.writeHostAccessRuntime(r); err != nil {
		return err
	}
	var ownershipErr error
	if len(grants.Devices) > 0 {
		ownershipErr = lock.lockHostDeviceOwners()
	}
	for i, d := range grants.Devices {
		err := ownershipErr
		if err == nil {
			err = activateHostAccessDevice(q, store, port, d, &r.Devices[i])
		}
		r.Devices[i].Active = err == nil
		r.Devices[i].Error = ""
		if err != nil {
			r.Devices[i].Error = err.Error()
			fmt.Fprintf(os.Stderr, "warning: saved device %s is Unavailable: %v\n", d.Path, err)
		}
		if err := store.writeHostAccessRuntime(r); err != nil {
			return err
		}
	}
	return nil
}

func activateHostAccessDevice(q *hostAccessQMP, store projectStore, port string, saved hostAccessDevice, runtime *hostAccessRuntimeDevice) error {
	d, f, err := openHostAccessDevice(store, saved.Path, &saved.Identity)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	runtime.Identity = &d.Identity
	// This path refers to our retained open file, not a mutable /dev symlink.
	backend := map[string]any{"type": "serial", "data": map[string]string{"device": fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), f.Fd())}}
	if _, err := q.command("chardev-change", map[string]any{"id": runtime.Backend, "backend": backend}); err != nil {
		return err
	}
	if _, err := hostAccessGuestCommand(port, "attach", saved.Path, runtime.Target); err != nil {
		_, detachErr := q.command("chardev-change", map[string]any{"id": runtime.Backend, "backend": map[string]any{"type": "null", "data": map[string]any{}}})
		if detachErr != nil {
			return fmt.Errorf("%w; backend could not be detached: %v; stop the VM before removal", err, detachErr)
		}
		return err
	}
	return nil
}

func hostPortOwnerHint(store projectStore, host int) string {
	stores, err := listProjectStores()
	if err != nil {
		return ""
	}
	for _, other := range stores {
		if other.Hash == store.Hash {
			continue
		}
		g, err := other.hostAccess()
		if err != nil {
			continue
		}
		for _, p := range g.Ports {
			if p.Host != host {
				continue
			}
			q, err := openHostAccessQMP(other)
			if err != nil {
				continue
			}
			active, err := q.forwards()
			_ = q.conn.Close()
			if err == nil && active[host] == p.VM {
				return "; owned by " + hostAccessOwnerLabel(other)
			}
		}
	}
	return ""
}

func hostAccessPortReserved(g hostAccessGrants, port int) bool {
	for _, p := range g.Ports {
		if p.Host == port {
			return true
		}
	}
	return false
}

func hostAccessDeviceBackendActive(q *hostAccessQMP, backend string) (bool, error) {
	data, err := q.command("query-chardev", nil)
	if err != nil {
		return false, err
	}
	var devices []struct {
		Label    string `json:"label"`
		Filename string `json:"filename"`
	}
	if err := json.Unmarshal(data, &devices); err != nil {
		return false, err
	}
	for _, d := range devices {
		if d.Label == backend {
			return d.Filename == "serial" || strings.HasPrefix(d.Filename, "serial:"), nil
		}
	}
	return false, nil
}

func verifyHostAccessRuntime(q *hostAccessQMP, r hostAccessRuntime, grants hostAccessGrants) error {
	data, err := q.command("query-chardev", nil)
	if err != nil {
		return err
	}
	var backends []struct {
		Label string `json:"label"`
	}
	if err := json.Unmarshal(data, &backends); err != nil {
		return err
	}
	actual := map[string]bool{}
	for _, b := range backends {
		if strings.HasPrefix(b.Label, "zaigr-host-uart") {
			actual[b.Label] = true
		}
	}
	if len(actual) != len(r.Devices) {
		return fmt.Errorf("host-access runtime metadata does not match QEMU; restart the VM")
	}
	for _, d := range r.Devices {
		if !actual[d.Backend] {
			return fmt.Errorf("host-access runtime device is missing from QEMU; restart the VM")
		}
		matched := false
		for _, grant := range grants.Devices {
			if grant.Path == d.Path && grant.Identity == d.GrantIdentity {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("host-access runtime device does not match its saved grant; stop the VM before changing grants")
		}
	}
	return nil
}

func hostAccessPortString(p hostAccessPort) string { return "localhost:" + strconv.Itoa(p.Host) }
