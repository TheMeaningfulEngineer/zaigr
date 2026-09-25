package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func newProjectHostAccessCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "host-access", Short: "Share host ports and serial devices with this project",
		Long: "Manage persistent host-access grants, preserved across stop/start, clean, and rebuild.\n" +
			"Ports forward TCP over IPv4 from host 127.0.0.1 to the project. The project server\n" +
			"must listen on 0.0.0.0 or its network interface. Outbound permissions use project firewall.\n" +
			"Serial TTY devices appear at the same absolute path in the project, with exclusive\n" +
			"ownership retained while stopped. Up to two devices are supported via emulated UARTs.\n" +
			"New device grants on a running VM wait for restart; stop the VM before removing an\n" +
			"exposed device. This is serial access, not USB or arbitrary-device passthrough.",
		Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	var vmPort string
	allow := &cobra.Command{Use: "allow <host-port|absolute-device-path>", Short: "Persistently allow one host resource",
		Long:    "Allow one host resource. A numeric host port defaults to the same project port;\n--vm-port overrides the project port. TCP forwarding applies live on 127.0.0.1.\nDevice grants persist and become active on the next VM start; a running VM needs a restart.",
		Example: "  zaigr project host-access allow 8080\n  zaigr project host-access allow 8080 --vm-port 3000\n  zaigr project host-access allow /dev/ttyUSB0",
		Args:    cobra.ExactArgs(1), RunE: func(c *cobra.Command, args []string) error {
			return cmdHostAccessChange(args[0], vmPort, c.Flags().Changed("vm-port"), true)
		},
	}
	allow.Flags().StringVar(&vmPort, "vm-port", "", "Project TCP port (default: host port)")
	remove := &cobra.Command{Use: "remove <host-port|saved-device-path>", Short: "Remove one saved host-access grant",
		Long: "Remove a grant by its host port or saved device path, even after unplugging.\nStop the VM before removing an exposed device; pending grants can be removed immediately.\nPort removal prevents new connections. Existing connections may finish; stopping the VM terminates them.",
		Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error { return cmdHostAccessChange(args[0], "", false, false) },
		ValidArgsFunction: completeHostAccessResource,
	}
	cmd.AddCommand(allow, remove, &cobra.Command{Use: "show", Short: "Observe sharing and guest attachment without probing resources", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error { return cmdHostAccessShow() }})
	return cmd
}

func completeHostAccessResource(_ *cobra.Command, args []string, prefix string) ([]string, cobra.ShellCompDirective) {
	if len(args) != 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	g, err := currentProjectStore().hostAccess()
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}
	var resources []string
	for _, p := range g.Ports {
		s := strconv.Itoa(p.Host)
		if strings.HasPrefix(s, prefix) {
			resources = append(resources, s)
		}
	}
	for _, d := range g.Devices {
		if strings.HasPrefix(d.Path, prefix) {
			resources = append(resources, d.Path)
		}
	}
	return resources, cobra.ShellCompDirectiveNoFileComp
}

func requireHostAccessProject(store projectStore) error {
	initialized, err := isProjectInitialized(store.Path)
	if err != nil {
		return err
	}
	if !initialized {
		return fmt.Errorf("project host-access requires a project. Run 'zaigr shell' to initialize it")
	}
	return nil
}

func cmdHostAccessChange(resource, vmPort string, override, allow bool) error {
	store := currentProjectStore()
	lock, err := lockCurrentProject("project host-access")
	if err != nil {
		return err
	}
	defer lock.releaseWithWarning()
	if err := requireHostAccessProject(store); err != nil {
		return err
	}
	if err := lock.lockHostAccess(store, "project host-access"); err != nil {
		return err
	}
	if err := lock.recover(store, "project host-access"); err != nil {
		return err
	}
	g, err := store.hostAccess()
	if err != nil {
		return err
	}
	running, stale := detectRunningProjectVMInStore(store)
	if running == nil {
		if err := requireNoRunningProjectQemu(store, "project host-access"); err != nil {
			return err
		}
	}
	if stale {
		running = nil
	}
	if filepath.IsAbs(resource) {
		if override {
			return fmt.Errorf("--vm-port applies only to a numeric host port")
		}
		if !validHostDevicePath(resource) {
			return fmt.Errorf("invalid device path")
		}
		if err := lock.lockHostDeviceOwners(); err != nil {
			return err
		}
		return changeHostAccessDevice(store, g, running, resource, allow)
	}
	host, err := parseHostAccessPort(resource)
	if err != nil {
		return fmt.Errorf("%w; otherwise supply an absolute serial device path", err)
	}
	vm := host
	if override {
		vm, err = parseHostAccessPort(vmPort)
		if err != nil {
			return fmt.Errorf("--vm-port: %w", err)
		}
	}
	return changeHostAccessPort(store, g, running, hostAccessPort{Host: host, VM: vm}, allow)
}

func changeHostAccessPort(store projectStore, g hostAccessGrants, running *runningVMInfo, p hostAccessPort, allow bool) error {
	index := -1
	for i, saved := range g.Ports {
		if saved.Host == p.Host {
			index = i
			break
		}
	}
	if index >= 0 {
		if allow && g.Ports[index].VM != p.VM {
			return fmt.Errorf("host port %d is already mapped to project port %d; remove it first", p.Host, g.Ports[index].VM)
		}
		p = g.Ports[index]
	}
	if !allow && index < 0 {
		fmt.Printf(":: Host port %d is already absent\n", p.Host)
		return nil
	}
	if allow && index < 0 {
		g.Ports = append(g.Ports, p)
		if err := store.writeHostAccess(g); err != nil {
			return err
		}
	}
	if running != nil {
		q, err := openHostAccessQMP(store)
		if err == nil {
			defer func() { _ = q.conn.Close() }()
			err = q.applyPort(p, running.Port, !allow)
		}
		if err != nil {
			return fmt.Errorf("host port %d remains saved; runtime change failed: %w%s; retry or restart the VM", p.Host, err, hostPortOwnerHint(store, p.Host))
		}
	}
	if !allow {
		g.Ports = append(g.Ports[:index], g.Ports[index+1:]...)
		if err := store.writeHostAccess(g); err != nil {
			return fmt.Errorf("runtime forward removed, but the grant remains saved and may return on restart: %w", err)
		}
		fmt.Printf(":: Removed host port %d\n", p.Host)
		return nil
	}
	verb := "Allowed"
	if index >= 0 {
		verb = "Already allowed"
	}
	state := "active on the running VM"
	if running == nil {
		state = "saved for the next VM start"
	}
	fmt.Printf(":: %s localhost:%d → project port %d; %s\n", verb, p.Host, p.VM, state)
	return nil
}

func changeHostAccessDevice(store projectStore, g hostAccessGrants, running *runningVMInfo, path string, allow bool) error {
	index := -1
	for i, d := range g.Devices {
		if d.Path == path {
			index = i
			break
		}
	}
	if !allow && index < 0 {
		fmt.Printf(":: Device %s is already absent\n", path)
		return nil
	}
	if !allow {
		if running != nil {
			r, err := store.readHostAccessRuntime()
			if err != nil {
				return fmt.Errorf("cannot confirm device is pending: %w; stop the VM before removal", err)
			}
			q, err := openHostAccessQMP(store)
			if err == nil {
				defer func() { _ = q.conn.Close() }()
				err = verifyHostAccessRuntime(q, r, g)
			}
			if err != nil {
				return fmt.Errorf("cannot confirm device is pending: %w; stop the VM before removal", err)
			}
			for _, d := range r.Devices {
				if d.Path == path {
					return fmt.Errorf("device %s belongs to this VM runtime; stop it with 'zaigr project vm stop' before removal", path)
				}
			}
		}
		g.Devices = append(g.Devices[:index], g.Devices[index+1:]...)
		if err := store.writeHostAccess(g); err != nil {
			return err
		}
		fmt.Printf(":: Removed device %s and released its reservation\n", path)
		return nil
	}
	if index >= 0 {
		fmt.Printf(":: Device %s is already allowed; saved reservation retained\n", path)
		return nil
	}
	if len(g.Devices) >= hostAccessDeviceLimit {
		return fmt.Errorf("this version supports up to two serial devices per project; remove a grant first")
	}
	// Check identity and ownership before opening: a losing request must not
	// disturb an already-owned serial device merely to validate it.
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	identity, err := hostIdentity(info)
	if err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	candidate := hostAccessDevice{Path: path, Resolved: resolved, Identity: identity, Transport: "isa-uart"}
	for _, d := range g.Devices {
		if d.Identity.Rdev == identity.Rdev || (identity.Stable != "" && d.Identity.Stable == identity.Stable) {
			return fmt.Errorf("this device is already allowed as %s; remove it before changing its path", d.Path)
		}
	}
	if err := requireHostDeviceOwner(store, candidate); err != nil {
		return err
	}
	d, f, err := openHostAccessDevice(store, path, &identity)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if err := requireHostDeviceOwner(store, d); err != nil {
		return err
	}
	g.Devices = append(g.Devices, d)
	if err := store.writeHostAccess(g); err != nil {
		return err
	}
	state := "saved for the next VM start"
	if running != nil {
		state = "Waiting for VM restart"
	}
	fmt.Printf(":: Allowed device %s; %s\n", path, state)
	return nil
}

type hostAccessRow struct{ status, reason string }

func cmdHostAccessShow() error {
	store := currentProjectStore()
	if err := requireHostAccessProject(store); err != nil {
		return err
	}
	g, err := store.hostAccess()
	if err != nil {
		return err
	}
	sort.Slice(g.Ports, func(i, j int) bool { return g.Ports[i].Host < g.Ports[j].Host })
	sort.Slice(g.Devices, func(i, j int) bool { return g.Devices[i].Path < g.Devices[j].Path })
	ports, devices, inspectErr := inspectHostAccess(store, g)
	name := filepath.Base(canonicalPath("."))
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 4, ' ', 0)
	_, _ = fmt.Fprintf(w, "Zaigr project “%s” ports exposed to host\n  HOST ADDRESS\tPROJECT PORT\tSTATUS\n", name)
	if len(g.Ports) == 0 {
		_, _ = fmt.Fprintln(w, "  (none)")
	}
	for _, p := range g.Ports {
		row := ports[p.Host]
		_, _ = fmt.Fprintf(w, "  %s\t%d\t%s%s\n", hostAccessPortString(p), p.VM, row.status, hostAccessReason(row.reason))
	}
	_, _ = fmt.Fprintf(w, "\nHost devices shared with zaigr project “%s”\n  DEVICE\tSTATUS\n", name)
	if len(g.Devices) == 0 {
		_, _ = fmt.Fprintln(w, "  (none)")
	}
	for _, d := range g.Devices {
		row := devices[d.Path]
		_, _ = fmt.Fprintf(w, "  %s\t%s%s\n", d.Path, row.status, hostAccessReason(row.reason))
	}
	_, _ = fmt.Fprintln(w, "\nStatus\n  Available\tSharing is active; no process inside the project is attached.\n  Attached\tA process inside the project is listening on the port or has opened the device.\n  Waiting for VM restart\tSharing will become active on the next VM start.\n  VM stopped\tSaved; sharing is inactive until the VM starts.\n  Unavailable\tSharing could not be activated or the device was lost.\n  Unknown\tIts current state could not be determined.")
	if err := w.Flush(); err != nil {
		return err
	}
	return inspectErr
}

func hostAccessReason(reason string) string {
	if reason == "" {
		return ""
	}
	return " — " + strings.Join(strings.Fields(reason), " ")
}

func inspectHostAccess(store projectStore, g hostAccessGrants) (map[int]hostAccessRow, map[string]hostAccessRow, error) {
	ports, devices := map[int]hostAccessRow{}, map[string]hostAccessRow{}
	for _, p := range g.Ports {
		ports[p.Host] = hostAccessRow{status: "VM stopped"}
	}
	for _, d := range g.Devices {
		devices[d.Path] = hostAccessRow{status: "VM stopped"}
	}
	unknown := func(err error) (map[int]hostAccessRow, map[string]hostAccessRow, error) {
		for _, p := range g.Ports {
			ports[p.Host] = hostAccessRow{"Unknown", err.Error()}
		}
		for _, d := range g.Devices {
			devices[d.Path] = hostAccessRow{"Unknown", err.Error()}
		}
		return ports, devices, err
	}
	running, _ := detectRunningProjectVMInStore(store)
	if running == nil {
		if err := requireNoRunningProjectQemu(store, "host-access inspection"); err != nil {
			return unknown(err)
		}
		return ports, devices, nil
	}
	q, err := openHostAccessQMP(store)
	if err != nil {
		return unknown(err)
	}
	defer func() { _ = q.conn.Close() }()
	forwards, err := q.forwards()
	if err != nil {
		return unknown(err)
	}
	runtime := hostAccessRuntime{}
	if len(g.Devices) > 0 {
		runtime, err = store.readHostAccessRuntime()
		if err == nil {
			err = verifyHostAccessRuntime(q, runtime, g)
		}
		if err != nil {
			return unknown(err)
		}
	}
	args := []string{"observe"}
	for _, p := range g.Ports {
		if forwards[p.Host] != p.VM || strconv.Itoa(p.Host) == running.Port {
			ports[p.Host] = hostAccessRow{"Unavailable", "forward is inactive; retry allow or restart"}
			continue
		}
		ports[p.Host] = hostAccessRow{status: "Available"}
		args = append(args, "port", strconv.Itoa(p.VM))
	}
	deviceTargets := map[string]string{}
	for _, d := range g.Devices {
		devices[d.Path] = hostAccessRow{status: "Waiting for VM restart"}
		for _, live := range runtime.Devices {
			if live.Path != d.Path {
				continue
			}
			if !live.Active {
				devices[d.Path] = hostAccessRow{"Unavailable", live.Error}
				break
			}
			info, err := os.Stat(d.Path)
			var identity hostDeviceIdentity
			if err == nil {
				identity, err = hostIdentity(info)
			}
			if err == nil && !sameHostDevice(d.Identity, identity) {
				err = fmt.Errorf("device identity changed; remove and allow the replacement")
			}
			if err == nil && !sameHostDeviceNode(*live.Identity, identity) {
				err = fmt.Errorf("device endpoint changed since activation; restart the VM to reconnect")
			}
			if err != nil {
				devices[d.Path] = hostAccessRow{"Unavailable", err.Error()}
				break
			}
			active, err := hostAccessDeviceBackendActive(q, live.Backend)
			if err != nil {
				return unknown(err)
			}
			if !active {
				devices[d.Path] = hostAccessRow{"Unavailable", "serial backend is inactive; restart the VM"}
				break
			}
			devices[d.Path] = hostAccessRow{status: "Available"}
			deviceTargets[live.Target] = d.Path
			args = append(args, "device", d.Path, live.Target)
			break
		}
	}
	if len(args) == 1 {
		return ports, devices, nil
	}
	out, err := hostAccessGuestCommand(running.Port, args...)
	observed := map[string]string{}
	if err == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(lines) == 0 || lines[0] != "host-access-v1" {
			err = fmt.Errorf("incompatible guest host-access observer; rebuild the project")
		} else {
			for _, line := range lines[1:] {
				f := strings.Split(line, "\t")
				if len(f) != 3 {
					err = fmt.Errorf("malformed guest host-access observation")
					break
				}
				observed[f[0]+":"+f[1]] = f[2]
			}
		}
	}
	rowFromObservation := func(key string) hostAccessRow {
		if err != nil {
			return hostAccessRow{"Unknown", err.Error()}
		}
		switch observed[key] {
		case "attached":
			return hostAccessRow{status: "Attached"}
		case "available":
			return hostAccessRow{status: "Available"}
		case "loopback":
			return hostAccessRow{"Available", "listener is on guest loopback; bind to 0.0.0.0 or the project interface"}
		case "unavailable":
			return hostAccessRow{"Unavailable", "guest device path is missing or changed"}
		default:
			err = fmt.Errorf("guest observer omitted %s", key)
			return hostAccessRow{"Unknown", err.Error()}
		}
	}
	for _, p := range g.Ports {
		if ports[p.Host].status == "Available" {
			ports[p.Host] = rowFromObservation("port:" + strconv.Itoa(p.VM))
		}
	}
	for target, path := range deviceTargets {
		devices[path] = rowFromObservation("device:" + target)
	}
	return ports, devices, err
}
