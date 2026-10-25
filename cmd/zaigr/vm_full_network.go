package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"zaigr/cmd/zaigr/hostnet"
)

const maintenanceNetworkWarning = "WARNING: --full-network gives this root shell and its child processes broad IPv4 TCP/UDP access, including private network destinations. Other VM processes stay on their ordinary network policy. Access ends when the host session expires or shell exits. Processes left behind keep access while another maintenance session remains active."

func maintenanceOperationWarning(operation string) string {
	switch operation {
	case "project setup run", "setup execution":
		return "WARNING: Setup execution runs root setup scripts with broad IPv4 TCP/UDP access in a shared maintenance network namespace. Other VM processes keep their ordinary network policy. Access ends when setup finishes or the last maintenance session expires; processes left behind keep access while another session remains active."
	case "project setup capture":
		return "WARNING: Setup capture runs its root shell with broad IPv4 TCP/UDP access in a shared maintenance network namespace. Other VM processes keep their ordinary network policy. Access ends when capture finishes or the last maintenance session expires; processes left behind keep access while another session remains active."
	default:
		return maintenanceNetworkWarning
	}
}

func withFullNetworkLeaseForRuntime(runtimeDir, launchID, operation, warning string, run func() error) error {
	leaseID, err := newVMLaunchID()
	if err != nil {
		return fmt.Errorf("create temporary full-network lease: %w", err)
	}
	fmt.Fprintln(os.Stderr, warning)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	ownerDeadline := time.Now().Add(fullNetworkOwnerTTL)
	_, err = hostNetworkControlWithLease(ctx, runtimeDir, launchID, "full-network-acquire", hostnet.Forward{}, leaseID, ownerDeadline)
	cancel()
	if err != nil {
		return fmt.Errorf("acquire temporary full-network lease: %w", err)
	}
	launchStoppedByWorkflow := false
	stopRenewal := make(chan struct{})
	renewalDone := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopRenewal:
				renewalDone <- nil
				return
			case <-ticker.C:
				renewCtx, renewCancel := context.WithTimeout(context.Background(), 4*time.Second)
				renewDeadline := time.Now().Add(fullNetworkOwnerTTL)
				_, renewErr := hostNetworkControlWithLease(renewCtx, runtimeDir, launchID, "full-network-renew", hostnet.Forward{}, leaseID, renewDeadline)
				renewCancel()
				if renewErr != nil {
					fmt.Fprintf(os.Stderr, "warning: temporary full-network lease renewal failed; host access will expire within %s: %v\n", fullNetworkOwnerTTL, renewErr)
					renewalDone <- renewErr
					return
				}
			}
		}
	}()
	runErr := run()
	close(stopRenewal)
	renewErr := <-renewalDone
	releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 5*time.Second)
	_, releaseErr := hostNetworkControlWithLease(releaseCtx, runtimeDir, launchID, "full-network-release", hostnet.Forward{}, leaseID, time.Time{})
	releaseCancel()
	if releaseErr != nil && waitFullNetworkLeaseLaunchStopped(runtimeDir, launchID, 12*time.Second) {
		// A capture accept can deliberately stop the VM whose interactive
		// capture shell owns this lease. In that case the namespace and its
		// firewall state are already gone, so the lease is revoked. Only treat
		// the missing control endpoint as success after proving this launch is
		// no longer represented by its supervisor record/runtime directory.
		releaseErr = nil
		launchStoppedByWorkflow = true
	}
	if releaseErr != nil {
		return fmt.Errorf("release temporary full-network lease: %w", releaseErr)
	}
	if runErr != nil {
		return runErr
	}
	if !launchStoppedByWorkflow && operation == "project setup capture" {
		launchStoppedByWorkflow = waitFullNetworkLeaseLaunchStopped(runtimeDir, launchID, 100*time.Millisecond)
	}
	if launchStoppedByWorkflow {
		// The only nil-returning capture callback for a stopped launch is the
		// capture shell's verified accept/discard path. Its supervisor teardown
		// also makes a concurrent renewal failure moot.
		return nil
	}
	if renewErr != nil {
		return fmt.Errorf("temporary full-network lease renewal failed; the host firewall expired the lease")
	}
	return nil
}

func waitFullNetworkLeaseLaunchStopped(runtimeDir, launchID string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if fullNetworkLeaseLaunchStopped(runtimeDir, launchID) {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func fullNetworkLeaseLaunchStopped(runtimeDir, launchID string) bool {
	if !filepath.IsAbs(runtimeDir) || launchID == "" {
		return false
	}
	store := projectStore{Path: filepath.Dir(filepath.Clean(runtimeDir)), Hash: filepath.Base(filepath.Dir(filepath.Clean(runtimeDir)))}
	if store.runtimeDir() != filepath.Clean(runtimeDir) {
		return false
	}
	record, err := readVMSupervisorRecord(store)
	if errors.Is(err, os.ErrNotExist) {
		_, statErr := os.Stat(runtimeDir)
		return errors.Is(statErr, os.ErrNotExist)
	}
	if err != nil {
		return false
	}
	// A different launch owns the canonical runtime path now. Launch IDs are
	// unique, and starting it requires the previous supervisor to have stopped.
	return record.LaunchID != launchID
}

// withMaintenanceNetworkSession grants access through the launch's shared
// maintenance namespace and the separately leased maintenance NIC. Ordinary
// guest interfaces and firewall grants are unchanged.
func withMaintenanceNetworkSession(store projectStore, endpoint vmControlEndpoint, operation string, run func(string) error) (retErr error) {
	if err := ensureMaintenanceNetworkProjectSafe(store); err != nil {
		return err
	}
	host, record, err := runningHostNetworkRecord(store)
	if err != nil {
		return err
	}
	if !host {
		return fmt.Errorf("%s requires a running VM with host-enforced networking; restart the project VM", operation)
	}
	sessionID, err := newVMLaunchID()
	if err != nil {
		return fmt.Errorf("create maintenance session identity: %w", err)
	}
	deadline := time.Now().Add(fullNetworkOwnerTTL)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	response, err := hostNetworkControlRequestWithReply(ctx, store.runtimeDir(), record.LaunchID, hostNetworkControlRequest{Operation: "maintenance-start", SessionID: sessionID}, deadline)
	cancel()
	if err != nil {
		return fmt.Errorf("start maintenance network session: %w", err)
	}
	if response.MaintenanceSession == nil {
		_ = stopMaintenanceControl(store.runtimeDir(), record.LaunchID, sessionID)
		return errors.New("host network returned no maintenance network details")
	}
	session := *response.MaintenanceSession
	name, err := maintenanceNamespaceName(record.LaunchID)
	if err != nil {
		_ = stopMaintenanceControl(store.runtimeDir(), record.LaunchID, sessionID)
		return err
	}
	stopRenewal := make(chan struct{})
	renewalDone := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopRenewal:
				renewalDone <- nil
				return
			case <-ticker.C:
				renewCtx, renewCancel := context.WithTimeout(context.Background(), 4*time.Second)
				_, renewErr := hostNetworkControlRequestWithReply(renewCtx, store.runtimeDir(), record.LaunchID, hostNetworkControlRequest{Operation: "maintenance-renew", SessionID: sessionID}, time.Now().Add(fullNetworkOwnerTTL))
				renewCancel()
				if renewErr != nil {
					fmt.Fprintf(os.Stderr, "warning: maintenance network renewal failed; network access expires within %s: %v\n", fullNetworkOwnerTTL, renewErr)
					renewalDone <- renewErr
					return
				}
			}
		}
	}()
	defer func() {
		close(stopRenewal)
		renewErr := <-renewalDone
		stoppedLaunch := operation == "project setup capture" && waitFullNetworkLeaseLaunchStopped(store.runtimeDir(), record.LaunchID, 100*time.Millisecond)
		if retErr == nil && renewErr != nil && !stoppedLaunch {
			retErr = errors.New("maintenance network session renewal failed; host firewall expired the session")
		}
		if stoppedLaunch {
			return
		}
		stopErr := stopMaintenanceControl(store.runtimeDir(), record.LaunchID, sessionID)
		if stopErr != nil && operation == "project setup capture" && waitFullNetworkLeaseLaunchStopped(store.runtimeDir(), record.LaunchID, 12*time.Second) {
			// Accept/discard can tear down the VM before its maintenance session
			// control request is served. Only that proven launch teardown makes
			// the missing endpoint equivalent to successful revocation.
			return
		}
		retErr = errors.Join(retErr, stopErr)
	}()
	if err := prepareMaintenanceNamespace(endpoint, name, record.LaunchID, session); err != nil {
		return fmt.Errorf("prepare shared maintenance namespace: %w", err)
	}
	fmt.Fprintln(os.Stderr, maintenanceOperationWarning(operation))
	retErr = run(name)
	return retErr
}

func withMaintenanceNetworkSessionForSetups(store projectStore, endpoint vmControlEndpoint, operation string, definitions []setupDefinition, run func(string) error) error {
	if names := rootEquivalentSetupNames(definitions); len(names) > 0 {
		return fmt.Errorf("cannot attach setup execution with maintenance network access while installing root-equivalent runtime setup(s): %s; use a clean dedicated image without these runtimes or exact host firewall grants", strings.Join(names, ", "))
	}
	return withMaintenanceNetworkSession(store, endpoint, operation, run)
}

func ensureMaintenanceNetworkProjectSafe(store projectStore) error {
	records, err := store.readAppliedSetups()
	if err != nil {
		return fmt.Errorf("cannot verify setup history before maintenance network access: %w", err)
	}
	if names := rootEquivalentAppliedSetupNames(records); len(names) > 0 {
		return fmt.Errorf("maintenance network access is unavailable because this project image contains root-equivalent runtime setup(s): %s; stopping their daemons or deleting setup metadata does not restore isolation. Use a clean project image without these runtimes or exact host firewall grants", strings.Join(names, ", "))
	}
	failed, err := store.hasSetupFailureMarker()
	if err != nil {
		return fmt.Errorf("cannot verify setup failure history before maintenance network access: %w", err)
	}
	if failed {
		return errors.New("maintenance network access is unavailable because a setup failed or was interrupted; it may have left partial image changes that are absent from setup records. Stop the VM and run `zaigr project rebuild` to replace the image from recorded setups, or run `zaigr project clean` to discard all setup changes. Rebuild may require `--force` if you intend to discard unrecorded root changes. If recovery cannot establish a trusted image, use a clean project image")
	}
	if _, pending, err := store.readSetupExecutionIntent(); err != nil {
		return fmt.Errorf("cannot verify setup execution state before maintenance network access: %w", err)
	} else if pending {
		return errors.New("maintenance network access is unavailable because an interrupted setup execution is unresolved; recover or replace the project image before opening a maintenance session")
	}
	if _, err := os.Stat(store.appliedSetupsPath()); errors.Is(err, os.ErrNotExist) {
		pin, hasPin, pinErr := store.readBackingPin()
		if pinErr != nil {
			return fmt.Errorf("cannot verify project base-image provenance before maintenance network access: %w", pinErr)
		}
		if hasPin && pin.Kind == "custom" {
			manifest, customized, manifestErr := readGlobalBaseManifest()
			if manifestErr != nil {
				return fmt.Errorf("cannot verify pinned custom base-image setup history before maintenance network access: %w", manifestErr)
			}
			if customized && manifest.Revision == pin.Revision {
				if names := rootEquivalentAppliedSetupNames(manifest.Applied); len(names) > 0 {
					return fmt.Errorf("maintenance network access is unavailable because the pinned custom base image contains root-equivalent runtime setup(s): %s; use a clean project image without these runtimes or exact host firewall grants", strings.Join(names, ", "))
				}
			} else {
				return errors.New("maintenance network access is unavailable because the custom base image has no verifiable applied-setup history; create a clean project image with recorded setup provenance")
			}
		}
	} else if err != nil {
		return fmt.Errorf("cannot verify applied setup history before maintenance network access: %w", err)
	}
	return nil
}

func rootEquivalentAppliedSetupNames(records []appliedSetup) []string {
	seen := make(map[string]struct{})
	var names []string
	for _, record := range records {
		name := strings.ToLower(strings.TrimSpace(record.Name))
		if name != "docker" && name != "k3s" {
			continue
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	return names
}

func rootEquivalentSetupNames(definitions []setupDefinition) []string {
	records := make([]appliedSetup, 0, len(definitions))
	for _, definition := range definitions {
		records = append(records, appliedSetup{Name: definition.Name})
	}
	return rootEquivalentAppliedSetupNames(records)
}

func stopMaintenanceControl(runtimeDir, launchID, sessionID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := hostNetworkControlRequestWithReply(ctx, runtimeDir, launchID, hostNetworkControlRequest{Operation: "maintenance-stop", SessionID: sessionID}, time.Time{})
	if err != nil {
		return fmt.Errorf("stop maintenance network session: %w", err)
	}
	return nil
}

func maintenanceNamespaceName(launchID string) (string, error) {
	if !validHostPolicyScopeID(launchID) {
		return "", errors.New("invalid maintenance network launch identity")
	}
	return "zaigr-maint-" + launchID, nil
}

func prepareMaintenanceNamespace(endpoint vmControlEndpoint, name, launchID string, session hostnet.MaintenanceSession) error {
	if !validHostPolicyScopeID(launchID) || name != "zaigr-maint-"+launchID {
		return errors.New("invalid maintenance namespace identity")
	}
	if session.HostAddress.String() != "10.0.4.1" || session.GuestAddress.String() != "10.0.4.2" {
		return fmt.Errorf("host returned unexpected maintenance NIC addresses %s and %s", session.HostAddress, session.GuestAddress)
	}
	const maintenanceMAC = "52:54:00:5a:47:52"
	lockPath := "/run/zaigr/maintenance-" + launchID + ".lock"
	configPath := "/etc/netns/" + name + "/resolv.conf"
	setup := "set -eu\n" +
		"install -d -o root -g root -m 0700 /run/netns /run/zaigr /etc/netns\n" +
		"find /etc/netns -mindepth 1 -maxdepth 1 -type d -name 'zaigr-maint-*' ! -name " + singleQuotedArg(name) + " -exec rm -rf -- {} +\n" +
		"ip netns list | awk -v wanted=" + singleQuotedArg(name) + " '$1 == wanted { found = 1 } END { exit !found }' || ip netns add " + singleQuotedArg(name) + "\n" +
		"find_mac() { ip -o link show | awk '$0 ~ /link\\/ether " + maintenanceMAC + "([[:space:]]|$)/ { name = $2; sub(/:$/, \"\", name); sub(/@.*/, \"\", name); count++ } END { if (count == 1) print name; else if (count > 1) print \"__duplicate__\" }'; }\n" +
		"iface=\"$(find_mac)\"\n" +
		"if [ -n \"$iface\" ]; then\n" +
		"  if [ \"$iface\" = __duplicate__ ]; then printf 'multiple guest interfaces have the maintenance MAC\\n' >&2; exit 1; fi\n" +
		"  in_namespace=\"$(ip -n " + singleQuotedArg(name) + " -o link show | awk '$0 ~ /link\\/ether " + maintenanceMAC + "([[:space:]]|$)/ { name = $2; sub(/:$/, \"\", name); sub(/@.*/, \"\", name); count++ } END { if (count == 1) print name; else if (count > 1) print \"__duplicate__\" }')\"\n" +
		"  if [ \"$in_namespace\" = __duplicate__ ]; then printf 'multiple guest interfaces in maintenance namespace have the maintenance MAC\\n' >&2; exit 1; fi\n" +
		"  if [ -n \"$in_namespace\" ]; then printf 'maintenance NIC appears in multiple namespaces\\n' >&2; exit 1; fi\n" +
		"  ip link set dev \"$iface\" netns " + singleQuotedArg(name) + "\n" +
		"else\n" +
		"  iface=\"$(ip -n " + singleQuotedArg(name) + " -o link show | awk '$0 ~ /link\\/ether " + maintenanceMAC + "([[:space:]]|$)/ { name = $2; sub(/:$/, \"\", name); sub(/@.*/, \"\", name); count++ } END { if (count == 1) print name; else if (count > 1) print \"__duplicate__\" }')\"\n" +
		"  if [ \"$iface\" = __duplicate__ ]; then printf 'multiple guest interfaces in maintenance namespace have the maintenance MAC\\n' >&2; exit 1; fi\n" +
		"  if [ -z \"$iface\" ]; then printf 'maintenance NIC with expected MAC was not found\\n' >&2; exit 1; fi\n" +
		"fi\n" +
		"ip -n " + singleQuotedArg(name) + " link set lo up\n" +
		"ip -n " + singleQuotedArg(name) + " addr replace " + session.GuestAddress.String() + "/24 dev \"$iface\"\n" +
		"ip -n " + singleQuotedArg(name) + " link set dev \"$iface\" up\n" +
		"ip -n " + singleQuotedArg(name) + " route replace default via " + session.HostAddress.String() + " dev \"$iface\"\n" +
		"install -d -o root -g root -m 0700 " + singleQuotedArg("/etc/netns/"+name) + "\n" +
		"printf 'nameserver 10.0.2.3\\noptions timeout:1 attempts:1\\n' > " + singleQuotedArg(configPath) + "\n"
	command := "install -d -o root -g root -m 0700 /run/zaigr && flock -x " + singleQuotedArg(lockPath) + " sh -eu -c " + singleQuotedArg(setup)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	return sshRunCommandWithExitStatusContext(ctx, endpoint, "root", command)
}
