package main

import (
	"fmt"
	"sort"
	"strings"
)

func cmdProjectFirewallIPChange(rawAddress string, allow bool) error {
	operation := "project firewall remove"
	if allow {
		operation = "project firewall allow"
	}
	lock, err := lockCurrentProject(operation)
	if err != nil {
		return fmt.Errorf("project firewall: %w", err)
	}
	defer lock.releaseWithWarning()
	if _, err := requireProject(operation); err != nil {
		return fmt.Errorf("project firewall: %w", err)
	}

	address, err := validateProjectFirewallIPv4(rawAddress)
	if err != nil {
		return err
	}
	store := currentProjectStore()
	if err := lock.lockFirewallIPMutation(store, operation); err != nil {
		return fmt.Errorf("project firewall: %w", err)
	}
	addresses, err := store.firewallIPs()
	if err != nil {
		return err
	}

	found := false
	for _, existing := range addresses {
		if existing == address {
			found = true
			break
		}
	}
	if !allow && !found {
		running, stale := detectRunningProjectVMWithMetadata()
		if stale {
			_ = store.clearRuntimeState()
			running = nil
		}
		if running != nil {
			applied, known, appliedErr := store.appliedFirewallIPs()
			if appliedErr != nil {
				return appliedErr
			}
			attempted, attemptedKnown, attemptedErr := store.attemptedFirewallIPs()
			if attemptedErr != nil {
				return attemptedErr
			}
			if (known && containsString(applied, address)) || (attemptedKnown && containsString(attempted, address)) {
				if err := syncProjectFirewallIPsToVM(running.Port, addresses, []string{address}); err != nil {
					return fmt.Errorf("project firewall permission is absent from saved state, but could not be removed from the running VM: %w; restart the project VM to reconcile it", err)
				}
				fmt.Printf(":: Exact IPv4 address %s was already absent from saved permissions; removal applied to the running project VM\n", address)
				return nil
			}
		}
		fmt.Printf(":: Exact IPv4 address %s is not allowed for this project\n", address)
		return nil
	}
	if allow && found {
		running, stale := detectRunningProjectVMWithMetadata()
		if stale {
			_ = store.clearRuntimeState()
			running = nil
		}
		if running != nil {
			applied, known, appliedErr := store.appliedFirewallIPs()
			if appliedErr != nil {
				return appliedErr
			}
			_, attempted, attemptedErr := store.attemptedFirewallIPs()
			if attemptedErr != nil {
				return attemptedErr
			}
			if known && !attempted && equalStrings(applied, addresses) {
				fmt.Printf(":: Exact IPv4 address %s is already allowed for this project on all ports; applied to the running project VM\n", address)
				return nil
			}
			if err := syncProjectFirewallIPsToVM(running.Port, addresses, nil); err != nil {
				return fmt.Errorf("project firewall permission is saved, but could not be reapplied to the running VM: %w; restart the project VM to reconcile it", err)
			}
			fmt.Printf(":: Exact IPv4 address %s is already allowed for this project on all ports; applied to the running project VM\n", address)
			return nil
		}
		fmt.Printf(":: Exact IPv4 address %s is already allowed for this project on all ports; saved for the next VM start\n", address)
		return nil
	}

	updated := make([]string, 0, len(addresses)+1)
	if allow {
		updated = append(updated, addresses...)
		updated = append(updated, address)
		sort.Strings(updated)
	} else {
		for _, existing := range addresses {
			if existing != address {
				updated = append(updated, existing)
			}
		}
	}
	if err := store.writeFirewallIPs(updated); err != nil {
		return err
	}

	running, stale := detectRunningProjectVMWithMetadata()
	if stale {
		_ = store.clearRuntimeState()
		running = nil
	}
	if running == nil {
		verb := "Allowed"
		if !allow {
			verb = "Removed"
		}
		fmt.Printf(":: %s %s in saved project firewall permissions; applies on the next VM start\n", verb, address)
		return nil
	}

	revoked := []string(nil)
	if !allow {
		revoked = []string{address}
	}
	if err := syncProjectFirewallIPsToVM(running.Port, updated, revoked); err != nil {
		return fmt.Errorf(
			"project firewall permission was saved, but could not be applied to the running VM: %w; retry the command or restart the project VM",
			err,
		)
	}
	verb := "Allowed"
	if !allow {
		verb = "Removed"
	}
	fmt.Printf(":: %s exact IPv4 address %s on all ports; applied to the running project VM\n", verb, address)
	return nil
}

func printProjectFirewallIPs(addresses []string, running bool) {
	fmt.Println("# Project exact IPv4 permissions (all ports)")
	if len(addresses) == 0 {
		fmt.Println("(none)")
	} else {
		for _, address := range addresses {
			fmt.Println(address)
		}
	}
	if running {
		applied, known, err := currentProjectStore().appliedFirewallIPs()
		_, attempted, attemptedErr := currentProjectStore().attemptedFirewallIPs()
		if err == nil && attemptedErr == nil && !attempted && known && equalStrings(applied, addresses) {
			fmt.Println("status: applied to the running project VM")
		} else {
			fmt.Println("status: saved; application to the running project VM is pending or unconfirmed")
		}
	} else {
		fmt.Println("status: saved; pending the next project VM start")
	}
	fmt.Println("# Domain permissions")
}

func syncProjectFirewallIPsToVM(port string, addresses []string, revoked []string) error {
	store := currentProjectStore()
	applied, _, err := store.appliedFirewallIPs()
	if err != nil {
		return err
	}
	attempted, _, err := store.attemptedFirewallIPs()
	if err != nil {
		return err
	}
	desired := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		desired[address] = struct{}{}
	}
	revocationSet := make(map[string]struct{}, len(revoked)+len(applied)+len(attempted))
	potentiallyApplied := make(map[string]struct{}, len(revoked)+len(applied)+len(attempted)+len(addresses))
	for _, address := range append(append(append([]string{}, revoked...), applied...), attempted...) {
		potentiallyApplied[address] = struct{}{}
		if _, remainsDesired := desired[address]; !remainsDesired {
			revocationSet[address] = struct{}{}
		}
	}
	for _, address := range addresses {
		potentiallyApplied[address] = struct{}{}
	}
	revoked = revoked[:0]
	for address := range revocationSet {
		revoked = append(revoked, address)
	}
	sort.Strings(revoked)
	pending := make([]string, 0, len(potentiallyApplied))
	for address := range potentiallyApplied {
		pending = append(pending, address)
	}
	sort.Strings(pending)
	if err := store.writeAttemptedFirewallIPs(pending); err != nil {
		return err
	}

	rootKeyPath, _, err := ensureRootSSHKey()
	if err != nil {
		return err
	}
	args := []string{"/usr/local/sbin/zaigr-inside", "firewall", "sync-ips"}
	for _, address := range revoked {
		args = append(args, "--revoke", address)
	}
	args = append(args, "--")
	args = append(args, addresses...)
	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		quoted = append(quoted, singleQuotedArg(arg))
	}
	if err := sshRunControlScript(port, rootKeyPath, "exec "+strings.Join(quoted, " ")+"\n"); err != nil {
		return fmt.Errorf("sync exact IPv4 permissions to VM: %w", err)
	}
	if err := store.writeAppliedFirewallIPs(addresses); err != nil {
		return err
	}
	if err := store.clearAttemptedFirewallIPs(); err != nil {
		return err
	}
	return nil
}

func syncSavedProjectFirewallIPsToVM(port string) error {
	store := currentProjectStore()
	held, err := acquireProjectFileLock(store, ".firewall-ips", "project firewall startup sync", true)
	if err != nil {
		return err
	}
	lock := &projectMutationLock{held: []heldProjectLock{held}}
	defer lock.releaseWithWarning()
	addresses, err := store.firewallIPs()
	if err != nil {
		return err
	}
	return syncProjectFirewallIPsToVM(port, addresses, nil)
}

// reconcileSavedProjectFirewallIPsToVM blocks ordinary guest entry until a
// prior partial live mutation has been repaired. The clean cache avoids
// republishing rules for every project vm exec.
func reconcileSavedProjectFirewallIPsToVM(port string) error {
	store := currentProjectStore()
	held, err := acquireProjectFileLock(store, ".firewall-ips", "project firewall entry sync", true)
	if err != nil {
		return err
	}
	lock := &projectMutationLock{held: []heldProjectLock{held}}
	defer lock.releaseWithWarning()

	addresses, err := store.firewallIPs()
	if err != nil {
		return err
	}
	applied, known, err := store.appliedFirewallIPs()
	if err != nil {
		return err
	}
	_, attempted, err := store.attemptedFirewallIPs()
	if err != nil {
		return err
	}
	if known && !attempted && equalStrings(applied, addresses) {
		return nil
	}
	return syncProjectFirewallIPsToVM(port, addresses, nil)
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func equalStrings(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
