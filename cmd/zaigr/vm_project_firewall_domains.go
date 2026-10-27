package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"zaigr/cmd/zaigr/hostnet"
)

const projectFirewallDomainsFile = "firewall-domains"

func (store projectStore) firewallDomainsPath() string {
	return filepath.Join(store.Path, projectFirewallDomainsFile)
}

func (store projectStore) firewallDomains() ([]string, error) {
	data, err := readProtectedHostPolicyFile(store.Path, projectFirewallDomainsFile)
	if err != nil {
		return nil, fmt.Errorf("read manual project firewall domains: %w", err)
	}
	return parseProtectedFirewallDomains(data, "manual project firewall")
}

func (store projectStore) writeFirewallDomains(entries []string) error {
	validated, err := normalizeFirewallDomains(entries)
	if err != nil {
		return err
	}
	var data []byte
	if len(validated) > 0 {
		data = []byte(strings.Join(validated, "\n") + "\n")
	}
	return writeProtectedHostPolicyFile(store.Path, projectFirewallDomainsFile, data)
}

func parseProtectedFirewallDomains(data []byte, label string) ([]string, error) {
	if len(data) == 0 {
		return nil, nil
	}
	if data[len(data)-1] != '\n' {
		return nil, fmt.Errorf("invalid %s metadata: nonempty file must end with a newline", label)
	}
	seen := make(map[string]struct{})
	entries := make([]string, 0)
	previous := ""
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if line == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if strings.TrimSpace(line) != line {
			return nil, fmt.Errorf("invalid %s entry %q", label, line)
		}
		entry, err := validateHostDNSPolicyName(line)
		if err != nil || entry != line {
			return nil, fmt.Errorf("invalid %s entry %q: only normalized exact DNS names are supported", label, line)
		}
		if _, exists := seen[entry]; exists || (previous != "" && entry <= previous) {
			return nil, fmt.Errorf("invalid %s metadata: entries must be sorted and unique", label)
		}
		seen[entry] = struct{}{}
		entries = append(entries, entry)
		previous = entry
	}
	return entries, nil
}

func writeProtectedHostPolicyFile(root, name string, data []byte) error {
	if !filepath.IsAbs(root) || (name != projectFirewallDomainsFile && name != "firewall" && name != "firewall-ips") {
		return errors.New("host network policy: invalid protected policy path")
	}
	if err := os.MkdirAll(root, 0755); err != nil {
		return fmt.Errorf("create protected firewall policy directory: %w", err)
	}
	canonical, err := canonicalPathWithMissingSuffix(root)
	if err != nil {
		return err
	}
	if filepath.Clean(root) != canonical {
		return errors.New("host network policy directory must not be a symlink or path alias")
	}
	dirFD, err := unix.Open(canonical, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open protected firewall policy directory: %w", err)
	}
	defer unix.Close(dirFD)
	var dirStat unix.Stat_t
	if err := unix.Fstat(dirFD, &dirStat); err != nil {
		return err
	}
	if dirStat.Uid != uint32(os.Getuid()) || dirStat.Mode&unix.S_IFMT != unix.S_IFDIR || dirStat.Mode&0022 != 0 {
		return errors.New("host network policy directory must be owned by the current user and not writable by others")
	}
	resolved, err := filepath.EvalSymlinks(fmt.Sprintf("/proc/self/fd/%d", dirFD))
	if err != nil || filepath.Clean(resolved) != canonical {
		return errors.New("host network policy directory changed while opening")
	}
	// Atomic rename replaces a leaf symlink instead of following it. Use an
	// O_EXCL temporary file relative to the already validated directory FD.
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	tmpName := fmt.Sprintf(".%s.%s.tmp", name, hex.EncodeToString(nonce[:]))
	tmpFD, err := unix.Openat(dirFD, tmpName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return fmt.Errorf("create protected firewall policy temporary file: %w", err)
	}
	keep := false
	defer func() {
		_ = unix.Close(tmpFD)
		if !keep {
			_ = unix.Unlinkat(dirFD, tmpName, 0)
		}
	}()
	if err := unix.Fchmod(tmpFD, 0644); err != nil {
		return err
	}
	for len(data) > 0 {
		written, err := unix.Write(tmpFD, data)
		if err != nil {
			return err
		}
		if written == 0 {
			return errors.New("write protected firewall policy: short write")
		}
		data = data[written:]
	}
	if err := unix.Fsync(tmpFD); err != nil {
		return err
	}
	if err := unix.Renameat(dirFD, tmpName, dirFD, name); err != nil {
		return fmt.Errorf("replace protected firewall policy: %w", err)
	}
	keep = true
	return unix.Fsync(dirFD)
}

func projectFirewallDomainSources(store projectStore) (manual, setups, global []string, err error) {
	manual, err = store.firewallDomains()
	if err != nil {
		return nil, nil, nil, err
	}
	setupData, err := readProtectedHostPolicyFile(store.Path, "firewall")
	if err != nil {
		return nil, nil, nil, err
	}
	// Unusable lines copied from older setups are skipped here, as when the
	// VM starts; the setup loader explains them.
	for _, raw := range parseHostPolicyNames(setupData) {
		if name, validateErr := validateHostDNSPolicyName(raw); validateErr == nil {
			setups = append(setups, name)
		}
	}
	global, err = globalFirewallEntries()
	if err != nil {
		return nil, nil, nil, err
	}
	return manual, setups, global, nil
}

func effectiveProjectFirewallDomains(sources ...[]string) []string {
	set := make(map[string]struct{})
	for _, entries := range sources {
		for _, entry := range entries {
			set[entry] = struct{}{}
		}
	}
	effective := make([]string, 0, len(set))
	for entry := range set {
		effective = append(effective, entry)
	}
	sort.Strings(effective)
	return effective
}

func printProjectHostFirewallShow(store projectStore, running *runningVMInfo) error {
	manual, setups, global, err := projectFirewallDomainSources(store)
	if err != nil {
		return err
	}
	addresses, err := store.firewallIPs()
	if err != nil {
		return err
	}
	printProjectFirewallIPs(addresses, running != nil)
	fmt.Println("# Temporary network sessions")
	if running == nil {
		fmt.Println("active sessions: 0 (VM stopped)")
	} else if host, record, recordErr := runningHostNetworkRecord(store); recordErr != nil {
		return recordErr
	} else if !host {
		fmt.Println("active sessions: unavailable for this legacy VM")
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		status, statusErr := hostNetworkControl(ctx, store.runtimeDir(), record.LaunchID, "status", hostnet.Forward{})
		cancel()
		if statusErr != nil {
			return fmt.Errorf("read temporary host network leases: %w", statusErr)
		}
		fmt.Printf("active sessions: %d\n", status.FullNetworkSessions+status.MaintenanceSessions)
		fmt.Printf("full-network sessions: %d\n", status.FullNetworkSessions)
		fmt.Printf("maintenance sessions: %d\n", status.MaintenanceSessions)
	}
	printDomainEntries("# Built-in base domain permissions", hostNetworkBuiltinDomains)
	printDomainEntries("# Project manual domain permissions", manual)
	printDomainEntries("# Project setup permissions", setups)
	printDomainEntries("# Global domain permissions", global)
	return nil
}

func printDomainEntries(title string, entries []string) {
	fmt.Println(title)
	if len(entries) == 0 {
		fmt.Println("(none)")
		return
	}
	for _, entry := range entries {
		fmt.Println(entry)
	}
}

// cmdProjectFirewallChange allows or removes each domain name or IPv4 address
// in order. Every argument is checked first, so a typo changes nothing.
func cmdProjectFirewallChange(rawTargets []string, allow bool) error {
	for _, raw := range rawTargets {
		if err := checkFirewallTarget(raw); err != nil {
			return err
		}
	}
	for _, raw := range rawTargets {
		var err error
		if _, parseErr := netip.ParseAddr(raw); parseErr == nil {
			err = cmdProjectFirewallIPChange(raw, allow)
		} else {
			err = cmdProjectFirewallDomainChange(raw, allow)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func checkFirewallTarget(raw string) error {
	if _, err := netip.ParseAddr(raw); err == nil {
		_, err := validateProjectFirewallIPv4(raw)
		return err
	}
	if _, err := normalizeFirewallDomains([]string{raw}); err == nil {
		return nil
	}
	message := fmt.Sprintf("%q is not a domain name or an IPv4 address. Use plain names like github.com.", raw)
	if suggestion := suggestFirewallDomain(raw); suggestion != "" {
		message += "\nDid you mean: " + suggestion
		if strings.HasPrefix(strings.TrimSpace(raw), "*.") {
			message += " (only that exact name is allowed, not its subdomains)"
		}
	}
	return errors.New(message)
}

func cmdProjectFirewallDomainChange(raw string, allow bool) error {
	operation := "project firewall remove"
	if allow {
		operation = "project firewall allow"
	}
	lock, err := lockCurrentProject(operation)
	if err != nil {
		return fmt.Errorf("%s: %w", operation, err)
	}
	defer lock.releaseWithWarning()
	if _, err := requireProject(operation); err != nil {
		return err
	}
	entries, err := normalizeFirewallDomains([]string{raw})
	if err != nil {
		return err
	}
	name := entries[0]
	store := currentProjectStore()
	if err := lock.lockFirewallIPMutation(store, operation); err != nil {
		return err
	}
	current, err := store.firewallDomains()
	if err != nil {
		return err
	}
	found := containsString(current, name)
	if allow && !found {
		current = append(current, name)
	}
	if !allow && found {
		updated := make([]string, 0, len(current)-1)
		for _, entry := range current {
			if entry != name {
				updated = append(updated, entry)
			}
		}
		current = updated
	}
	sort.Strings(current)
	if (allow && !found) || (!allow && found) {
		if err := store.writeFirewallDomains(current); err != nil {
			return err
		}
	}
	running, stale := detectRunningProjectVMWithMetadata()
	if stale {
		if err := store.clearRuntimeState(); err != nil {
			return err
		}
		running = nil
	}
	if running != nil {
		host, record, err := runningHostNetworkRecord(store)
		if err != nil {
			return err
		}
		if !host {
			return errors.New("domain firewall changes require host-enforced networking; stop and restart this legacy VM")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
		_, err = hostNetworkControl(ctx, store.runtimeDir(), record.LaunchID, "policy-reconcile", hostnet.Forward{})
		cancel()
		if err != nil {
			return fmt.Errorf("domain permission saved but live policy reconciliation failed: %w", err)
		}
	}
	if allow {
		fmt.Printf(":: Exact DNS name %s allowed for this project\n", name)
	} else {
		fmt.Printf(":: Exact DNS name %s removed from this project\n", name)
	}
	return nil
}
