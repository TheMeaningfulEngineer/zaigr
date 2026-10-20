package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"zaigr/cmd/zaigr/hostnet"
)

var firewallDomainPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

func acquireGlobalFirewallMutationLock(operation string) (*projectMutationLock, error) {
	dir, err := projectLocksDir()
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filepath.Join(dir, "global-firewall.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open global firewall lock: %w", err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("cannot run %s: another global firewall mutation is running", operation)
	}
	return &projectMutationLock{held: []heldProjectLock{{file: file}}}, nil
}

func newGlobalFirewallCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "firewall",
		Short: "Manage global firewall allowlist entries",
	}
	cmd.AddCommand(newGlobalFirewallListCommand())
	cmd.AddCommand(newGlobalFirewallAllowCommand())
	cmd.AddCommand(newGlobalFirewallRemoveCommand())
	return cmd
}

func newGlobalFirewallListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List global firewall allowlist entries",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cmdGlobalFirewallList()
		},
	}
}

func newGlobalFirewallAllowCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "allow <domain> [<domain> ...]",
		Short: "Add global firewall allowlist entries",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return cmdGlobalFirewallAllow(args)
		},
	}
}

func newGlobalFirewallRemoveCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove <domain> [<domain> ...]",
		Short: "Remove global firewall allowlist entries",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return cmdGlobalFirewallRemove(args)
		},
	}
	cmd.ValidArgsFunction = completeGlobalFirewallEntry
	return cmd
}

func cmdGlobalFirewallList() error {
	entries, err := globalFirewallEntries()
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		fmt.Println("No global firewall entries have been configured.")
		return nil
	}
	for _, entry := range entries {
		fmt.Println(entry)
	}
	return nil
}

func cmdGlobalFirewallAllow(rawDomains []string) error {
	lock, err := acquireGlobalFirewallMutationLock("global firewall allow")
	if err != nil {
		return err
	}
	defer lock.release()
	domains, err := normalizeFirewallDomains(rawDomains)
	if err != nil {
		return err
	}
	current, err := globalFirewallEntries()
	if err != nil {
		return err
	}
	currentSet := make(map[string]struct{}, len(current))
	for _, entry := range current {
		currentSet[entry] = struct{}{}
	}
	for _, domain := range domains {
		if _, ok := currentSet[domain]; ok {
			fmt.Printf("already allowed %s\n", domain)
			continue
		}
		current = append(current, domain)
		currentSet[domain] = struct{}{}
		fmt.Printf("allowed %s\n", domain)
	}
	if err := writeGlobalFirewallEntries(current); err != nil {
		return err
	}
	return reconcileGlobalHostFirewallPolicy()
}

func cmdGlobalFirewallRemove(rawDomains []string) error {
	lock, err := acquireGlobalFirewallMutationLock("global firewall remove")
	if err != nil {
		return err
	}
	defer lock.release()
	domains, err := normalizeFirewallDomains(rawDomains)
	if err != nil {
		return err
	}
	current, err := globalFirewallEntries()
	if err != nil {
		return err
	}
	removeSet := make(map[string]struct{}, len(domains))
	for _, domain := range domains {
		removeSet[domain] = struct{}{}
	}
	currentSet := make(map[string]struct{}, len(current))
	for _, entry := range current {
		currentSet[entry] = struct{}{}
	}
	for _, domain := range domains {
		if _, ok := currentSet[domain]; !ok {
			return fmt.Errorf("not allowed %s", domain)
		}
	}
	remaining := make([]string, 0, len(current))
	for _, entry := range current {
		if _, remove := removeSet[entry]; remove {
			continue
		}
		remaining = append(remaining, entry)
	}
	if err := writeGlobalFirewallEntries(remaining); err != nil {
		return err
	}
	for _, domain := range domains {
		fmt.Printf("removed %s\n", domain)
	}
	return reconcileGlobalHostFirewallPolicy()
}

func completeGlobalFirewallEntry(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	entries, err := globalFirewallEntries()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	used := make(map[string]struct{}, len(args))
	for _, arg := range args {
		domain := normalizeFirewallDomain(arg)
		used[domain] = struct{}{}
	}
	prefix := normalizeFirewallDomain(toComplete)
	matches := make([]string, 0)
	for _, entry := range entries {
		if _, ok := used[entry]; ok {
			continue
		}
		if strings.HasPrefix(entry, prefix) {
			matches = append(matches, entry)
		}
	}
	return matches, cobra.ShellCompDirectiveNoFileComp
}

func globalFirewallPath() string {
	return filepath.Join(zaigDir(), "firewall")
}

func globalFirewallEntries() ([]string, error) {
	data, err := readProtectedHostPolicyFile(zaigDir(), "firewall")
	if err != nil {
		return nil, err
	}
	return parseProtectedFirewallDomains(data, "global firewall")
}

func writeGlobalFirewallEntries(entries []string) error {
	normalized, err := normalizeFirewallDomains(entries)
	if err != nil {
		return err
	}
	var data []byte
	if len(normalized) > 0 {
		data = []byte(strings.Join(normalized, "\n") + "\n")
	}
	return writeProtectedHostPolicyFile(zaigDir(), "firewall", data)
}

func reconcileGlobalHostFirewallPolicy() error {
	stores, err := listProjectStores()
	if err != nil {
		return fmt.Errorf("global firewall saved, but project stores could not be enumerated for live reconciliation: %w", err)
	}
	var failures []error
	for _, store := range stores {
		running, stale := detectRunningProjectVMWithMetadataInStore(store)
		if stale || running == nil {
			continue
		}
		host, record, err := runningHostNetworkRecord(store)
		if err != nil {
			failures = append(failures, fmt.Errorf("project %s host firewall status: %w", store.Hash, err))
			continue
		}
		if !host {
			continue
		}
		lock, err := acquireProjectOperationLock(store, "global firewall policy reconciliation", false, true)
		if err != nil {
			failures = append(failures, fmt.Errorf("project %s: %w", store.Hash, err))
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, syncErr := hostNetworkControl(ctx, store.runtimeDir(), record.LaunchID, "policy-reconcile", hostnet.Forward{})
		cancel()
		_ = lock.release()
		if syncErr != nil {
			failures = append(failures, fmt.Errorf("project %s host firewall: %w", store.Hash, syncErr))
		}
	}
	if len(failures) != 0 {
		return fmt.Errorf("global firewall policy was saved, but live project policy reconciliation failed: %w", errors.Join(failures...))
	}
	return nil
}

func normalizeFirewallDomains(rawDomains []string) ([]string, error) {
	seen := make(map[string]struct{}, len(rawDomains))
	domains := make([]string, 0, len(rawDomains))
	for _, raw := range rawDomains {
		domain := normalizeFirewallDomain(raw)
		if !isValidFirewallDomain(domain) {
			return nil, fmt.Errorf("invalid domain: %s", raw)
		}
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		domains = append(domains, domain)
	}
	return domains, nil
}

func normalizeFirewallDomain(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func isValidFirewallDomain(domain string) bool {
	if len(domain) > 253 {
		return false
	}
	return firewallDomainPattern.MatchString(domain)
}

func readFirewallListFile(path string, label string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", label, err)
	}
	seen := make(map[string]struct{})
	entries := make([]string, 0)
	for _, line := range strings.Split(string(data), "\n") {
		entry := strings.TrimSpace(line)
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		if !isValidFirewallDomain(entry) {
			return nil, fmt.Errorf("invalid %s entry: %s", label, entry)
		}
		if _, ok := seen[entry]; ok {
			continue
		}
		seen[entry] = struct{}{}
		entries = append(entries, entry)
	}
	sort.Strings(entries)
	return entries, nil
}

func writeFirewallListFile(path string, entries []string, label string) error {
	seen := make(map[string]struct{})
	normalized := make([]string, 0, len(entries))
	for _, value := range entries {
		entry := strings.TrimSpace(value)
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		if !isValidFirewallDomain(entry) {
			return fmt.Errorf("invalid %s entry: %s", label, entry)
		}
		if _, ok := seen[entry]; ok {
			continue
		}
		seen[entry] = struct{}{}
		normalized = append(normalized, entry)
	}
	sort.Strings(normalized)
	content := ""
	if len(normalized) > 0 {
		content = strings.Join(normalized, "\n") + "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("write %s: %w", label, err)
	}
	return nil
}
