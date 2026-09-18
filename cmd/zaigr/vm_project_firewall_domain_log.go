package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
)

func cmdProjectFirewallDomainLog() error {
	lock, err := lockCurrentProject("project firewall domain-log")
	if err != nil {
		return err
	}
	defer lock.releaseWithWarning()
	store := currentProjectStore()
	logInfo("starting project firewall domain-log command", "store", storeDir())
	if _, err := requireProject("project firewall domain-log"); err != nil {
		return err
	}

	running, stale := detectRunningProjectVM()
	if stale {
		_ = store.clearRuntimeState()
		return fmt.Errorf("project VM is not running; start it with 'zaigr project vm start' or 'zaigr shell'")
	}
	if running == nil || running.Port == "" {
		return fmt.Errorf("project VM is not running; start it with 'zaigr project vm start' or 'zaigr shell'")
	}

	rootKeyPath, _, err := ensureRootSSHKey()
	if err != nil {
		return fmt.Errorf("prepare root SSH key: %w", err)
	}

	port := running.Port
	if err := lock.release(); err != nil {
		return fmt.Errorf("release project operation lock: %w", err)
	}
	return streamProjectFirewallDomainLog(port, rootKeyPath)
}

func streamProjectFirewallDomainLog(port string, rootKeyPath string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	args := append(sshManagedOptions(), "-o", sshConnectTimeoutOption)
	args = append(args, "-i", rootKeyPath, "-p", port, "root@localhost", "/usr/local/sbin/zaigr-inside firewall domain-log")
	cmd := exec.CommandContext(ctx, "ssh", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if ctx.Err() != nil {
		return nil
	}
	if err != nil {
		return fmt.Errorf("VM domain-log stream failed: %w", err)
	}
	return nil
}
