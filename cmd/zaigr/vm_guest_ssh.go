package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"zaigr/cmd/zaigr/vmssh"
)

func runVMGuestCommand(ctx context.Context, endpoint vmControlEndpoint, user string, command string, input io.Reader, stdout io.Writer, stderr io.Writer) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateVMControlEndpoint(endpoint); err != nil {
		return err
	}
	if input == nil {
		return vmssh.Run(ctx, endpoint.SocketPath, vmssh.Request{User: user, Command: command}, nil, stdout, stderr)
	}
	return vmssh.Run(ctx, endpoint.SocketPath, vmssh.Request{User: user, Command: command, Input: true}, input, stdout, stderr)
}

func runVMGuestInteractive(ctx context.Context, endpoint vmControlEndpoint, user string, command string, terminal *os.File) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateVMControlEndpoint(endpoint); err != nil {
		return err
	}
	return vmssh.RunInteractive(ctx, endpoint.SocketPath, user, command, terminal, os.Stdout, os.Stderr)
}

func validateVMControlEndpoint(endpoint vmControlEndpoint) error {
	if endpoint.SocketPath == "" || !filepath.IsAbs(endpoint.SocketPath) || endpoint.LaunchID == "" || endpoint.VsockCID < 3 {
		return errors.New("VM guest-control endpoint is incomplete; restart the VM")
	}
	return nil
}

func vmSSHExitError(err error) error {
	var status *vmssh.ExitError
	if errors.As(err, &status) {
		return exitError(status.Status)
	}
	return err
}

// showVMStopAfterSession prints why the VM stopped when an interactive session
// was cut off, instead of leaving the reason for the next zaigr command. The
// supervisor writes the reason while it shuts down, so wait for it briefly.
func showVMStopAfterSession(store projectStore, sessionErr error) {
	var exitErr *vmssh.ExitError
	if sessionErr == nil || errors.As(sessionErr, &exitErr) {
		return
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(vmStopNoticePath(store)); err == nil {
			showVMStopNotice(store)
			return
		}
		if !time.Now().Before(deadline) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}
