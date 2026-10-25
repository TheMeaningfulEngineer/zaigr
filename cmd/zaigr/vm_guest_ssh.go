package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

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
