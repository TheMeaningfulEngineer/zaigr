package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"zaigr/cmd/zaigr/vmssh"
)

const (
	vmSSHBrokerChildCommand = "__vm-ssh-broker"
	vmSSHBrokerReadyFD      = 3
	vmSSHBrokerStopTimeout  = 5 * time.Second
)

type vmSSHBroker struct {
	command  *exec.Cmd
	done     chan struct{}
	ready    chan struct{}
	readyMu  sync.Mutex
	readyErr error

	waitMu  sync.Mutex
	waitErr error

	closeOnce sync.Once
	closeErr  error
	stopCtx   func() bool
}

type vmSSHBrokerReady struct {
	Ready bool   `json:"ready"`
	Error string `json:"error,omitempty"`
}

func startVMSSHBroker(ctx context.Context, cid uint32, runtimeSocket, rootPrivateKeyPath, userPrivateKeyPath string) (*vmSSHBroker, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("locate zaigr executable for SSH broker child: %w", err)
	}
	readyReader, readyWriter, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("create SSH broker readiness pipe: %w", err)
	}
	command := exec.Command(executable, vmSSHBrokerChildCommand,
		"--cid", fmt.Sprint(cid),
		"--socket", runtimeSocket,
		"--root-key", rootPrivateKeyPath,
		"--user-key", userPrivateKeyPath,
	)
	command.ExtraFiles = []*os.File{readyWriter}
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		_ = readyReader.Close()
		_ = readyWriter.Close()
		return nil, fmt.Errorf("start SSH broker child: %w", err)
	}
	_ = readyWriter.Close()
	broker := &vmSSHBroker{command: command, done: make(chan struct{}), ready: make(chan struct{})}
	go broker.waitChild()
	contextCallbackReady := make(chan struct{})
	broker.stopCtx = context.AfterFunc(ctx, func() {
		<-contextCallbackReady
		_ = broker.Close()
	})
	close(contextCallbackReady)

	go func() {
		defer readyReader.Close()
		var message vmSSHBrokerReady
		readErr := json.NewDecoder(io.LimitReader(readyReader, 64<<10)).Decode(&message)
		var readyErr error
		switch {
		case readErr != nil:
			readyErr = fmt.Errorf("read SSH broker readiness: %w", readErr)
		case !message.Ready && message.Error == "":
			readyErr = errors.New("SSH broker child exited without readiness")
		case !message.Ready:
			readyErr = fmt.Errorf("SSH broker child failed readiness: %s", message.Error)
		}
		broker.readyMu.Lock()
		broker.readyErr = readyErr
		broker.readyMu.Unlock()
		close(broker.ready)
	}()
	if err := ctx.Err(); err != nil {
		_ = broker.Close()
		return nil, err
	}
	return broker, nil
}

func (broker *vmSSHBroker) PID() int {
	if broker == nil || broker.command == nil || broker.command.Process == nil {
		return 0
	}
	return broker.command.Process.Pid
}

// Done closes when the SSH broker child exits. Wait returns its cached status.
func (broker *vmSSHBroker) Done() <-chan struct{} {
	return broker.done
}

func (broker *vmSSHBroker) Wait() error {
	if broker == nil {
		return nil
	}
	<-broker.done
	broker.waitMu.Lock()
	defer broker.waitMu.Unlock()
	return broker.waitErr
}

func (broker *vmSSHBroker) WaitReady(ctx context.Context) error {
	if broker == nil {
		return errors.New("SSH broker child is not running")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-broker.ready:
		broker.readyMu.Lock()
		err := broker.readyErr
		broker.readyMu.Unlock()
		if err != nil {
			return err
		}
		select {
		case <-broker.done:
			if waitErr := broker.Wait(); waitErr != nil {
				return fmt.Errorf("SSH broker child exited after readiness: %w", waitErr)
			}
			return errors.New("SSH broker child exited after readiness")
		default:
			return nil
		}
	case <-broker.done:
		select {
		case <-broker.ready:
			broker.readyMu.Lock()
			err := broker.readyErr
			broker.readyMu.Unlock()
			if err != nil {
				return err
			}
		default:
		}
		if waitErr := broker.Wait(); waitErr != nil {
			return fmt.Errorf("SSH broker child exited before readiness: %w", waitErr)
		}
		return errors.New("SSH broker child exited before readiness")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (broker *vmSSHBroker) Close() error {
	if broker == nil {
		return nil
	}
	broker.closeOnce.Do(func() {
		if broker.stopCtx != nil {
			broker.stopCtx()
		}
		select {
		case <-broker.done:
			broker.closeErr = broker.Wait()
			return
		default:
		}
		if err := broker.command.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
			broker.closeErr = fmt.Errorf("signal SSH broker child %d: %w", broker.PID(), err)
		}
		timer := time.NewTimer(vmSSHBrokerStopTimeout)
		defer timer.Stop()
		select {
		case <-broker.done:
			if err := broker.Wait(); err != nil {
				broker.closeErr = errors.Join(broker.closeErr, fmt.Errorf("SSH broker child exited during shutdown: %w", err))
			}
		case <-timer.C:
			killErr := broker.command.Process.Kill()
			waitErr := broker.Wait()
			broker.closeErr = errors.Join(broker.closeErr, fmt.Errorf("SSH broker child %d did not stop after SIGTERM; killed (kill=%v, wait=%v)", broker.PID(), killErr, waitErr))
		}
	})
	return broker.closeErr
}

func (broker *vmSSHBroker) waitChild() {
	err := broker.command.Wait()
	broker.waitMu.Lock()
	broker.waitErr = err
	broker.waitMu.Unlock()
	close(broker.done)
}

func newVMSSHBrokerChildCommand() *cobra.Command {
	var cid uint32
	var socket, rootKey, userKey string
	cmd := &cobra.Command{
		Use:    vmSSHBrokerChildCommand,
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			readyFile := os.NewFile(vmSSHBrokerReadyFD, "ssh-broker-ready")
			if readyFile == nil {
				return errors.New("SSH broker readiness descriptor is missing")
			}
			defer readyFile.Close()
			writeResult := func(message vmSSHBrokerReady) error {
				return json.NewEncoder(readyFile).Encode(message)
			}
			brokerCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
			defer stop()
			broker, err := vmssh.Start(brokerCtx, cid, socket, rootKey, userKey, vmssh.DialVSock)
			if err != nil {
				_ = writeResult(vmSSHBrokerReady{Error: err.Error()})
				return err
			}
			defer broker.Close()
			if err := broker.WaitReady(brokerCtx); err != nil {
				_ = writeResult(vmSSHBrokerReady{Error: err.Error()})
				return err
			}
			if err := writeResult(vmSSHBrokerReady{Ready: true}); err != nil {
				return fmt.Errorf("report SSH broker readiness: %w", err)
			}
			<-brokerCtx.Done()
			return nil
		},
	}
	cmd.Flags().Uint32Var(&cid, "cid", 0, "guest vsock CID")
	cmd.Flags().StringVar(&socket, "socket", "", "private SSH broker socket")
	cmd.Flags().StringVar(&rootKey, "root-key", "", "root SSH private key")
	cmd.Flags().StringVar(&userKey, "user-key", "", "user SSH private key")
	_ = cmd.MarkFlagRequired("cid")
	_ = cmd.MarkFlagRequired("socket")
	_ = cmd.MarkFlagRequired("root-key")
	_ = cmd.MarkFlagRequired("user-key")
	return cmd
}
