package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"time"

	"zaigr/cmd/zaigr/hostdns"
	"zaigr/cmd/zaigr/hostnet"
)

// StreamDomainEvents sends launch-scoped host DNS observations as JSON lines.
// A history-gap event is explicit: callers must mark capture output incomplete
// rather than silently treating a wrapped ring as a complete observation.
func (h *hostNetworkHandle) StreamDomainEvents(ctx context.Context, after uint64, writer io.Writer) error {
	if writer == nil {
		return errors.New("host DNS event stream: writer is required")
	}
	for {
		eventCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		event, err := h.dns.NextEvent(eventCtx, after)
		cancel()
		if errors.Is(err, context.DeadlineExceeded) {
			event = hostdns.Event{Time: time.Now().UTC(), Decision: "heartbeat", Generation: h.network.Generation()}
			err = nil
		}
		if err != nil {
			return err
		}
		data, err := json.Marshal(event)
		if err != nil {
			return err
		}
		if deadlineWriter, ok := writer.(interface{ SetWriteDeadline(time.Time) error }); ok {
			_ = deadlineWriter.SetWriteDeadline(time.Now().Add(5 * time.Second))
		}
		if _, err := writer.Write(append(data, '\n')); err != nil {
			return err
		}
		if event.Sequence > after {
			after = event.Sequence
		}
	}
}

// StreamFirewallEvents forwards bounded, host-observed terminal firewall
// verdicts. This stream is separate from DNS events so setup capture keeps its
// existing DNS-only event format.
func (h *hostNetworkHandle) StreamFirewallEvents(ctx context.Context, after uint64, writer io.Writer) error {
	if writer == nil {
		return errors.New("host firewall event stream: writer is required")
	}
	for {
		event, err := h.network.NextFirewallEvent(ctx, after)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		data, err := json.Marshal(event)
		if err != nil {
			return err
		}
		if deadlineWriter, ok := writer.(interface{ SetWriteDeadline(time.Time) error }); ok {
			_ = deadlineWriter.SetWriteDeadline(time.Now().Add(5 * time.Second))
		}
		if _, err := writer.Write(append(data, '\n')); err != nil {
			return err
		}
		if event.Sequence > after {
			after = event.Sequence
		}
	}
}

// streamHostNetworkDomainEvents is the CLI/capture client for the private
// same-user control socket. It writes validated broker events as JSONL.
func streamHostNetworkDomainEvents(ctx context.Context, runtimeDir, launchID string, after uint64, writer io.Writer) error {
	return streamHostNetworkDomainEventsReady(ctx, runtimeDir, launchID, after, writer, nil)
}

func streamHostNetworkDomainEventsReady(ctx context.Context, runtimeDir, launchID string, after uint64, writer io.Writer, ready func()) error {
	if !filepath.IsAbs(runtimeDir) || launchID == "" || writer == nil {
		return errors.New("host DNS event stream: invalid runtime identity or writer")
	}
	path := filepath.Join(runtimeDir, hostNetworkControlSocketName)
	if len(path) > 107 {
		return errors.New("host DNS event stream: control socket path exceeds Linux limit")
	}
	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", path)
	if err != nil {
		return fmt.Errorf("connect to host DNS event stream: %w", err)
	}
	defer conn.Close()
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClose()
	request := hostNetworkControlRequest{LaunchID: launchID, Operation: "domain-log", AfterSequence: after}
	data, err := json.Marshal(request)
	if err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := conn.Write(append(data, '\n')); err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Time{})
	if ready != nil {
		ready()
	}
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 4096), 64<<10)
	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)
		var event hostdns.Event
		if err := json.Unmarshal(line, &event); err != nil {
			return fmt.Errorf("decode host DNS event: %w", err)
		}
		if event.Decision == "heartbeat" {
			continue
		}
		if _, err := writer.Write(append(line, '\n')); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("read host DNS event stream: %w", err)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errors.New("host DNS event stream ended unexpectedly")
}

// streamHostNetworkFirewallEvents is the interactive CLI client for packet
// verdict events. It deliberately uses a separate control operation and event
// type from the DNS stream, which remains shared with setup capture.
func streamHostNetworkFirewallEvents(ctx context.Context, runtimeDir, launchID string, after uint64, writer io.Writer) error {
	if !filepath.IsAbs(runtimeDir) || launchID == "" || writer == nil {
		return errors.New("host firewall event stream: invalid runtime identity or writer")
	}
	path := filepath.Join(runtimeDir, hostNetworkControlSocketName)
	if len(path) > 107 {
		return errors.New("host firewall event stream: control socket path exceeds Linux limit")
	}
	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", path)
	if err != nil {
		return fmt.Errorf("connect to host firewall event stream: %w", err)
	}
	defer conn.Close()
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClose()
	request := hostNetworkControlRequest{LaunchID: launchID, Operation: "firewall-log", AfterSequence: after}
	data, err := json.Marshal(request)
	if err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := conn.Write(append(data, '\n')); err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Time{})
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 4096), 64<<10)
	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)
		var event hostnet.FirewallEvent
		if err := json.Unmarshal(line, &event); err != nil {
			return fmt.Errorf("decode host firewall event: %w", err)
		}
		if event.Decision == "" && !event.Gap {
			var response hostNetworkControlResponse
			if err := json.Unmarshal(line, &response); err == nil {
				if response.Error == "unknown host network control operation" {
					return errors.New("firewall packet log requires a VM supervisor that supports firewall events; stop and restart the VM with this version")
				}
				if response.Error != "" {
					return fmt.Errorf("host firewall event stream: %s", response.Error)
				}
				if response.Streaming {
					continue
				}
			}
			return errors.New("host firewall event stream: invalid event")
		}
		if event.Decision == "heartbeat" {
			continue
		}
		if _, err := writer.Write(append(line, '\n')); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("read host firewall event stream: %w", err)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errors.New("host firewall event stream ended unexpectedly")
}
