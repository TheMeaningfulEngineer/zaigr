package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"zaigr/cmd/zaigr/hostdns"
	"zaigr/cmd/zaigr/hostnet"
)

func cmdProjectFirewallDomainLog(verbose, history bool) error {
	startedAt := time.Now()
	lock, err := lockCurrentProject("project firewall domain-log")
	if err != nil {
		return err
	}
	defer lock.releaseWithWarning()
	store := currentProjectStore()
	if _, err := requireProject("project firewall domain-log"); err != nil {
		return err
	}
	running, stale := detectRunningProjectVM()
	if stale {
		if err := store.clearRuntimeState(); err != nil {
			return err
		}
		return fmt.Errorf("project VM is not running; start it with 'zaigr project vm start' or 'zaigr shell'")
	}
	if running == nil {
		return fmt.Errorf("project VM is not running; start it with 'zaigr project vm start' or 'zaigr shell'")
	}
	host, record, err := runningHostNetworkRecord(store)
	if err != nil {
		return err
	}
	if !host {
		return fmt.Errorf("project VM uses the legacy guest firewall; stop it and start it again to migrate")
	}
	if err := lock.release(); err != nil {
		return fmt.Errorf("release project operation lock: %w", err)
	}
	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithCancel(signalCtx)
	defer cancel()
	output := &domainLogOutput{stdout: os.Stdout, stderr: os.Stderr}
	if _, err := fmt.Fprintln(output.stderr, "Firewall packet events coalesce repeated identical decisions for about 2 seconds; allowed/blocked records are packet verdicts, not proof of connection or application success."); err != nil {
		return fmt.Errorf("write firewall event notice: %w", err)
	}
	results := make(chan domainLogStreamResult, 2)
	go func() {
		writer := domainNameLogWriter{output: output, verbose: verbose, recent: make(map[string]dnsLogDecision)}
		results <- domainLogStreamResult{name: "DNS", err: streamHostNetworkDomainEvents(ctx, store.runtimeDir(), record.LaunchID, 0, newDomainLogHistoryFilter(&writer, history, startedAt))}
	}()
	go func() {
		writer := firewallEventLogWriter{output: output}
		results <- domainLogStreamResult{name: "firewall", err: streamHostNetworkFirewallEvents(ctx, store.runtimeDir(), record.LaunchID, 0, newDomainLogHistoryFilter(&writer, history, startedAt))}
	}()
	select {
	case <-signalCtx.Done():
		// The stream readers close their control sockets through the contexts.
		// Do not wait on a writer blocked by a slow terminal consumer.
		cancel()
		return nil
	case result := <-results:
		if signalCtx.Err() != nil {
			cancel()
			return nil
		}
		cancel()
		if result.err == nil {
			return fmt.Errorf("host %s event stream ended unexpectedly", result.name)
		}
		return fmt.Errorf("host %s event stream failed: %w", result.name, result.err)
	}
}

// domainLogHistoryFilter hides events the host recorded before the command
// started, so the log follows only new traffic unless --history is given.
// Both host streams replay their whole buffer to a reader starting at
// sequence zero; a gap reported during that replay only means older history
// was lost, so it is hidden too.
type domainLogHistoryFilter struct {
	next      io.Writer
	startedAt time.Time
	live      bool
}

func newDomainLogHistoryFilter(next io.Writer, history bool, startedAt time.Time) io.Writer {
	if history {
		return next
	}
	return &domainLogHistoryFilter{next: next, startedAt: startedAt}
}

func (f *domainLogHistoryFilter) Write(line []byte) (int, error) {
	if !f.live {
		var event struct {
			Time time.Time
			Gap  bool
		}
		if err := json.Unmarshal(line, &event); err != nil {
			return 0, fmt.Errorf("decode host event time: %w", err)
		}
		if event.Gap || event.Time.Before(f.startedAt) {
			return len(line), nil
		}
		f.live = true
	}
	return f.next.Write(line)
}

type domainLogStreamResult struct {
	name string
	err  error
}

// domainLogOutput serializes the DNS and firewall streams so concurrent host
// events remain complete, human-readable lines on the public CLI.
type domainLogOutput struct {
	stdout io.Writer
	stderr io.Writer
	mu     sync.Mutex
}

// domainNameLogWriter keeps the CLI's public DNS stream human-readable while
// the shared event stream remains structured for setup capture and callers.
type domainNameLogWriter struct {
	output  *domainLogOutput
	verbose bool
	recent  map[string]dnsLogDecision
}

const (
	dnsLogDedupWindow = 2 * time.Second
	dnsLogDedupLimit  = 4096
)

type dnsLogDecision struct {
	status    string
	emittedAt time.Time
}

func (w *domainNameLogWriter) Write(line []byte) (int, error) {
	var event hostdns.Event
	if err := json.Unmarshal(line, &event); err != nil {
		return 0, fmt.Errorf("decode host DNS event: %w", err)
	}
	if event.Gap {
		w.recent = make(map[string]dnsLogDecision)
		w.output.mu.Lock()
		defer w.output.mu.Unlock()
		if _, err := fmt.Fprintln(w.output.stderr, "warning: domain log history gap; some domain names may be missing"); err != nil {
			return 0, err
		}
		return len(line), nil
	}
	name := strings.ToLower(strings.TrimSuffix(event.Name, "."))
	if name == "" {
		return len(line), nil
	}
	status, reason := describeDNSOutcome(event)
	text := fmt.Sprintf("DNS %-8s %s", status, name)
	if w.verbose {
		queryType := event.QueryType
		if queryType == "" {
			queryType = "unknown query type"
		}
		text += " (" + queryType + ")"
	} else if w.shouldSuppress(name, status, event.Time) {
		return len(line), nil
	}
	if reason != "" {
		text += " (" + reason + ")"
	}
	w.output.mu.Lock()
	defer w.output.mu.Unlock()
	if _, err := fmt.Fprintln(w.output.stdout, text); err != nil {
		return 0, err
	}
	return len(line), nil
}

func (w *domainNameLogWriter) shouldSuppress(name, status string, eventTime time.Time) bool {
	if eventTime.IsZero() {
		eventTime = time.Now()
	}
	for recentName, recent := range w.recent {
		if eventTime.Sub(recent.emittedAt) >= dnsLogDedupWindow {
			delete(w.recent, recentName)
		}
	}
	if recent, ok := w.recent[name]; ok && recent.status == status &&
		eventTime.Sub(recent.emittedAt) >= 0 && eventTime.Sub(recent.emittedAt) < dnsLogDedupWindow {
		return true
	}
	if len(w.recent) >= dnsLogDedupLimit {
		oldestName := ""
		var oldest time.Time
		for recentName, recent := range w.recent {
			if oldestName == "" || recent.emittedAt.Before(oldest) {
				oldestName = recentName
				oldest = recent.emittedAt
			}
		}
		delete(w.recent, oldestName)
	}
	w.recent[name] = dnsLogDecision{status: status, emittedAt: eventTime}
	return false
}

type firewallEventLogWriter struct {
	output *domainLogOutput
}

func (w *firewallEventLogWriter) Write(line []byte) (int, error) {
	var event hostnet.FirewallEvent
	if err := json.Unmarshal(line, &event); err != nil {
		return 0, fmt.Errorf("decode host firewall event: %w", err)
	}
	w.output.mu.Lock()
	defer w.output.mu.Unlock()
	if event.Gap {
		message := "warning: firewall event history gap; some packet decisions may be missing"
		if event.Dropped > 0 {
			message += fmt.Sprintf(" (%d events dropped)", event.Dropped)
		}
		if event.Reason != "" {
			message += " (" + event.Reason + ")"
		}
		if _, err := fmt.Fprintln(w.output.stderr, message); err != nil {
			return 0, err
		}
		return len(line), nil
	}
	protocol := strings.ToUpper(event.Protocol)
	status := event.Decision
	if status != "blocked" && status != "allowed" {
		status = "unknown"
	}
	var text string
	if protocol == "TCP" || protocol == "UDP" {
		source := event.Source.String()
		destination := event.Destination.String()
		if !event.Source.IsValid() {
			source = "unknown"
		}
		if !event.Destination.IsValid() {
			destination = "unknown"
		}
		if event.PortsAvailable && event.Source.IsValid() && event.Destination.IsValid() {
			source = netip.AddrPortFrom(event.Source, event.SourcePort).String()
			destination = netip.AddrPortFrom(event.Destination, event.DestinationPort).String()
			text = fmt.Sprintf("FIREWALL %s %s %s -> %s", status, protocol, source, destination)
		} else {
			text = fmt.Sprintf("FIREWALL %s %s %s -> %s (ports unavailable)",
				status, protocol, source, destination)
		}
	} else {
		text = fmt.Sprintf("FIREWALL %s %s %s -> %s", status, protocol,
			event.Source, event.Destination)
	}
	if _, err := fmt.Fprintln(w.output.stdout, text); err != nil {
		return 0, err
	}
	return len(line), nil
}

func describeDNSOutcome(event hostdns.Event) (status, reason string) {
	switch event.Decision {
	case "refused":
		return "blocked", ""
	case "nodata":
		return "allowed", "IPv6 DNS answers are disabled"
	case "resolved", "full-network-resolved", "discovery-resolved":
		if len(event.Addresses) == 0 {
			return "allowed", "no address returned"
		}
		return "allowed", ""
	case "nxdomain":
		return "failed", "domain not found"
	case "unsupported-type":
		return "failed", "unsupported query type"
	case "upstream-failed":
		return "failed", "upstream lookup failed"
	case "servfail":
		return "failed", "DNS server failure"
	case "unsafe-answer":
		return "blocked", "answer rejected by host policy"
	case "discovery-expired", "full-network-expired":
		return "blocked", "temporary access expired"
	case "lease-failed":
		return "failed", "could not authorize resolved addresses"
	case "zero-ttl":
		return "failed", "answer expires immediately"
	default:
		return "unknown", "unknown DNS result"
	}
}
