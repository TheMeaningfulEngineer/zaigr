//go:build linux

package hostnet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

const (
	firewallEventHistory = 4096
	firewallRepeatWindow = 2 * time.Second
)

type firewallEventState struct {
	decision string
	time     time.Time
}

func (r *linuxRuntime) readFirewallEvents(reader *os.File) {
	buf := make([]byte, 8192)
	for {
		n, err := reader.Read(buf)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, os.ErrClosed) {
				r.recordFirewallEvent(FirewallEvent{Gap: true, Reason: "firewall event channel read failed"})
			}
			r.eventMu.Lock()
			if !r.eventClosed {
				r.eventClosed = true
				close(r.eventChanged)
			}
			r.eventMu.Unlock()
			return
		}
		if n == 0 {
			r.eventMu.Lock()
			if !r.eventClosed {
				r.eventClosed = true
				close(r.eventChanged)
			}
			r.eventMu.Unlock()
			return
		}
		var event FirewallEvent
		if err := json.Unmarshal(buf[:n], &event); err != nil {
			r.recordFirewallEvent(FirewallEvent{Gap: true, Reason: "invalid firewall event from namespace helper"})
			continue
		}
		r.recordFirewallEvent(event)
	}
}

func (r *linuxRuntime) recordFirewallEvent(event FirewallEvent) {
	now := time.Now().UTC()
	if event.Time.IsZero() {
		event.Time = now
	}
	r.eventMu.Lock()
	defer r.eventMu.Unlock()
	if r.eventClosed {
		return
	}
	if !event.Gap {
		if !event.Source.IsValid() || !event.Destination.IsValid() || event.Decision != "allowed" && event.Decision != "blocked" {
			return
		}
		key := firewallTupleKey(event)
		for tuple, last := range r.recentEvents {
			if now.Sub(last.time) > firewallRepeatWindow {
				delete(r.recentEvents, tuple)
			}
		}
		if last, ok := r.recentEvents[key]; ok && last.decision == event.Decision && now.Sub(last.time) <= firewallRepeatWindow {
			r.recentEvents[key] = firewallEventState{decision: event.Decision, time: now}
			return
		}
		r.recentEvents[key] = firewallEventState{decision: event.Decision, time: now}
		if len(r.recentEvents) > firewallEventHistory {
			var oldestKey string
			var oldest time.Time
			for tuple, state := range r.recentEvents {
				if oldest.IsZero() || state.time.Before(oldest) {
					oldestKey, oldest = tuple, state.time
				}
			}
			delete(r.recentEvents, oldestKey)
		}
	}
	r.eventSequence++
	event.Sequence = r.eventSequence
	if len(r.events) == firewallEventHistory {
		copy(r.events, r.events[1:])
		r.events[len(r.events)-1] = event
	} else {
		r.events = append(r.events, event)
	}
	close(r.eventChanged)
	r.eventChanged = make(chan struct{})
}

func firewallTupleKey(event FirewallEvent) string {
	return fmt.Sprintf("%s|%d|%s|%d|%t|%s", event.Source, event.SourcePort, event.Destination, event.DestinationPort, event.PortsAvailable, event.Protocol)
}

func (r *linuxRuntime) NextFirewallEvent(ctx context.Context, sequence uint64) (FirewallEvent, error) {
	for {
		r.eventMu.Lock()
		if len(r.events) > 0 {
			first := r.events[0].Sequence
			if sequence+1 < first {
				gap := FirewallEvent{Sequence: first - 1, Time: time.Now().UTC(), Gap: true, Dropped: first - sequence - 1, Reason: "firewall event history wrapped"}
				r.eventMu.Unlock()
				return gap, nil
			}
			for _, event := range r.events {
				if event.Sequence > sequence {
					r.eventMu.Unlock()
					return event, nil
				}
			}
		}
		if r.eventClosed {
			r.eventMu.Unlock()
			return FirewallEvent{}, errors.New("host firewall event stream is closed")
		}
		changed := r.eventChanged
		r.eventMu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return FirewallEvent{}, ctx.Err()
		}
	}
}
