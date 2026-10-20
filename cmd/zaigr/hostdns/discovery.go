package hostdns

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"
)

var discoveryScopePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{7,127}$`)

// BeginDiscovery opens a host-issued, launch-scoped discovery interval. During
// the interval, valid exact DNS questions outside the saved allowlist may be
// resolved and observed, but their address leases cannot outlive deadline.
// The caller must bind this API to a dedicated capture VM, never an ordinary
// project VM. Discovery does not create persistent names or policy entries.
func (s *Server) BeginDiscovery(ctx context.Context, launchID string, generation uint64, scopeID string, deadline time.Time) error {
	if launchID != s.cfg.LaunchID {
		return errors.New("host DNS discovery: launch identity mismatch")
	}
	if !discoveryScopePattern.MatchString(scopeID) {
		return errors.New("host DNS discovery: invalid host-issued scope ID")
	}
	now := time.Now()
	if !deadline.After(now) || deadline.After(now.Add(time.Hour)) {
		return errors.New("host DNS discovery: deadline must be within the next hour")
	}
	s.commitMu.Lock()
	defer s.commitMu.Unlock()
	if err := s.ctx.Err(); err != nil {
		return fmt.Errorf("host DNS discovery: broker is closing: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed != nil {
		return fmt.Errorf("host DNS discovery: broker is fail-closed: %w", s.failed)
	}
	if generation != s.generation {
		return fmt.Errorf("host DNS discovery: stale generation %d (current %d)", generation, s.generation)
	}
	if s.discoveryScope != "" {
		return errors.New("host DNS discovery: another scoped discovery session is active")
	}
	// Bump the global lookup token before enabling transient discovery. This
	// invalidates any old unknown-name result without risking token reuse.
	s.lookupSequence++
	s.discoveryScope = scopeID
	s.discoveryUntil = deadline
	return nil
}

// EndDiscovery immediately removes leases that were learned only through the
// discovery window and deletes their associated conntrack state through the
// lease backend before returning.
func (s *Server) EndDiscovery(ctx context.Context, launchID string, generation uint64, scopeID string) error {
	if launchID != s.cfg.LaunchID {
		return errors.New("host DNS discovery: launch identity mismatch")
	}
	s.commitMu.Lock()
	defer s.commitMu.Unlock()
	if err := s.ctx.Err(); err != nil {
		return fmt.Errorf("host DNS discovery: broker is closing: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	if generation != s.generation {
		s.mu.Unlock()
		return fmt.Errorf("host DNS discovery: stale generation %d (current %d)", generation, s.generation)
	}
	if s.discoveryScope == "" {
		s.mu.Unlock()
		return nil
	}
	if s.discoveryScope != scopeID {
		s.mu.Unlock()
		return errors.New("host DNS discovery: scope identity mismatch")
	}
	s.discoveryScope = ""
	s.discoveryUntil = time.Time{}
	leases := s.removeDiscoveryNamesLocked(time.Now())
	s.mu.Unlock()
	if err := s.backend.ReplaceDNSLeases(ctx, s.cfg.LaunchID, generation, leases.addresses, leases.names); err != nil {
		s.failClosed(err)
		return fmt.Errorf("host DNS discovery: revoke discovery leases: %w", err)
	}
	return nil
}

func (s *Server) discoveryAllowsLocked(name string, now time.Time) bool {
	if _, ok := s.names[name]; ok {
		return true
	}
	return (s.discoveryScope != "" && s.discoveryUntil.After(now)) || s.fullAccessUntil.After(now)
}

func (s *Server) discoveryDeadlineForLocked(name string, now time.Time) time.Time {
	if _, permanent := s.names[name]; permanent {
		return time.Time{}
	}
	deadline := time.Time{}
	if s.discoveryScope != "" && s.discoveryUntil.After(now) {
		deadline = s.discoveryUntil
	}
	if s.fullAccessUntil.After(now) && s.fullAccessUntil.After(deadline) {
		deadline = s.fullAccessUntil
	}
	return deadline
}

func (s *Server) removeDiscoveryNamesLocked(now time.Time) leaseSnapshot {
	s.lookupSequence++
	for name := range s.active {
		if _, permanent := s.names[name]; permanent {
			continue
		}
		s.lookupEpoch[name]++
		delete(s.active, name)
		delete(s.lookupEpoch, name)
	}
	for name := range s.lookupEpoch {
		if _, permanent := s.names[name]; !permanent {
			delete(s.lookupEpoch, name)
		}
	}
	return s.currentLeaseSnapshotLocked(now)
}

func (s *Server) expireDiscovery(now time.Time) {
	s.commitMu.Lock()
	defer s.commitMu.Unlock()
	if s.ctx.Err() != nil {
		return
	}
	s.mu.Lock()
	if s.discoveryScope == "" || s.discoveryUntil.After(now) {
		s.mu.Unlock()
		return
	}
	s.discoveryScope = ""
	s.discoveryUntil = time.Time{}
	generation := s.generation
	leases := s.removeDiscoveryNamesLocked(now)
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(s.ctx, s.cfg.ResolveTimeout)
	defer cancel()
	if err := s.backend.ReplaceDNSLeases(ctx, s.cfg.LaunchID, generation, leases.addresses, leases.names); err != nil {
		s.failClosed(err)
	}
}
