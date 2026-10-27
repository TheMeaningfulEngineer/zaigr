package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"zaigr/cmd/zaigr/hostdns"
	"zaigr/cmd/zaigr/hostnet"
)

const hostNetworkControlSocketName = "host-network-control.sock"

// hostNetworkHandle ties the network namespace, DNS broker/frontend, policy
// coordinator, and host control socket to one VM launch. Its methods are the
// only supported live mutation path once the VM has started.
type hostNetworkHandle struct {
	ctx                 context.Context
	cancel              context.CancelFunc
	store               projectStore
	runtimeDir          string
	network             hostnet.Runtime
	dns                 *hostdns.Server
	frontend            *exec.Cmd
	udp                 *os.File
	tcp                 *os.File
	control             *net.UnixListener
	controlWG           sync.WaitGroup
	controlSlots        chan struct{}
	updateMu            sync.Mutex
	closeOnce           sync.Once
	closeErr            error
	fatal               chan error
	childExits          chan hostnet.ChildExit
	frontendDone        chan error
	frontendIdentity    hostnet.ProcessIdentity
	checkFailures       chan hostNetworkCheckFailure
	asyncCheckFailed    atomic.Bool
	policyNames         []string
	policyGrants        []netip.Addr
	hostExclusions      []netip.Prefix
	policyScopes        map[string]hostNetworkPolicyScope
	fullAccessLeases    map[string]time.Time
	maintenanceSessions map[string]maintenanceSessionRecord
	fullAccessLive      bool
	networkLiveUntil    time.Time
	discoveryScope      string
	recordUpdater       func(uint64) error
}

type hostNetworkPolicyScope struct {
	Names []string
	IPs   []netip.Addr
}

type hostNetworkStatus struct {
	LaunchID            string                             `json:"launch_id"`
	Generation          uint64                             `json:"generation"`
	EventSequence       uint64                             `json:"event_sequence"`
	Processes           map[string]hostnet.ProcessIdentity `json:"processes"`
	Forwards            []hostnet.Forward                  `json:"forwards"`
	FullNetworkSessions int                                `json:"full_network_sessions"`
	MaintenanceSessions int                                `json:"maintenance_sessions"`
}

type maintenanceSessionRecord struct {
	session  hostnet.MaintenanceSession
	deadline time.Time
}

type hostNetworkCheckFailure struct {
	step string
	err  error
}

// startHostNetworkRuntime performs the complete host-owned network bootstrap.
// It returns only after the frontend has validated its inherited sockets,
// dropped every capability, set no_new_privs, and been authorized by the
// broker. The caller must not boot the guest before this succeeds.
func startHostNetworkRuntime(ctx context.Context, opts hostnet.Options, store projectStore, names []string, generation uint64) (_ *hostNetworkHandle, retErr error) {
	if opts.LaunchID == "" || opts.RuntimeDir == "" || store.Path == "" {
		return nil, errors.New("host network: launch ID, runtime directory, and project store are required")
	}
	trustedNames, trustedGeneration, trustedGrants, err := loadHostNetworkInitialPolicy(store)
	if err != nil {
		return nil, fmt.Errorf("load initial host network policy: %w", err)
	}
	if generation != 0 && generation != trustedGeneration {
		return nil, fmt.Errorf("host network: requested initial generation %d differs from saved policy generation %d", generation, trustedGeneration)
	}
	if opts.InitialGeneration != 0 && opts.InitialGeneration != trustedGeneration {
		return nil, fmt.Errorf("host network: requested initial generation %d differs from saved policy generation %d", opts.InitialGeneration, trustedGeneration)
	}
	// Never accept caller-supplied policy contents at the launch boundary.
	names, generation, opts.InitialIPGrants = trustedNames, trustedGeneration, trustedGrants
	opts.InitialGeneration = generation
	hostRuntime, err := hostnet.Start(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("start host network: %w", err)
	}
	if hostRuntime.Generation() != generation {
		_ = hostRuntime.Stop(context.Background())
		return nil, fmt.Errorf("host network: runtime started at generation %d, expected %d", hostRuntime.Generation(), generation)
	}
	initialLeaseDeadline := time.Now().Add(fullNetworkOwnerTTL)
	leaseCtx, leaseCancel := context.WithTimeout(ctx, 4*time.Second)
	leaseErr := hostRuntime.SetNetworkLease(leaseCtx, hostRuntime.LaunchID(), initialLeaseDeadline)
	leaseCancel()
	if leaseErr != nil {
		_ = hostRuntime.Stop(context.Background())
		return nil, fmt.Errorf("initialize fail-closed network liveness lease: %w", leaseErr)
	}
	exclusions, err := hostDNSExcludedPrefixes()
	if err != nil {
		_ = hostRuntime.Stop(context.Background())
		return nil, err
	}
	ownedCtx, cancel := context.WithCancel(ctx)
	h := &hostNetworkHandle{ctx: ownedCtx, cancel: cancel, store: store, runtimeDir: opts.RuntimeDir, network: hostRuntime, hostExclusions: exclusions, networkLiveUntil: initialLeaseDeadline, fatal: make(chan error, 1), childExits: make(chan hostnet.ChildExit, 4), frontendDone: make(chan error, 1), checkFailures: make(chan hostNetworkCheckFailure, 8), controlSlots: make(chan struct{}, 32), policyNames: append([]string(nil), trustedNames...), policyGrants: append([]netip.Addr(nil), trustedGrants...), policyScopes: make(map[string]hostNetworkPolicyScope), fullAccessLeases: make(map[string]time.Time), maintenanceSessions: make(map[string]maintenanceSessionRecord)}
	defer func() {
		if retErr != nil {
			_ = h.Close(context.Background())
		}
	}()
	udp, tcp := hostRuntime.TakeDNSSockets()
	if udp == nil || tcp == nil {
		if udp != nil {
			_ = udp.Close()
		}
		if tcp != nil {
			_ = tcp.Close()
		}
		return nil, errors.New("host network: runtime did not provide bound guest DNS sockets")
	}
	h.udp, h.tcp = udp, tcp
	broker, err := startHostDNSBroker(ownedCtx, hostRuntime, opts.RuntimeDir, names, generation, exclusions)
	if err != nil {
		return nil, err
	}
	h.dns = broker
	executable, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("locate host DNS frontend executable: %w", err)
	}
	cmd, readyRead, readyWrite, err := buildCaplessHostDNSFrontend(ownedCtx, executable, filepath.Join(opts.RuntimeDir, "dns.sock"), udp, tcp)
	if err != nil {
		return nil, err
	}
	if err = cmd.Start(); err != nil {
		_ = readyRead.Close()
		_ = readyWrite.Close()
		return nil, fmt.Errorf("start capless host DNS frontend: %w", err)
	}
	h.frontend = cmd
	go h.waitFrontend(cmd)
	_ = readyWrite.Close()
	if err = awaitCaplessHostDNSFrontend(ownedCtx, broker, cmd, readyRead); err != nil {
		_ = cmd.Process.Kill()
		return nil, err
	}
	frontendIdentity, err := inspectFrontendIdentity(cmd.Process.Pid)
	if err != nil {
		_ = cmd.Process.Kill()
		return nil, err
	}
	h.frontendIdentity = hostnet.ProcessIdentity{PID: cmd.Process.Pid, StartTime: fmt.Sprint(frontendIdentity.startTime)}
	if err = h.startControlServer(); err != nil {
		return nil, err
	}
	go h.watchFatal()
	go h.fullNetworkLeaseLoop()
	return h, nil
}

const fullNetworkOwnerTTL = 10 * time.Second

func (h *hostNetworkHandle) acquireFullNetworkLease(ctx context.Context, leaseID string, deadline time.Time) error {
	return h.updateFullNetworkLease(ctx, leaseID, "acquire", deadline)
}

func (h *hostNetworkHandle) renewFullNetworkLease(ctx context.Context, leaseID string, deadline time.Time) error {
	return h.updateFullNetworkLease(ctx, leaseID, "renew", deadline)
}

func (h *hostNetworkHandle) releaseFullNetworkLease(ctx context.Context, leaseID string) error {
	return h.updateFullNetworkLease(ctx, leaseID, "release", time.Time{})
}

func (h *hostNetworkHandle) startMaintenanceSession(ctx context.Context, sessionID string, deadline time.Time) (hostnet.MaintenanceSession, error) {
	h.updateMu.Lock()
	defer h.updateMu.Unlock()
	if err := h.checkOperation(ctx); err != nil {
		return hostnet.MaintenanceSession{}, err
	}
	if !validHostPolicyScopeID(sessionID) {
		return hostnet.MaintenanceSession{}, errors.New("invalid maintenance session identity")
	}
	if _, exists := h.maintenanceSessions[sessionID]; exists {
		return hostnet.MaintenanceSession{}, errors.New("maintenance session ID is already used")
	}
	if !deadline.After(time.Now()) || deadline.After(time.Now().Add(fullNetworkOwnerTTL)) {
		return hostnet.MaintenanceSession{}, errors.New("maintenance session deadline is outside the owner lease bound")
	}
	session, err := h.network.StartMaintenanceSession(ctx, h.network.LaunchID(), sessionID, deadline)
	if err != nil {
		return hostnet.MaintenanceSession{}, err
	}
	if err := h.dns.SetMaintenanceAccess(ctx, h.network.LaunchID(), h.network.Generation(), session.GuestAddress, sessionID, deadline); err != nil {
		_ = h.network.StopMaintenanceSession(context.Background(), h.network.LaunchID(), sessionID)
		return hostnet.MaintenanceSession{}, err
	}
	h.maintenanceSessions[sessionID] = maintenanceSessionRecord{session: session, deadline: deadline}
	return session, nil
}

func (h *hostNetworkHandle) renewMaintenanceSession(ctx context.Context, sessionID string, deadline time.Time) error {
	h.updateMu.Lock()
	defer h.updateMu.Unlock()
	if err := h.checkOperation(ctx); err != nil {
		return err
	}
	previous, exists := h.maintenanceSessions[sessionID]
	if !exists || !previous.deadline.After(time.Now()) {
		return errors.New("maintenance session expired and cannot be renewed")
	}
	if !deadline.After(time.Now()) || deadline.After(time.Now().Add(fullNetworkOwnerTTL)) {
		return errors.New("maintenance session deadline is outside the owner lease bound")
	}
	if err := h.network.RenewMaintenanceSession(ctx, h.network.LaunchID(), sessionID, deadline); err != nil {
		return err
	}
	if err := h.dns.SetMaintenanceAccess(ctx, h.network.LaunchID(), h.network.Generation(), previous.session.GuestAddress, sessionID, deadline); err != nil {
		return err
	}
	previous.deadline = deadline
	h.maintenanceSessions[sessionID] = previous
	return nil
}

func (h *hostNetworkHandle) stopMaintenanceSession(ctx context.Context, sessionID string) error {
	h.updateMu.Lock()
	defer h.updateMu.Unlock()
	if err := h.checkOperation(ctx); err != nil {
		return err
	}
	if _, exists := h.maintenanceSessions[sessionID]; !exists {
		return nil
	}
	record := h.maintenanceSessions[sessionID]
	networkErr := h.network.StopMaintenanceSession(ctx, h.network.LaunchID(), sessionID)
	dnsErr := h.dns.ClearMaintenanceAccess(ctx, h.network.LaunchID(), h.network.Generation(), record.session.GuestAddress, sessionID)
	cleanupErr := errors.Join(networkErr, dnsErr)
	if cleanupErr != nil {
		// A stop request is terminal for renewal, but retain the host-side
		// record so the expiry reaper can retry failed helper/DNS cleanup. The
		// zero deadline makes this session immediately eligible for reaping and
		// keeps it out of public active-session counts.
		record.deadline = time.Time{}
		h.maintenanceSessions[sessionID] = record
		return cleanupErr
	}
	delete(h.maintenanceSessions, sessionID)
	return nil
}

func (h *hostNetworkHandle) updateFullNetworkLease(ctx context.Context, leaseID, operation string, deadline time.Time) error {
	h.updateMu.Lock()
	defer h.updateMu.Unlock()
	if err := h.checkOperation(ctx); err != nil {
		return err
	}
	if !validHostPolicyScopeID(leaseID) {
		return errors.New("host network: invalid full-network lease ID")
	}
	now := time.Now()
	if operation == "acquire" || operation == "renew" {
		if !deadline.After(now) {
			return errors.New("host network: full-network owner deadline has expired")
		}
		if deadline.After(now.Add(fullNetworkOwnerTTL)) {
			return errors.New("host network: full-network owner deadline exceeds lease bound")
		}
	}
	if _, exists := h.fullAccessLeases[leaseID]; operation == "acquire" && exists {
		return errors.New("host network: full-network lease ID is already active")
	} else if operation == "renew" && (!exists || !h.fullAccessLeases[leaseID].After(now)) {
		delete(h.fullAccessLeases, leaseID)
		return errors.New("host network: full-network lease is no longer active")
	}
	switch operation {
	case "acquire", "renew":
		h.fullAccessLeases[leaseID] = deadline
	case "release":
		delete(h.fullAccessLeases, leaseID)
	default:
		return errors.New("host network: unsupported full-network lease operation")
	}
	active := len(h.fullAccessLeases) > 0
	if active != h.fullAccessLive || active {
		applyCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		deadline := h.latestFullAccessDeadlineLocked(now)
		err := h.dns.SetFullNetworkAccess(applyCtx, h.network.LaunchID(), h.network.Generation(), deadline)
		if err == nil {
			err = h.network.SetFullNetworkLease(applyCtx, h.network.LaunchID(), deadline)
		}
		cancel()
		if err != nil {
			if operation == "acquire" || operation == "renew" {
				delete(h.fullAccessLeases, leaseID)
			}
			h.reportFatal(fmt.Errorf("apply full-network host lease: %w", err))
			return err
		}
		h.fullAccessLive = active
	}
	return nil
}

func (h *hostNetworkHandle) fullNetworkLeaseLoop() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	var failureSince time.Time
	var failureDeadline time.Time
	lastFailure := ""
	var failureTimer *time.Timer
	var asyncFailure string
	defer func() {
		if failureTimer != nil {
			failureTimer.Stop()
		}
	}()
	failed := func(step string, err error) bool {
		if failureSince.IsZero() {
			failureSince = time.Now()
			failureDeadline = failureSince.Add(60 * time.Second)
			timedOutCheck := step
			failureTimer = time.AfterFunc(time.Until(failureDeadline), func() {
				h.reportFatal(fmt.Errorf("host network checks failed for 60 s: %s", timedOutCheck))
			})
		}
		lastFailure = step
		logWarn("host network check failed; retrying", "check", step, "error", err, "failed_for", time.Since(failureSince).Round(time.Second))
		if !time.Now().Before(failureDeadline) {
			h.reportFatal(fmt.Errorf("host network checks failed for 60 s: %s: %w", lastFailure, err))
			return true
		}
		return false
	}
	for {
		select {
		case <-h.ctx.Done():
			return
		case issue := <-h.checkFailures:
			h.asyncCheckFailed.Store(true)
			asyncFailure = issue.step
			if failed(issue.step, issue.err) {
				return
			}
		case <-ticker.C:
			if h.asyncCheckFailed.Load() {
				if asyncFailure == "" {
					asyncFailure = "reconcile host DNS policy"
				}
				if failed(asyncFailure, errors.New("host DNS policy worker reported a terminal reconciliation failure")) {
					return
				}
				continue
			}
			policyCtx, policyCancel := context.WithTimeout(h.ctx, 4*time.Second)
			policyErr := h.applySavedPolicy(policyCtx, false)
			policyCancel()
			if policyErr != nil {
				if failed("reconcile saved host policy", policyErr) {
					return
				}
				continue
			}
			currentExclusions, inventoryErr := hostDNSExcludedPrefixes()
			if inventoryErr != nil {
				if failed("inspect host network topology", inventoryErr) {
					return
				}
				continue
			}
			if !equalHostDNSPrefixes(currentExclusions, h.hostExclusions) {
				h.reportFatal(errors.New("host network topology changed: host interface/address/route inventory changed; stop and restart the VM to recompute host exclusions"))
				return
			}
			now := time.Now()
			h.updateMu.Lock()
			if err, childDied := h.checkChildLiveness(); err != nil {
				h.updateMu.Unlock()
				if childDied {
					h.reportFatal(err)
					return
				}
				if failed("check host network child liveness", err) {
					return
				}
				continue
			}
			for id, deadline := range h.fullAccessLeases {
				if !deadline.After(now) {
					delete(h.fullAccessLeases, id)
				}
			}
			var cycleErr error
			cycleStep := ""
			for id, record := range h.maintenanceSessions {
				if record.deadline.After(now) {
					continue
				}
				cleanupCtx, cleanupCancel := context.WithTimeout(h.ctx, 5*time.Second)
				networkErr := h.network.StopMaintenanceSession(cleanupCtx, h.network.LaunchID(), id)
				dnsErr := h.dns.ClearMaintenanceAccess(cleanupCtx, h.network.LaunchID(), h.network.Generation(), record.session.GuestAddress, id)
				cleanupCancel()
				if err := errors.Join(networkErr, dnsErr); err != nil {
					cycleStep = "reap expired maintenance session"
					cycleErr = fmt.Errorf("%s: %w", id, err)
					break
				}
				delete(h.maintenanceSessions, id)
			}
			if cycleErr != nil {
				h.updateMu.Unlock()
				if failed(cycleStep, cycleErr) {
					return
				}
				continue
			}
			active := len(h.fullAccessLeases) > 0
			if active != h.fullAccessLive || active {
				ctx, cancel := context.WithTimeout(h.ctx, 4*time.Second)
				deadline := h.latestFullAccessDeadlineLocked(time.Now())
				err := h.dns.SetFullNetworkAccess(ctx, h.network.LaunchID(), h.network.Generation(), deadline)
				if err == nil {
					err = h.network.SetFullNetworkLease(ctx, h.network.LaunchID(), deadline)
				}
				cancel()
				if err != nil {
					h.updateMu.Unlock()
					if failed("renew full-network host lease", err) {
						return
					}
					continue
				} else {
					h.fullAccessLive = active
				}
			}
			select {
			case issue := <-h.checkFailures:
				h.asyncCheckFailed.Store(true)
				asyncFailure = issue.step
				h.updateMu.Unlock()
				if failed(issue.step, issue.err) {
					return
				}
				continue
			default:
			}
			if h.asyncCheckFailed.Load() {
				h.updateMu.Unlock()
				if failed("reconcile host DNS policy", errors.New("host DNS policy worker reported a terminal reconciliation failure")) {
					return
				}
				continue
			}
			networkCtx, networkCancel := context.WithTimeout(h.ctx, 4*time.Second)
			networkDeadline := time.Now().Add(fullNetworkOwnerTTL)
			networkErr := h.network.SetNetworkLease(networkCtx, h.network.LaunchID(), networkDeadline)
			networkCancel()
			if networkErr != nil {
				h.updateMu.Unlock()
				if failed("renew host network liveness gate", networkErr) {
					return
				}
				continue
			}
			h.networkLiveUntil = networkDeadline
			h.updateMu.Unlock()
			select {
			case issue := <-h.checkFailures:
				h.asyncCheckFailed.Store(true)
				asyncFailure = issue.step
				if failed(issue.step, issue.err) {
					return
				}
			default:
				if asyncFailure == "" && !h.asyncCheckFailed.Load() {
					if !failureDeadline.IsZero() && !time.Now().Before(failureDeadline) {
						h.reportFatal(fmt.Errorf("host network checks failed for 60 s: %s", lastFailure))
						return
					}
					if failureTimer != nil {
						failureTimer.Stop()
						failureTimer = nil
					}
					failureSince = time.Time{}
					failureDeadline = time.Time{}
					lastFailure = ""
				}
			}
		}
	}
}

func equalHostDNSPrefixes(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (h *hostNetworkHandle) latestFullAccessDeadlineLocked(now time.Time) time.Time {
	var latest time.Time
	for _, deadline := range h.fullAccessLeases {
		if deadline.After(now) && deadline.After(latest) {
			latest = deadline
		}
	}
	if latest.IsZero() {
		return time.Time{}
	}
	kernelDeadline := now.Add(fullNetworkOwnerTTL)
	if kernelDeadline.Before(latest) {
		return kernelDeadline
	}
	return latest
}

func (h *hostNetworkHandle) checkChildLiveness() (error, bool) {
	identities := h.network.Processes()
	if h.frontendIdentity.PID > 0 {
		identities["host-dns-frontend"] = hostnet.ProcessIdentity{PID: h.frontendIdentity.PID, StartTime: fmt.Sprint(h.frontendIdentity.StartTime)}
	}
	for name, identity := range identities {
		state, start, _, err := readQemuProcessState(identity.PID)
		if err != nil {
			wrapped := fmt.Errorf("host network child %s liveness check failed: %w", name, err)
			return wrapped, errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH)
		}
		expected, parseErr := strconv.ParseUint(identity.StartTime, 10, 64)
		if parseErr != nil || expected != start {
			if parseErr != nil {
				return fmt.Errorf("host network child %s process identity check failed: %w", name, parseErr), false
			}
			return fmt.Errorf("host network child %s process identity changed", name), true
		}
		if state == 'Z' || state == 'X' {
			return fmt.Errorf("host network child %s is exiting", name), true
		}
	}
	return nil, false
}

func (h *hostNetworkHandle) Network() hostnet.Runtime { return h.network }
func (h *hostNetworkHandle) TakeTapFile() *os.File    { return h.network.TakeTapFile() }
func (h *hostNetworkHandle) TakeMaintenanceTapFile() *os.File {
	return h.network.TakeMaintenanceTapFile()
}
func (h *hostNetworkHandle) TakeSupervisorExitWriter() *os.File {
	return h.network.TakeSupervisorExitWriter()
}
func (h *hostNetworkHandle) ChildExits() <-chan hostnet.ChildExit { return h.childExits }
func (h *hostNetworkHandle) Fatal() <-chan error                  { return h.fatal }
func (h *hostNetworkHandle) Done() <-chan struct{}                { return h.ctx.Done() }

func (h *hostNetworkHandle) SetPolicyRecordUpdater(update func(uint64) error) {
	h.updateMu.Lock()
	h.recordUpdater = update
	h.updateMu.Unlock()
}

// ApplySavedPolicy reloads the complete authoritative project/global snapshot
// in the supervisor. Callers cannot submit stale policy contents over IPC.
func (h *hostNetworkHandle) ApplySavedPolicy(ctx context.Context) error {
	return h.applySavedPolicy(ctx, true)
}

func (h *hostNetworkHandle) applySavedPolicy(ctx context.Context, fatalOnFailure bool) error {
	h.updateMu.Lock()
	defer h.updateMu.Unlock()
	if err := h.checkOperation(ctx); err != nil {
		return err
	}
	names, _, grants, err := loadHostNetworkInitialPolicy(h.store)
	if err != nil {
		wrapped := fmt.Errorf("reload saved host network policy: %w", err)
		if fatalOnFailure {
			h.reportFatal(wrapped)
		}
		return wrapped
	}
	if equalStrings(names, h.policyNames) && equalHostNetworkAddresses(grants, h.policyGrants) {
		return nil
	}
	allNames, allGrants := unionScopedHostPolicy(names, grants, h.policyScopes)
	generation := h.network.Generation() + 1
	if generation == 0 {
		return errors.New("host network: policy generation overflow")
	}
	err = h.dns.UpdatePolicyWith(ctx, h.network.LaunchID(), allNames, generation, func(applyCtx context.Context) error {
		return h.network.ApplyPolicy(applyCtx, hostnet.PolicySnapshot{LaunchID: h.network.LaunchID(), Generation: generation, IPGrants: allGrants})
	})
	if err != nil {
		if fatalOnFailure {
			h.reportFatal(fmt.Errorf("apply saved host network policy: %w", err))
		}
		return err
	}
	if h.recordUpdater != nil {
		if err := h.recordUpdater(generation); err != nil {
			if fatalOnFailure {
				h.reportFatal(fmt.Errorf("persist host network policy generation: %w", err))
			}
			return err
		}
	}
	h.policyNames = append(h.policyNames[:0], names...)
	h.policyGrants = append(h.policyGrants[:0], grants...)
	return nil
}

// BeginScopedPolicy adds exact domains and addresses to this launch under a
// host-owned scope. Callers use it only for a dedicated temporary setup or
// capture VM. It never changes the durable project/global policy files.
func (h *hostNetworkHandle) BeginScopedPolicy(ctx context.Context, scopeID string, names []string, ips []netip.Addr) error {
	h.updateMu.Lock()
	defer h.updateMu.Unlock()
	if err := h.checkOperation(ctx); err != nil {
		return err
	}
	if !validHostPolicyScopeID(scopeID) {
		return errors.New("host network: invalid scoped policy ID")
	}
	if _, exists := h.policyScopes[scopeID]; exists {
		return errors.New("host network: scoped policy ID is already active")
	}
	validatedNames, err := normalizeHostPolicyScopeNames(names)
	if err != nil {
		return err
	}
	validatedIPs, err := normalizeHostPolicyScopeIPs(ips)
	if err != nil {
		return err
	}
	nextScopes := make(map[string]hostNetworkPolicyScope, len(h.policyScopes)+1)
	for id, scope := range h.policyScopes {
		nextScopes[id] = scope
	}
	nextScopes[scopeID] = hostNetworkPolicyScope{Names: validatedNames, IPs: validatedIPs}
	allNames, allIPs := unionScopedHostPolicy(h.policyNames, h.policyGrants, nextScopes)
	generation := h.network.Generation() + 1
	if generation == 0 {
		return errors.New("host network: policy generation overflow")
	}
	err = h.dns.UpdatePolicyWith(ctx, h.network.LaunchID(), allNames, generation, func(applyCtx context.Context) error {
		return h.network.ApplyPolicy(applyCtx, hostnet.PolicySnapshot{LaunchID: h.network.LaunchID(), Generation: generation, IPGrants: allIPs})
	})
	if err != nil {
		h.reportFatal(fmt.Errorf("apply scoped host network policy: %w", err))
		return err
	}
	h.policyScopes = nextScopes
	if h.recordUpdater != nil {
		if err := h.recordUpdater(generation); err != nil {
			h.reportFatal(fmt.Errorf("persist scoped host network policy generation: %w", err))
			return err
		}
	}
	return nil
}

// EndScopedPolicy removes only the contribution owned by scopeID; an address
// or name with another base/setup/scope reference stays authorized.
func (h *hostNetworkHandle) EndScopedPolicy(ctx context.Context, scopeID string) error {
	h.updateMu.Lock()
	defer h.updateMu.Unlock()
	if err := h.checkOperation(ctx); err != nil {
		return err
	}
	if _, exists := h.policyScopes[scopeID]; !exists {
		return nil
	}
	nextScopes := make(map[string]hostNetworkPolicyScope, len(h.policyScopes)-1)
	for id, scope := range h.policyScopes {
		if id != scopeID {
			nextScopes[id] = scope
		}
	}
	allNames, allIPs := unionScopedHostPolicy(h.policyNames, h.policyGrants, nextScopes)
	generation := h.network.Generation() + 1
	if generation == 0 {
		return errors.New("host network: policy generation overflow")
	}
	err := h.dns.UpdatePolicyWith(ctx, h.network.LaunchID(), allNames, generation, func(applyCtx context.Context) error {
		return h.network.ApplyPolicy(applyCtx, hostnet.PolicySnapshot{LaunchID: h.network.LaunchID(), Generation: generation, IPGrants: allIPs})
	})
	if err != nil {
		h.reportFatal(fmt.Errorf("remove scoped host network policy: %w", err))
		return err
	}
	h.policyScopes = nextScopes
	if h.recordUpdater != nil {
		if err := h.recordUpdater(generation); err != nil {
			h.reportFatal(fmt.Errorf("persist scoped host network policy generation: %w", err))
			return err
		}
	}
	return nil
}

// BeginDiscovery is reserved for a dedicated, host-issued temporary launch.
// The broker resolves otherwise-unlisted exact questions only until deadline.
func (h *hostNetworkHandle) BeginDiscovery(ctx context.Context, launchID string, generation uint64, scopeID string, deadline time.Time) error {
	h.updateMu.Lock()
	defer h.updateMu.Unlock()
	if err := h.checkOperation(ctx); err != nil {
		return err
	}
	if launchID != h.network.LaunchID() || generation != h.network.Generation() {
		return errors.New("host network discovery: launch identity or generation mismatch")
	}
	if h.discoveryScope != "" {
		return errors.New("host network discovery: another discovery scope is active")
	}
	if err := h.dns.BeginDiscovery(ctx, launchID, generation, scopeID, deadline); err != nil {
		return err
	}
	h.discoveryScope = scopeID
	return nil
}

func (h *hostNetworkHandle) EndDiscovery(ctx context.Context, launchID string, generation uint64, scopeID string) error {
	h.updateMu.Lock()
	defer h.updateMu.Unlock()
	if err := h.checkOperation(ctx); err != nil {
		return err
	}
	if launchID != h.network.LaunchID() || generation != h.network.Generation() {
		return errors.New("host network discovery: launch identity or generation mismatch")
	}
	if h.discoveryScope == "" {
		return nil
	}
	if h.discoveryScope != scopeID {
		return errors.New("host network discovery: scope identity mismatch")
	}
	if err := h.dns.EndDiscovery(ctx, launchID, generation, scopeID); err != nil {
		h.reportFatal(fmt.Errorf("end host DNS discovery: %w", err))
		return err
	}
	h.discoveryScope = ""
	return nil
}

func validHostPolicyScopeID(value string) bool {
	if len(value) < 8 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-') {
			return false
		}
	}
	return true
}

func normalizeHostPolicyScopeNames(names []string) ([]string, error) {
	set := make(map[string]struct{}, len(names))
	for _, raw := range names {
		name, err := validateHostDNSPolicyName(raw)
		if err != nil {
			return nil, err
		}
		set[name] = struct{}{}
	}
	result := make([]string, 0, len(set))
	for name := range set {
		result = append(result, name)
	}
	sort.Strings(result)
	return result, nil
}

func normalizeHostPolicyScopeIPs(ips []netip.Addr) ([]netip.Addr, error) {
	set := make(map[netip.Addr]struct{}, len(ips))
	for _, raw := range ips {
		ip := raw.Unmap()
		if !ip.IsValid() || !ip.Is4() {
			return nil, fmt.Errorf("host network: scoped address %q is not IPv4", raw)
		}
		set[ip] = struct{}{}
	}
	result := make([]netip.Addr, 0, len(set))
	for ip := range set {
		result = append(result, ip)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Less(result[j]) })
	return result, nil
}

func unionScopedHostPolicy(baseNames []string, baseIPs []netip.Addr, scopes map[string]hostNetworkPolicyScope) ([]string, []netip.Addr) {
	names := make(map[string]struct{}, len(baseNames))
	ips := make(map[netip.Addr]struct{}, len(baseIPs))
	for _, name := range baseNames {
		names[name] = struct{}{}
	}
	for _, ip := range baseIPs {
		ips[ip.Unmap()] = struct{}{}
	}
	for _, scope := range scopes {
		for _, name := range scope.Names {
			names[name] = struct{}{}
		}
		for _, ip := range scope.IPs {
			ips[ip.Unmap()] = struct{}{}
		}
	}
	nameList := make([]string, 0, len(names))
	for name := range names {
		nameList = append(nameList, name)
	}
	sort.Strings(nameList)
	ipList := make([]netip.Addr, 0, len(ips))
	for ip := range ips {
		ipList = append(ipList, ip)
	}
	sort.Slice(ipList, func(i, j int) bool { return ipList[i].Less(ipList[j]) })
	return nameList, ipList
}

func equalHostNetworkAddresses(left, right []netip.Addr) bool {
	if len(left) != len(right) {
		return false
	}
	set := make(map[netip.Addr]struct{}, len(left))
	for _, address := range left {
		set[address.Unmap()] = struct{}{}
	}
	for _, address := range right {
		if _, ok := set[address.Unmap()]; !ok {
			return false
		}
	}
	return true
}

func (h *hostNetworkHandle) checkOperation(ctx context.Context) error {
	if err := h.ctx.Err(); err != nil {
		return fmt.Errorf("host network is closing: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func (h *hostNetworkHandle) AddForward(ctx context.Context, forward hostnet.Forward) error {
	h.updateMu.Lock()
	defer h.updateMu.Unlock()
	if err := h.checkOperation(ctx); err != nil {
		return err
	}
	if err := validateHostNetworkForward(forward); err != nil {
		return err
	}
	return h.network.AddForward(ctx, h.network.LaunchID(), h.network.Generation(), forward)
}

func (h *hostNetworkHandle) RemoveForward(ctx context.Context, forward hostnet.Forward) error {
	h.updateMu.Lock()
	defer h.updateMu.Unlock()
	if err := h.checkOperation(ctx); err != nil {
		return err
	}
	if err := validateHostNetworkForward(forward); err != nil {
		return err
	}
	return h.network.RemoveForward(ctx, h.network.LaunchID(), h.network.Generation(), forward)
}

func validateHostNetworkForward(forward hostnet.Forward) error {
	if forward.HostPort == 0 || forward.GuestPort == 0 || (forward.Protocol != "tcp" && forward.Protocol != "udp") {
		return errors.New("host network: forward requires nonzero ports and tcp or udp protocol")
	}
	return nil
}

func (h *hostNetworkHandle) Status(ctx context.Context) (hostNetworkStatus, error) {
	h.updateMu.Lock()
	defer h.updateMu.Unlock()
	if err := h.checkOperation(ctx); err != nil {
		return hostNetworkStatus{}, err
	}
	forwards, err := h.network.ListForwards(ctx)
	if err != nil {
		return hostNetworkStatus{}, err
	}
	sort.Slice(forwards, func(i, j int) bool {
		if forwards[i].Protocol != forwards[j].Protocol {
			return forwards[i].Protocol < forwards[j].Protocol
		}
		if forwards[i].HostPort != forwards[j].HostPort {
			return forwards[i].HostPort < forwards[j].HostPort
		}
		return forwards[i].GuestPort < forwards[j].GuestPort
	})
	processes := h.network.Processes()
	if h.frontendIdentity.PID > 0 {
		processes["host-dns-frontend"] = h.frontendIdentity
	}
	maintenanceSessions := 0
	for _, record := range h.maintenanceSessions {
		if record.deadline.After(time.Now()) {
			maintenanceSessions++
		}
	}
	return hostNetworkStatus{LaunchID: h.network.LaunchID(), Generation: h.network.Generation(), EventSequence: h.dns.EventSequence(), Processes: processes, Forwards: forwards, FullNetworkSessions: len(h.fullAccessLeases), MaintenanceSessions: maintenanceSessions}, nil
}

func (h *hostNetworkHandle) watchFatal() {
	for {
		select {
		case err := <-h.dns.Fatal():
			if err != nil {
				h.asyncCheckFailed.Store(true)
				select {
				case h.checkFailures <- hostNetworkCheckFailure{step: "reconcile host DNS policy", err: err}:
				case <-h.ctx.Done():
					return
				}
			}
		case child := <-h.network.ChildExits():
			select {
			case h.childExits <- child:
			default:
			}
			if h.ctx.Err() == nil {
				h.reportFatal(fmt.Errorf("host network child %s exited: %v", child.Name, child.Err))
				return
			}
		case <-h.ctx.Done():
			return
		}
	}
}

func (h *hostNetworkHandle) waitFrontend(cmd *exec.Cmd) {
	err := cmd.Wait()
	h.frontendDone <- err
	select {
	case h.childExits <- hostnet.ChildExit{Name: "host-dns-frontend", Err: err}:
	default:
	}
	if h.ctx.Err() == nil {
		h.reportFatal(fmt.Errorf("host DNS frontend exited: %v", err))
	}
}

func (h *hostNetworkHandle) reportFatal(err error) {
	select {
	case h.fatal <- err:
	default:
	}
}

func (h *hostNetworkHandle) startControlServer() error {
	path := filepath.Join(h.runtimeDir, hostNetworkControlSocketName)
	if len(path) > 107 {
		return fmt.Errorf("host network control socket path exceeds Linux limit")
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return fmt.Errorf("listen on host network control socket: %w", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return err
	}
	h.control = listener
	h.controlWG.Add(1)
	go h.controlLoop()
	return nil
}

type hostNetworkControlRequest struct {
	LaunchID            string          `json:"launch_id"`
	Operation           string          `json:"operation"`
	AfterSequence       uint64          `json:"after_sequence,omitempty"`
	Forward             hostnet.Forward `json:"forward,omitempty"`
	LeaseID             string          `json:"lease_id,omitempty"`
	FullNetworkDeadline int64           `json:"full_network_deadline,omitempty"`
	RequestNotAfter     int64           `json:"request_not_after,omitempty"`
	SessionID           string          `json:"session_id,omitempty"`
}

type hostNetworkControlResponse struct {
	Status             *hostNetworkStatus          `json:"status,omitempty"`
	Error              string                      `json:"error,omitempty"`
	MaintenanceSession *hostnet.MaintenanceSession `json:"maintenance_session,omitempty"`
	Streaming          bool                        `json:"streaming,omitempty"`
}

func (h *hostNetworkHandle) controlLoop() {
	defer h.controlWG.Done()
	for {
		conn, err := h.control.AcceptUnix()
		if err != nil {
			if h.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		select {
		case h.controlSlots <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		h.controlWG.Add(1)
		go func() {
			defer h.controlWG.Done()
			defer func() { <-h.controlSlots }()
			h.handleControl(conn)
		}()
	}
}

func (h *hostNetworkHandle) handleControl(conn *net.UnixConn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	cred, err := hostNetworkPeerCredentials(conn)
	if err != nil || cred.Uid != uint32(os.Getuid()) {
		return
	}
	reader := bufio.NewReaderSize(io.LimitReader(conn, 4097), 4096)
	line, err := reader.ReadBytes('\n')
	if err != nil || len(line) > 4096 {
		return
	}
	var request hostNetworkControlRequest
	if err := json.Unmarshal(line, &request); err != nil {
		return
	}
	response := hostNetworkControlResponse{}
	if request.LaunchID != h.network.LaunchID() {
		response.Error = "host network launch identity mismatch"
	} else if request.Operation == "domain-log" {
		_ = conn.SetDeadline(time.Time{})
		ctx, cancel := context.WithCancel(h.ctx)
		defer cancel()
		_ = h.StreamDomainEvents(ctx, request.AfterSequence, conn)
		return
	} else if request.Operation == "firewall-log" {
		_ = conn.SetDeadline(time.Time{})
		response.Streaming = true
		data, _ := json.Marshal(response)
		if _, err := conn.Write(append(data, '\n')); err != nil {
			return
		}
		ctx, cancel := context.WithCancel(h.ctx)
		defer cancel()
		// A firewall logger is an idle stream when no packets are flowing. Watch
		// the client side independently so closing the logger immediately frees
		// this control slot without waiting for another verdict event.
		go func() {
			_, _ = io.Copy(io.Discard, conn)
			cancel()
		}()
		_ = h.StreamFirewallEvents(ctx, request.AfterSequence, conn)
		return
	} else {
		requestTimeout := 4 * time.Second
		if request.Operation == "maintenance-start" {
			requestTimeout = 12 * time.Second
		}
		requestDeadline := time.Now().Add(requestTimeout)
		_ = conn.SetDeadline(requestDeadline.Add(time.Second))
		if request.RequestNotAfter != 0 {
			notAfter := time.Unix(0, request.RequestNotAfter)
			if !notAfter.After(time.Now()) {
				response.Error = "host network control request has expired"
				data, _ := json.Marshal(response)
				_, _ = conn.Write(append(data, '\n'))
				return
			}
			if notAfter.Before(requestDeadline) {
				requestDeadline = notAfter
			}
		}
		ctx, cancel := context.WithDeadline(h.ctx, requestDeadline)
		switch request.Operation {
		case "policy-reconcile":
			response.Error = errorString(h.ApplySavedPolicy(ctx))
		case "forward-add":
			response.Error = errorString(h.AddForward(ctx, request.Forward))
		case "forward-remove":
			response.Error = errorString(h.RemoveForward(ctx, request.Forward))
		case "status":
			status, statusErr := h.Status(ctx)
			if statusErr != nil {
				response.Error = statusErr.Error()
			} else {
				response.Status = &status
			}
		case "full-network-acquire":
			response.Error = errorString(h.acquireFullNetworkLease(ctx, request.LeaseID, time.Unix(0, request.FullNetworkDeadline)))
		case "full-network-renew":
			response.Error = errorString(h.renewFullNetworkLease(ctx, request.LeaseID, time.Unix(0, request.FullNetworkDeadline)))
		case "full-network-release":
			response.Error = errorString(h.releaseFullNetworkLease(ctx, request.LeaseID))
		case "maintenance-start":
			var session hostnet.MaintenanceSession
			session, err = h.startMaintenanceSession(ctx, request.SessionID, time.Unix(0, request.FullNetworkDeadline))
			if err == nil {
				response.MaintenanceSession = &session
			}
			response.Error = errorString(err)
		case "maintenance-renew":
			response.Error = errorString(h.renewMaintenanceSession(ctx, request.SessionID, time.Unix(0, request.FullNetworkDeadline)))
		case "maintenance-stop":
			response.Error = errorString(h.stopMaintenanceSession(ctx, request.SessionID))
		default:
			response.Error = "unknown host network control operation"
		}
		cancel()
	}
	data, _ := json.Marshal(response)
	_, _ = conn.Write(append(data, '\n'))
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func hostNetworkPeerCredentials(conn *net.UnixConn) (*unix.Ucred, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	var cred *unix.Ucred
	var controlErr error
	err = raw.Control(func(fd uintptr) { cred, controlErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	if err != nil {
		return nil, err
	}
	return cred, controlErr
}

// hostNetworkControl performs a bounded request to a live supervisor. Policy
// RPC deliberately carries no names or addresses; the supervisor reloads the
// protected persisted snapshot before advancing the generation.
func hostNetworkControl(ctx context.Context, runtimeDir, launchID, operation string, forward hostnet.Forward) (hostNetworkStatus, error) {
	return hostNetworkControlWithLease(ctx, runtimeDir, launchID, operation, forward, "", time.Time{})
}

func hostNetworkControlWithLease(ctx context.Context, runtimeDir, launchID, operation string, forward hostnet.Forward, leaseID string, deadline time.Time) (hostNetworkStatus, error) {
	response, err := hostNetworkControlRequestWithReply(ctx, runtimeDir, launchID, hostNetworkControlRequest{Operation: operation, Forward: forward, LeaseID: leaseID}, deadline)
	if err != nil {
		return hostNetworkStatus{}, err
	}
	if response.Status != nil {
		return *response.Status, nil
	}
	return hostNetworkStatus{}, nil
}

func hostNetworkControlRequestWithReply(ctx context.Context, runtimeDir, launchID string, request hostNetworkControlRequest, deadline time.Time) (hostNetworkControlResponse, error) {
	if !filepath.IsAbs(runtimeDir) || launchID == "" {
		return hostNetworkControlResponse{}, errors.New("host network control: invalid runtime path or launch ID")
	}
	operation := request.Operation
	if operation != "status" && operation != "policy-reconcile" && operation != "forward-add" && operation != "forward-remove" && operation != "domain-log" && operation != "firewall-log" && operation != "full-network-acquire" && operation != "full-network-renew" && operation != "full-network-release" && operation != "maintenance-start" && operation != "maintenance-renew" && operation != "maintenance-stop" {
		return hostNetworkControlResponse{}, errors.New("host network control: unsupported operation")
	}
	path := filepath.Join(runtimeDir, hostNetworkControlSocketName)
	if len(path) > 107 {
		return hostNetworkControlResponse{}, errors.New("host network control: socket path exceeds Linux limit")
	}
	dialer := net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		return hostNetworkControlResponse{}, fmt.Errorf("connect to running host network supervisor: %w", err)
	}
	defer conn.Close()
	controlTimeout := 4 * time.Second
	if operation == "maintenance-start" {
		controlTimeout = 12 * time.Second
	}
	controlDeadline := time.Now().Add(controlTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(controlDeadline) {
		controlDeadline = ctxDeadline
	}
	_ = conn.SetDeadline(controlDeadline)
	request.LaunchID = launchID
	if !deadline.IsZero() {
		request.FullNetworkDeadline = deadline.UnixNano()
	}
	if request.RequestNotAfter == 0 && operation != "domain-log" && operation != "firewall-log" {
		request.RequestNotAfter = controlDeadline.UnixNano()
	}
	data, err := json.Marshal(request)
	if err != nil {
		return hostNetworkControlResponse{}, err
	}
	if _, err := conn.Write(append(data, '\n')); err != nil {
		return hostNetworkControlResponse{}, err
	}
	var response hostNetworkControlResponse
	if err := json.NewDecoder(io.LimitReader(conn, 64<<10)).Decode(&response); err != nil {
		return hostNetworkControlResponse{}, err
	}
	if response.Error != "" {
		return hostNetworkControlResponse{}, errors.New(response.Error)
	}
	if operation == "status" {
		if response.Status == nil {
			return hostNetworkControlResponse{}, errors.New("host network control: missing status response")
		}
		return response, nil
	}
	return response, nil
}

func (h *hostNetworkHandle) Close(ctx context.Context) error {
	h.closeOnce.Do(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		h.cancel()
		if h.control != nil {
			_ = h.control.Close()
		}
		controlDone := make(chan struct{})
		go func() { h.controlWG.Wait(); close(controlDone) }()
		select {
		case <-controlDone:
		case <-cleanupCtx.Done():
			h.closeErr = errors.Join(h.closeErr, errors.New("host network control workers did not stop before cleanup deadline"))
		}
		if h.frontend != nil && h.frontend.Process != nil {
			_ = h.frontend.Process.Signal(syscall.SIGTERM)
			frontendExited := false
			select {
			case <-h.frontendDone:
				frontendExited = true
			case <-cleanupCtx.Done():
				_ = h.frontend.Process.Kill()
			case <-time.After(2 * time.Second):
				_ = h.frontend.Process.Kill()
			}
			if !frontendExited {
				select {
				case <-h.frontendDone:
				case <-time.After(2 * time.Second):
					h.closeErr = errors.Join(h.closeErr, errors.New("host DNS frontend did not exit after kill"))
				}
			}
		}
		if h.dns != nil {
			dnsDone := make(chan error, 1)
			go func() { dnsDone <- h.dns.Close() }()
			select {
			case err := <-dnsDone:
				h.closeErr = errors.Join(h.closeErr, err)
			case <-cleanupCtx.Done():
				h.closeErr = errors.Join(h.closeErr, errors.New("host DNS broker did not stop before cleanup deadline"))
			}
		}
		if h.udp != nil {
			h.closeErr = errors.Join(h.closeErr, h.udp.Close())
		}
		if h.tcp != nil {
			h.closeErr = errors.Join(h.closeErr, h.tcp.Close())
		}
		if h.network != nil {
			h.closeErr = errors.Join(h.closeErr, h.network.Stop(cleanupCtx))
		}
		if h.control != nil {
			if err := os.Remove(filepath.Join(h.runtimeDir, hostNetworkControlSocketName)); err != nil && !errors.Is(err, os.ErrNotExist) {
				h.closeErr = errors.Join(h.closeErr, err)
			}
		}
	})
	return h.closeErr
}
