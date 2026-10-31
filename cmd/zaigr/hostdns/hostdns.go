// Package hostdns implements the host-owned DNS policy broker and capless
// guest-facing DNS frontend for a single VM launch.
package hostdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	defaultMaxMessageBytes = 4096
	defaultMaxConcurrent   = 128
	defaultMaxNames        = 4096
	defaultMaxAnswers      = 128
	defaultMaxLeaseRefs    = 8192
	defaultResolveTimeout  = 5 * time.Second
	defaultMaxLeaseTTL     = time.Hour
	defaultRefreshLead     = 15 * time.Second
	defaultRefreshRetry    = 2 * time.Second
	defaultUDPPayload      = 1232
)

// LeaseBackend separates current DNS admission leases from name authorization.
// Answer expiry stops new flows; established flows retain their authorizing
// names until explicit revocation. A zero name deadline means saved policy;
// transient discovery permissions must expire in the kernel. Implementations
// reject stale generations and finish revocation cleanup before returning.
type LeaseBackend interface {
	ReplaceDNSLeases(ctx context.Context, launchID string, generation uint64, leases map[string]map[netip.Addr]time.Time, names map[string]time.Time) error
}

// Config contains trusted host-side policy and resolver settings for one VM.
// ResolverServers overrides ResolverConfigPath when provided. ExcludedPrefixes
// must include host-owned addresses and internal routes in addition to the
// built-in special-use ranges.
type Config struct {
	LaunchID           string
	IPCPath            string
	ResolverConfigPath string
	ResolverServers    []string
	Names              []string
	Generation         uint64
	ExcludedPrefixes   []netip.Prefix
	FrontendUID        int
	FrontendPID        int
	FrontendStartTime  uint64
	MaxMessageBytes    int
	MaxConcurrent      int
	MaxNames           int
	MaxAnswers         int
	MaxLeaseRefs       int
	ResolveTimeout     time.Duration
	MaxLeaseTTL        time.Duration
	RefreshLead        time.Duration
}

type activeName struct {
	addresses   map[netip.Addr]time.Time
	nextRefresh time.Time
	refreshing  bool
}

type nameGate struct {
	token chan struct{}
	refs  int
}

// Server owns exact-name authorization, upstream lookup, DNS lease references,
// refresh scheduling, and the private frontend IPC socket for one VM launch.
type Server struct {
	cfg               Config
	backend           LeaseBackend
	resolver          *upstreamResolver
	listener          *net.UnixListener
	ctx               context.Context
	cancel            context.CancelFunc
	closeOnce         sync.Once
	closed            chan struct{}
	workers           chan struct{}
	wg                sync.WaitGroup
	commitMu          sync.Mutex
	mu                sync.Mutex
	names             map[string]struct{}
	active            map[string]*activeName
	lookupEpoch       map[string]uint64
	nameGates         map[string]*nameGate
	lookupSequence    uint64
	generation        uint64
	failed            error
	peers             map[int]uint64
	fatal             chan error
	eventMu           sync.Mutex
	events            []Event
	eventSequence     uint64
	eventChanged      chan struct{}
	discoveryScope    string
	discoveryUntil    time.Time
	fullAccessUntil   time.Time
	fullAccessEpoch   uint64
	maintenanceAccess map[netip.Addr]*maintenanceLease
}

type maintenanceLease struct {
	sessions map[string]time.Time
	epoch    uint64
}

// FrontendLimits bounds work performed by the capless guest-facing process.
type FrontendLimits struct {
	MaxMessageBytes int
	MaxConcurrent   int
	UDPPayloadBytes int
}

// FrontendConfig describes pre-opened guest-facing sockets. The caller binds
// UDPFD and TCPFD inside the policy network namespace and starts this process
// only after dropping all capabilities and setting no_new_privs.
type FrontendConfig struct {
	UDPFD   int
	TCPFD   int
	ReadyFD int
	IPCPath string
	Limits  FrontendLimits
}

// StartBroker creates a private Unix-socket DNS broker and begins bounded
// request/refresh workers. The frontend is launched separately after this
// returns, then its PID identity must be registered with AuthorizeFrontend.
func StartBroker(parent context.Context, cfg Config, backend LeaseBackend) (*Server, error) {
	if err := normalizeConfig(&cfg); err != nil {
		return nil, err
	}
	if backend == nil {
		return nil, errors.New("host DNS: lease backend is required")
	}
	if cfg.IPCPath == "" {
		return nil, errors.New("host DNS: private IPC path is required")
	}
	if err := ensurePrivateIPCParent(cfg.IPCPath); err != nil {
		return nil, err
	}
	resolver, err := newUpstreamResolver(cfg)
	if err != nil {
		return nil, err
	}
	policyNames, err := normalizePolicyNames(cfg.Names, cfg.MaxNames)
	if err != nil {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: cfg.IPCPath, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("host DNS: listen on private IPC socket: %w", err)
	}
	if err := os.Chmod(cfg.IPCPath, 0600); err != nil {
		listener.Close()
		os.Remove(cfg.IPCPath)
		return nil, fmt.Errorf("host DNS: secure private IPC socket: %w", err)
	}
	if err := listener.SetDeadline(time.Time{}); err != nil {
		listener.Close()
		os.Remove(cfg.IPCPath)
		return nil, fmt.Errorf("host DNS: configure private IPC socket: %w", err)
	}
	ctx, cancel := context.WithCancel(parent)
	s := &Server{
		cfg: cfg, backend: backend, resolver: resolver, listener: listener,
		ctx: ctx, cancel: cancel, closed: make(chan struct{}),
		workers: make(chan struct{}, cfg.MaxConcurrent),
		names:   policyNames, active: make(map[string]*activeName), lookupEpoch: make(map[string]uint64), nameGates: make(map[string]*nameGate),
		generation: cfg.Generation, peers: make(map[int]uint64), fatal: make(chan error, 1),
		maintenanceAccess: make(map[netip.Addr]*maintenanceLease),
		eventChanged:      make(chan struct{}),
	}
	if cfg.FrontendPID > 0 {
		s.peers[cfg.FrontendPID] = cfg.FrontendStartTime
	}
	s.wg.Add(2)
	go func() { defer s.wg.Done(); s.acceptLoop() }()
	go func() { defer s.wg.Done(); s.refreshLoop() }()
	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()
	return s, nil
}

func normalizeConfig(cfg *Config) error {
	if cfg.LaunchID == "" {
		return errors.New("host DNS: launch identity is required")
	}
	if cfg.MaxMessageBytes == 0 {
		cfg.MaxMessageBytes = defaultMaxMessageBytes
	}
	if cfg.MaxMessageBytes < 512 || cfg.MaxMessageBytes > 65535 {
		return fmt.Errorf("host DNS: message bound %d is outside 512..65535", cfg.MaxMessageBytes)
	}
	if cfg.MaxConcurrent == 0 {
		cfg.MaxConcurrent = defaultMaxConcurrent
	}
	if cfg.MaxConcurrent < 1 || cfg.MaxConcurrent > 4096 {
		return fmt.Errorf("host DNS: concurrency bound %d is outside 1..4096", cfg.MaxConcurrent)
	}
	if cfg.MaxNames == 0 {
		cfg.MaxNames = defaultMaxNames
	}
	if cfg.MaxNames < 1 || cfg.MaxNames > 100000 {
		return fmt.Errorf("host DNS: name bound %d is outside 1..100000", cfg.MaxNames)
	}
	if cfg.MaxAnswers == 0 {
		cfg.MaxAnswers = defaultMaxAnswers
	}
	if cfg.MaxAnswers < 1 || cfg.MaxAnswers > 4096 {
		return fmt.Errorf("host DNS: answer bound %d is outside 1..4096", cfg.MaxAnswers)
	}
	if cfg.MaxLeaseRefs == 0 {
		cfg.MaxLeaseRefs = defaultMaxLeaseRefs
	}
	if cfg.MaxLeaseRefs < 1 || cfg.MaxLeaseRefs > 8192 {
		return fmt.Errorf("host DNS: lease-reference bound %d is outside 1..8192", cfg.MaxLeaseRefs)
	}
	if cfg.ResolveTimeout == 0 {
		cfg.ResolveTimeout = defaultResolveTimeout
	}
	if cfg.ResolveTimeout < 100*time.Millisecond || cfg.ResolveTimeout > time.Minute {
		return errors.New("host DNS: resolver timeout must be between 100ms and 1m")
	}
	if cfg.MaxLeaseTTL == 0 {
		cfg.MaxLeaseTTL = defaultMaxLeaseTTL
	}
	if cfg.MaxLeaseTTL < time.Second || cfg.MaxLeaseTTL > 24*time.Hour {
		return errors.New("host DNS: maximum lease TTL must be between 1s and 24h")
	}
	if cfg.RefreshLead == 0 {
		cfg.RefreshLead = defaultRefreshLead
	}
	if cfg.RefreshLead < time.Second || cfg.RefreshLead > 10*time.Minute {
		return errors.New("host DNS: refresh lead must be between 1s and 10m")
	}
	if cfg.ResolverConfigPath == "" {
		cfg.ResolverConfigPath = "/etc/resolv.conf"
	}
	if cfg.FrontendUID == 0 {
		cfg.FrontendUID = os.Getuid()
	}
	for i := range cfg.ExcludedPrefixes {
		if !cfg.ExcludedPrefixes[i].IsValid() {
			return fmt.Errorf("host DNS: invalid excluded address prefix %q", cfg.ExcludedPrefixes[i])
		}
		cfg.ExcludedPrefixes[i] = cfg.ExcludedPrefixes[i].Masked()
	}
	return nil
}

func ensurePrivateIPCParent(path string) error {
	parent := filepath.Dir(path)
	info, err := os.Stat(parent)
	if err != nil {
		return fmt.Errorf("host DNS: inspect private IPC directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("host DNS: IPC parent %q is not a directory", parent)
	}
	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("host DNS: IPC parent %q must have mode 0700", parent)
	}
	return nil
}

// AuthorizeFrontend registers the expected frontend process PID and Linux
// /proc start time. A matching UID alone is not sufficient to call the broker.
func (s *Server) AuthorizeFrontend(pid int, startTime uint64) error {
	if pid <= 0 || startTime == 0 {
		return errors.New("host DNS: frontend PID and start time are required")
	}
	actual, err := processStartTime(pid)
	if err != nil {
		return fmt.Errorf("host DNS: inspect frontend process: %w", err)
	}
	if actual != startTime {
		return errors.New("host DNS: frontend process identity changed before authorization")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed != nil {
		return fmt.Errorf("host DNS: broker is fail-closed: %w", s.failed)
	}
	s.peers[pid] = startTime
	return nil
}

// RevokeFrontend removes a registered frontend identity. Existing IPC
// connections are still checked at acceptance and may finish their one request.
func (s *Server) RevokeFrontend(pid int) {
	s.mu.Lock()
	delete(s.peers, pid)
	s.mu.Unlock()
}

// UpdatePolicy is an idempotent same-generation refresh. Advancing policy
// state must use UpdatePolicyWith so hostnet and DNS share one transaction.
func (s *Server) UpdatePolicy(ctx context.Context, launchID string, exactNames []string, generation uint64) error {
	return s.UpdatePolicyWith(ctx, launchID, exactNames, generation, nil)
}

// SetFullNetworkAccess temporarily lets this launch resolve any exact DNS name.
// It creates no persistent name policy and no address lease, so a cached answer
// becomes unusable as soon as the independent nftables full-network lease ends.
func (s *Server) SetFullNetworkAccess(ctx context.Context, launchID string, generation uint64, deadline time.Time) error {
	if launchID != s.cfg.LaunchID {
		return errors.New("host DNS full-network lease: launch identity mismatch")
	}
	if !deadline.IsZero() && (!deadline.After(time.Now()) || deadline.After(time.Now().Add(10*time.Second))) {
		return errors.New("host DNS full-network lease: deadline is outside the kernel lease bound")
	}
	s.commitMu.Lock()
	defer s.commitMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed != nil {
		return fmt.Errorf("host DNS full-network lease: broker is fail-closed: %w", s.failed)
	}
	if generation != s.generation {
		return errors.New("host DNS full-network lease: stale policy generation")
	}
	wasActive := s.fullAccessUntil.After(time.Now())
	willBeActive := deadline.After(time.Now())
	if wasActive != willBeActive {
		s.fullAccessEpoch++
		if s.fullAccessEpoch == 0 {
			s.fullAccessEpoch++
		}
	}
	if deadline.IsZero() {
		s.fullAccessUntil = time.Time{}
	} else {
		s.fullAccessUntil = deadline
	}
	s.lookupSequence++
	return nil
}

// SetMaintenanceAccess authorizes DNS discovery only for a source address on
// one host-owned maintenance network. These answers are observed, but the
// session's broad route already supplies transport access, so no guest-wide
// DNS address lease is created.
func (s *Server) SetMaintenanceAccess(ctx context.Context, launchID string, generation uint64, address netip.Addr, sessionID string, deadline time.Time) error {
	if launchID != s.cfg.LaunchID || !address.Is4() || !netip.MustParsePrefix("10.0.4.0/24").Contains(address) || sessionID == "" {
		return errors.New("host DNS maintenance lease: invalid launch or source address")
	}
	if !deadline.After(time.Now()) || deadline.After(time.Now().Add(10*time.Second)) {
		return errors.New("host DNS maintenance lease: deadline is outside the kernel lease bound")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed != nil {
		return fmt.Errorf("host DNS maintenance lease: broker is fail-closed: %w", s.failed)
	}
	if generation != s.generation {
		return fmt.Errorf("host DNS maintenance lease: stale policy generation %d (current %d)", generation, s.generation)
	}
	current := s.maintenanceAccess[address]
	if current == nil {
		current = &maintenanceLease{sessions: make(map[string]time.Time)}
		s.maintenanceAccess[address] = current
	}
	wasActive := maintenanceLeaseActive(current, time.Now())
	current.sessions[sessionID] = deadline
	if !wasActive {
		current.epoch++
	}
	return nil
}

func (s *Server) ClearMaintenanceAccess(ctx context.Context, launchID string, generation uint64, address netip.Addr, sessionID string) error {
	if launchID != s.cfg.LaunchID || !address.Is4() {
		return errors.New("host DNS maintenance lease: invalid launch or source address")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed != nil {
		return fmt.Errorf("host DNS maintenance lease: broker is fail-closed: %w", s.failed)
	}
	if generation != s.generation {
		return errors.New("host DNS maintenance lease: stale policy generation")
	}
	current := s.maintenanceAccess[address]
	if current != nil {
		wasActive := maintenanceLeaseActive(current, time.Now())
		delete(current.sessions, sessionID)
		if wasActive && !maintenanceLeaseActive(current, time.Now()) {
			current.epoch++
		}
	}
	return nil
}

func maintenanceLeaseActive(lease *maintenanceLease, now time.Time) bool {
	if lease == nil {
		return false
	}
	active := false
	for id, deadline := range lease.sessions {
		if !deadline.After(now) {
			delete(lease.sessions, id)
		} else {
			active = true
		}
	}
	return active
}

// UpdatePolicyWith serializes the external manual-policy replacement and DNS
// policy generation against every in-flight DNS lease commit. The callback
// must atomically apply the host network's non-DNS policy at this generation.
func (s *Server) UpdatePolicyWith(ctx context.Context, launchID string, exactNames []string, generation uint64, applyManual func(context.Context) error) error {
	if launchID != s.cfg.LaunchID {
		return errors.New("host DNS: launch identity mismatch")
	}
	names, err := normalizePolicyNames(exactNames, s.cfg.MaxNames)
	if err != nil {
		return err
	}
	s.commitMu.Lock()
	defer s.commitMu.Unlock()
	if err := s.ctx.Err(); err != nil {
		return fmt.Errorf("host DNS: broker is closing: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	if s.failed != nil {
		err := s.failed
		s.mu.Unlock()
		return fmt.Errorf("host DNS: broker is fail-closed: %w", err)
	}
	if generation < s.generation {
		s.mu.Unlock()
		return fmt.Errorf("host DNS: stale policy generation %d (current %d)", generation, s.generation)
	}
	if generation == s.generation && !sameSet(names, s.names) {
		s.mu.Unlock()
		return errors.New("host DNS: policy names changed without advancing generation")
	}
	if generation == s.generation && applyManual != nil {
		s.mu.Unlock()
		return errors.New("host DNS: manual policy callback requires an advanced generation")
	}
	if generation == s.generation {
		s.mu.Unlock()
		return nil
	}
	oldGeneration := s.generation
	if applyManual == nil {
		s.mu.Unlock()
		return errors.New("host DNS: advancing a policy generation requires the coupled hostnet apply callback")
	}
	retainedActive := make(map[string]*activeName, len(s.active))
	for name, active := range s.active {
		if _, keep := names[name]; keep {
			retainedActive[name] = active
		}
	}
	retainedLeases := s.leaseSnapshotLocked(retainedActive, names, time.Now())
	s.mu.Unlock()
	if applyManual != nil {
		// Remove only references belonging exclusively to removed names before
		// advancing the shared generation. Retained names (including shared-IP
		// references) keep their nft leases and conntrack state continuously.
		if err := s.backend.ReplaceDNSLeases(ctx, s.cfg.LaunchID, oldGeneration, retainedLeases.addresses, retainedLeases.names); err != nil {
			s.failClosed(err)
			return fmt.Errorf("host DNS: withdraw leases before policy generation advance: %w", err)
		}
		if err := applyManual(ctx); err != nil {
			s.failClosed(err)
			return fmt.Errorf("host DNS: apply coupled manual policy: %w", err)
		}
	}
	s.mu.Lock()
	if s.failed != nil {
		err := s.failed
		s.mu.Unlock()
		return fmt.Errorf("host DNS: broker is fail-closed: %w", err)
	}
	if s.ctx.Err() != nil {
		s.mu.Unlock()
		return errors.New("host DNS: broker is closing")
	}
	if generation <= s.generation {
		s.mu.Unlock()
		return errors.New("host DNS: policy generation changed during serialized update")
	}
	s.names = names
	s.generation = generation
	for name := range s.lookupEpoch {
		if _, keep := names[name]; !keep {
			delete(s.lookupEpoch, name)
		}
	}
	s.active = retainedActive
	leases := s.leaseSnapshotLocked(s.active, s.names, time.Now())
	s.mu.Unlock()
	if err := s.backend.ReplaceDNSLeases(ctx, s.cfg.LaunchID, generation, leases.addresses, leases.names); err != nil {
		s.failClosed(err)
		return fmt.Errorf("host DNS: apply policy generation %d: %w", generation, err)
	}
	return nil
}

// leaseSnapshot preserves name identity even when its last answer expires.
// The helper needs that identity to distinguish DNS churn from revocation.
type leaseSnapshot struct {
	addresses map[string]map[netip.Addr]time.Time
	names     map[string]time.Time
}

func (s *Server) leaseSnapshotLocked(active map[string]*activeName, names map[string]struct{}, now time.Time) leaseSnapshot {
	result := leaseSnapshot{addresses: make(map[string]map[netip.Addr]time.Time), names: make(map[string]time.Time)}
	for name := range names {
		result.names[name] = time.Time{}
	}
	for name, entry := range active {
		if _, permanent := names[name]; !permanent {
			deadline := s.discoveryDeadlineForLocked(name, now)
			if deadline.IsZero() || !deadline.After(now) {
				continue
			}
			result.names[name] = deadline
		}
		addresses := make(map[netip.Addr]time.Time)
		for address, expiry := range entry.addresses {
			if expiry.After(now) {
				addresses[address] = expiry
			}
		}
		result.addresses[name] = addresses
	}
	return result
}

// Close stops all broker workers and removes the private IPC socket.
func (s *Server) Close() error {
	var closeErr error
	s.closeOnce.Do(func() {
		s.cancel()
		if err := s.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			closeErr = err
		}
		s.wg.Wait()
		s.commitMu.Lock()
		s.commitMu.Unlock()
		close(s.closed)
		if err := os.Remove(s.cfg.IPCPath); err != nil && !errors.Is(err, os.ErrNotExist) && closeErr == nil {
			closeErr = err
		}
	})
	return closeErr
}

// Fatal reports the first failure to install or reconcile kernel policy. The
// supervisor must stop the VM/network after receiving it. Resolver failures
// remain ordinary fail-closed DNS responses and do not signal this channel.
func (s *Server) Fatal() <-chan error { return s.fatal }

// Failure returns the sticky kernel-policy failure, if one has occurred.
// Unlike consuming Fatal, this snapshot is safe for synchronous callers that
// need to distinguish a terminal policy failure from ordinary validation
// errors while the supervisor also observes the asynchronous notification.
func (s *Server) Failure() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failed
}

func (s *Server) failClosed(err error) {
	s.mu.Lock()
	first := false
	if s.failed == nil {
		s.failed = err
		first = true
	}
	s.mu.Unlock()
	if first {
		select {
		case s.fatal <- err:
		default:
		}
	}
}

func normalizePolicyNames(names []string, limit int) (map[string]struct{}, error) {
	if len(names) > limit {
		return nil, fmt.Errorf("host DNS: policy contains %d names; maximum is %d", len(names), limit)
	}
	result := make(map[string]struct{}, len(names))
	for _, raw := range names {
		name, err := normalizeName(raw)
		if err != nil {
			return nil, fmt.Errorf("host DNS: invalid exact-name policy entry %q: %w", raw, err)
		}
		result[name] = struct{}{}
	}
	return result, nil
}

func sameSet(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for value := range a {
		if _, ok := b[value]; !ok {
			return false
		}
	}
	return true
}

func (s *Server) currentLeaseSnapshotLocked(now time.Time) leaseSnapshot {
	return s.leaseSnapshotLocked(s.active, s.names, now)
}

func (s *Server) leaseReferenceCountLocked(replaceName string, replacementCount int) int {
	total := replacementCount
	for name, active := range s.active {
		if name != replaceName {
			total += len(active.addresses)
		}
	}
	return total
}

func sortedAddresses(leases map[netip.Addr]time.Time) []netip.Addr {
	addresses := make([]netip.Addr, 0, len(leases))
	for addr := range leases {
		addresses = append(addresses, addr)
	}
	sort.Slice(addresses, func(i, j int) bool { return addresses[i].Less(addresses[j]) })
	return addresses
}

func normalizeName(raw string) (string, error) {
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if len(name) == 0 || len(name) > 253 {
		return "", errors.New("name is empty or exceeds 253 bytes")
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("DNS label has invalid length or hyphen placement")
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return "", errors.New("only lowercase ASCII DNS labels are accepted")
			}
		}
	}
	return name + ".", nil
}

func processStartTime(pid int) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	closeParen := strings.LastIndexByte(string(data), ')')
	if closeParen < 0 || closeParen+1 >= len(data) {
		return 0, errors.New("malformed process stat")
	}
	fields := strings.Fields(string(data[closeParen+1:]))
	// The first field after comm is stat field 3 (state); starttime is field 22.
	if len(fields) <= 19 {
		return 0, errors.New("process stat lacks start time")
	}
	var start uint64
	_, err = fmt.Sscan(fields[19], &start)
	return start, err
}
