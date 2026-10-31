package hostdns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

var errStaleLookup = errors.New("DNS lookup was superseded by newer policy or query state")

func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.AcceptUnix()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		if !s.authorizedPeer(conn) {
			conn.Close()
			continue
		}
		select {
		case s.workers <- struct{}{}:
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer func() { <-s.workers }()
				s.handleIPC(conn)
			}()
		default:
			conn.Close()
		}
	}
}

func (s *Server) authorizedPeer(conn *net.UnixConn) bool {
	cred, err := unixPeerCredentials(conn)
	if err != nil || cred.Uid != uint32(s.cfg.FrontendUID) {
		return false
	}
	s.mu.Lock()
	start, ok := s.peers[int(cred.Pid)]
	s.mu.Unlock()
	if !ok || start == 0 {
		return false
	}
	actual, err := processStartTime(int(cred.Pid))
	return err == nil && actual == start
}

func unixPeerCredentials(conn *net.UnixConn) (*syscall.Ucred, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	var cred *syscall.Ucred
	var controlErr error
	err = raw.Control(func(fd uintptr) {
		cred, controlErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil {
		return nil, err
	}
	return cred, controlErr
}

func (s *Server) handleIPC(conn *net.UnixConn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(s.cfg.ResolveTimeout + time.Second))
	message, err := readFrame(conn, s.cfg.MaxMessageBytes+4)
	if err != nil || len(message) < 16 {
		return
	}
	source := netip.AddrFrom4([4]byte{message[0], message[1], message[2], message[3]})
	answer := s.handleQuery(s.ctx, source, message[4:])
	if len(answer) == 0 || len(answer) > s.cfg.MaxMessageBytes {
		return
	}
	_ = writeFrame(conn, answer)
}

func readFrame(reader io.Reader, limit int) ([]byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(header[:]))
	if size < 12 || size > limit {
		return nil, fmt.Errorf("host DNS IPC frame length %d is outside 12..%d", size, limit)
	}
	message := make([]byte, size)
	if _, err := io.ReadFull(reader, message); err != nil {
		return nil, err
	}
	return message, nil
}

func writeFrame(writer io.Writer, message []byte) error {
	if len(message) > 65535 {
		return errors.New("host DNS IPC response exceeds DNS frame limit")
	}
	var header [2]byte
	binary.BigEndian.PutUint16(header[:], uint16(len(message)))
	if _, err := writer.Write(header[:]); err != nil {
		return err
	}
	_, err := writer.Write(message)
	return err
}

func (s *Server) handleQuery(parent context.Context, source netip.Addr, packet []byte) []byte {
	request := new(dns.Msg)
	if err := request.Unpack(packet); err != nil {
		return formatErrorResponse(packet)
	}
	if request.Response || request.Opcode != dns.OpcodeQuery || request.Authoritative || request.Truncated || request.RecursionAvailable || request.Zero || len(request.Question) != 1 || len(request.Answer) != 0 || len(request.Ns) != 0 {
		return responseBytes(request, nil, dns.RcodeFormatError, 0)
	}
	if !validQueryAdditionals(request) {
		return responseBytes(request, nil, dns.RcodeFormatError, 0)
	}
	question := request.Question[0]
	if question.Qclass != dns.ClassINET {
		return responseBytes(request, nil, dns.RcodeNotImplemented, 0)
	}
	name, err := normalizeName(question.Name)
	if err != nil {
		return responseBytes(request, nil, dns.RcodeFormatError, 0)
	}
	if name == "localhost." || strings.HasSuffix(name, ".localhost.") {
		return localhostResponse(request, question)
	}
	queryType := dns.TypeToString[question.Qtype]
	if queryType == "" {
		queryType = fmt.Sprintf("TYPE%d", question.Qtype)
	}
	record := func(decision string, rcode int, addresses []netip.Addr, generation uint64) {
		s.recordEvent(name, queryType, decision, rcode, addresses, generation)
	}
	s.mu.Lock()
	if s.failed != nil {
		s.mu.Unlock()
		return responseBytes(request, nil, dns.RcodeServerFailure, 0)
	}
	now := time.Now()
	maintenanceLease := s.maintenanceAccess[source]
	maintenanceEpoch := uint64(0)
	maintenanceAccess := maintenanceLeaseActive(maintenanceLease, now)
	if maintenanceLease != nil {
		maintenanceEpoch = maintenanceLease.epoch
	}
	fullAccess := s.fullAccessUntil.After(now) || maintenanceAccess
	fullAccessEpoch := s.fullAccessEpoch
	allowed := maintenanceAccess || s.discoveryAllowsLocked(name, now)
	_, permanent := s.names[name]
	discoveryDeadline := s.discoveryDeadlineForLocked(name, now)
	generation := s.generation
	s.mu.Unlock()
	if !allowed {
		record("refused", dns.RcodeRefused, nil, generation)
		return responseBytes(request, nil, dns.RcodeRefused, 0)
	}
	if opt := request.IsEdns0(); opt != nil && opt.Do() {
		// DNSSEC validation is not part of this address-lease backend. Do not
		// advertise an incomplete DNSSEC answer to a client that requested it.
		return responseBytes(request, nil, dns.RcodeNotImplemented, 0)
	}
	if question.Qtype == dns.TypeAAAA {
		// The first host backend deliberately authorizes IPv4 transport only.
		// Return NODATA for exact-allowed names rather than exposing an unroutable
		// IPv6 destination or leaking a public AAAA address without a kernel lease.
		record("nodata", dns.RcodeSuccess, nil, generation)
		return responseBytes(request, nil, dns.RcodeSuccess, 0)
	}
	if question.Qtype != dns.TypeA {
		record("unsupported-type", dns.RcodeNotImplemented, nil, generation)
		return responseBytes(request, nil, dns.RcodeNotImplemented, 0)
	}
	ctx, cancel := context.WithTimeout(parent, s.cfg.ResolveTimeout)
	defer cancel()
	releaseNameGate, err := s.acquireNameGate(ctx, name)
	if err != nil {
		record("servfail", dns.RcodeServerFailure, nil, generation)
		return responseBytes(request, nil, dns.RcodeServerFailure, 0)
	}
	defer releaseNameGate()

	// Authorization may have changed while this request waited behind another
	// lookup for the same name. Use a fresh snapshot before resolving or creating
	// a lease so queued work cannot carry an old policy through the gate.
	s.mu.Lock()
	if s.failed != nil {
		s.mu.Unlock()
		record("servfail", dns.RcodeServerFailure, nil, generation)
		return responseBytes(request, nil, dns.RcodeServerFailure, 0)
	}
	now = time.Now()
	maintenanceLease = s.maintenanceAccess[source]
	maintenanceEpoch = 0
	maintenanceAccess = maintenanceLeaseActive(maintenanceLease, now)
	if maintenanceLease != nil {
		maintenanceEpoch = maintenanceLease.epoch
	}
	fullAccess = s.fullAccessUntil.After(now) || maintenanceAccess
	fullAccessEpoch = s.fullAccessEpoch
	allowed = maintenanceAccess || s.discoveryAllowsLocked(name, now)
	_, permanent = s.names[name]
	discoveryDeadline = s.discoveryDeadlineForLocked(name, now)
	generation = s.generation
	s.mu.Unlock()
	if !allowed {
		record("refused", dns.RcodeRefused, nil, generation)
		return responseBytes(request, nil, dns.RcodeRefused, 0)
	}
	var epoch uint64
	if !maintenanceAccess {
		var ok bool
		epoch, ok = s.beginLookup(name, generation)
		if !ok {
			record("servfail", dns.RcodeServerFailure, nil, generation)
			return responseBytes(request, nil, dns.RcodeServerFailure, 0)
		}
	}
	upstreamRequest := new(dns.Msg)
	upstreamRequest.SetQuestion(name, dns.TypeA)
	upstreamRequest.RecursionDesired = true
	if opt := request.IsEdns0(); opt != nil {
		upstreamRequest.SetEdns0(defaultUDPPayload, opt.Do())
	}
	upstreamResponse, err := s.resolver.exchange(ctx, upstreamRequest)
	if err != nil {
		record("upstream-failed", dns.RcodeServerFailure, nil, generation)
		return responseBytes(request, nil, dns.RcodeServerFailure, 0)
	}
	if upstreamResponse.Rcode == dns.RcodeNameError {
		if !maintenanceAccess {
			if err := s.commitNegative(ctx, name, generation, epoch); err != nil {
				record("servfail", dns.RcodeServerFailure, nil, generation)
				return responseBytes(request, nil, dns.RcodeServerFailure, 0)
			}
		}
		record("nxdomain", dns.RcodeNameError, nil, generation)
		return responseBytes(request, nil, dns.RcodeNameError, 0)
	}
	if upstreamResponse.Rcode != dns.RcodeSuccess {
		record("upstream-failed", dns.RcodeServerFailure, nil, generation)
		return responseBytes(request, nil, dns.RcodeServerFailure, 0)
	}
	answer, leases, ttl, err := s.validateAnswerChain(name, upstreamResponse, fullAccess)
	if err != nil {
		if !maintenanceAccess {
			if commitErr := s.commitNegative(ctx, name, generation, epoch); commitErr != nil {
				record("servfail", dns.RcodeServerFailure, nil, generation)
				return responseBytes(request, nil, dns.RcodeServerFailure, 0)
			}
		}
		record("unsafe-answer", dns.RcodeServerFailure, nil, generation)
		return responseBytes(request, nil, dns.RcodeServerFailure, 0)
	}
	if fullAccess && !permanent && !maintenanceAccess {
		remaining := time.Until(discoveryDeadline)
		if remaining < time.Second {
			if err := s.commitNegative(ctx, name, generation, epoch); err != nil {
				record("servfail", dns.RcodeServerFailure, nil, generation)
				return responseBytes(request, nil, dns.RcodeServerFailure, 0)
			}
			record("discovery-expired", dns.RcodeRefused, nil, generation)
			return responseBytes(request, nil, dns.RcodeRefused, 0)
		}
		if ttl > remaining {
			ttl = remaining
		}
		for address, duration := range leases {
			if duration > remaining {
				leases[address] = remaining
			}
		}
	}
	observed := make([]netip.Addr, 0, len(leases))
	for address := range leases {
		observed = append(observed, address)
	}
	if fullAccess {
		// Exact saved names retain ordinary DNS leases when this answer also
		// passes the restricted public-address policy. Private/excluded answers
		// can be returned only while the broad host lease remains active.
		if permanent && !maintenanceAccess {
			_, persistentLeases, persistentTTL, normalErr := s.validateAnswerChain(name, upstreamResponse, false)
			persistentLeases = omitPrivateLeases(persistentLeases)
			if normalErr == nil && len(persistentLeases) > 0 && persistentTTL > 0 {
				if err := s.commitAnswer(ctx, name, generation, epoch, persistentLeases, persistentTTL); err != nil {
					record("lease-failed", dns.RcodeServerFailure, nil, generation)
					return responseBytes(request, nil, dns.RcodeServerFailure, 0)
				}
			}
		} else {
			leases = nil
		}
	}
	if fullAccess {
		// Non-permanent full-network answers never mutate DNS lease state.
	} else if len(leases) > 0 {
		if ttl <= 0 {
			record("zero-ttl", dns.RcodeServerFailure, nil, generation)
			return responseBytes(request, nil, dns.RcodeServerFailure, 0)
		}
		persistentLeases := omitPrivateLeases(leases)
		if len(persistentLeases) > 0 {
			if err := s.commitAnswer(ctx, name, generation, epoch, persistentLeases, ttl); err != nil {
				record("lease-failed", dns.RcodeServerFailure, nil, generation)
				return responseBytes(request, nil, dns.RcodeServerFailure, 0)
			}
		}
	} else if upstreamResponse.Rcode == dns.RcodeSuccess {
		// Exact authorized names with valid NODATA remain refresh candidates, but
		// never create an address lease.
		if err := s.commitNegative(ctx, name, generation, epoch); err != nil {
			record("servfail", dns.RcodeServerFailure, nil, generation)
			return responseBytes(request, nil, dns.RcodeServerFailure, 0)
		}
	}
	if fullAccess {
		// The upstream lookup may outlive the host-owned full-network lease.
		// Recheck the exact authorization snapshot immediately before returning
		// an answer, including after a release/reacquire of the same domain.
		s.mu.Lock()
		currentMaintenanceLease := s.maintenanceAccess[source]
		maintenanceStillAuthorized := true
		if maintenanceAccess {
			maintenanceStillAuthorized = currentMaintenanceLease != nil && maintenanceLeaseActive(currentMaintenanceLease, time.Now()) && currentMaintenanceLease.epoch == maintenanceEpoch
		}
		lookupStillCurrent := maintenanceAccess || s.lookupEpoch[name] == epoch
		stillAuthorized := s.failed == nil && s.generation == generation && maintenanceStillAuthorized &&
			(s.fullAccessUntil.After(time.Now()) && s.fullAccessEpoch == fullAccessEpoch || maintenanceAccess) && lookupStillCurrent
		s.mu.Unlock()
		if !stillAuthorized || ctx.Err() != nil {
			record("full-network-expired", dns.RcodeRefused, nil, generation)
			return responseBytes(request, nil, dns.RcodeRefused, 0)
		}
	}
	decision := "resolved"
	if fullAccess {
		decision = "full-network-resolved"
	} else if !permanent {
		decision = "discovery-resolved"
	}
	record(decision, dns.RcodeSuccess, observed, generation)
	return responseBytes(request, answer, upstreamResponse.Rcode, ttl)
}

func omitPrivateLeases(input map[netip.Addr]time.Duration) map[netip.Addr]time.Duration {
	filtered := make(map[netip.Addr]time.Duration, len(input))
	for address, ttl := range input {
		if !address.IsPrivate() {
			filtered[address] = ttl
		}
	}
	return filtered
}

func formatErrorResponse(packet []byte) []byte {
	if len(packet) < 2 {
		return nil
	}
	response := &dns.Msg{MsgHdr: dns.MsgHdr{
		Id: binary.BigEndian.Uint16(packet[:2]), Response: true,
		Opcode: dns.OpcodeQuery, Rcode: dns.RcodeFormatError,
	}}
	packed, _ := response.Pack()
	return packed
}

func validQueryAdditionals(request *dns.Msg) bool {
	var optCount int
	for _, record := range request.Extra {
		if record.Header().Rrtype != dns.TypeOPT {
			return false
		}
		optCount++
		if optCount > 1 {
			return false
		}
	}
	if opt := request.IsEdns0(); opt != nil {
		if opt.Version() != 0 || len(opt.Option) != 0 {
			return false
		}
	}
	return true
}

func responseBytes(request *dns.Msg, answers []dns.RR, rcode int, ttl time.Duration) []byte {
	response := new(dns.Msg)
	response.SetReply(request)
	response.Authoritative = false
	response.RecursionAvailable = true
	response.AuthenticatedData = false
	response.CheckingDisabled = false
	response.Rcode = rcode
	response.Answer = answers
	if ttl > 0 {
		seconds := uint32(ttl / time.Second)
		if seconds == 0 {
			seconds = 1
		}
		for _, rr := range response.Answer {
			rr.Header().Ttl = seconds
		}
	}
	if opt := request.IsEdns0(); opt != nil {
		udpSize := int(opt.UDPSize())
		if udpSize < 512 || udpSize > defaultUDPPayload {
			udpSize = defaultUDPPayload
		}
		response.SetEdns0(uint16(udpSize), false)
	}
	packed, err := response.Pack()
	if err != nil {
		return nil
	}
	return packed
}

func (s *Server) validateAnswerChain(queryName string, response *dns.Msg, allowPrivate bool) ([]dns.RR, map[netip.Addr]time.Duration, time.Duration, error) {
	if len(response.Answer) > s.cfg.MaxAnswers {
		return nil, nil, 0, errors.New("trusted DNS answer exceeds record-count bound")
	}
	cnames := make(map[string]string)
	cnamesRR := make(map[string]dns.RR)
	addresses := make(map[string][]*dns.A)
	for _, record := range response.Answer {
		header := record.Header()
		if header.Class != dns.ClassINET {
			return nil, nil, 0, errors.New("trusted DNS answer contains a non-IN record")
		}
		owner, err := normalizeName(header.Name)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("malformed trusted DNS answer owner: %w", err)
		}
		switch typed := record.(type) {
		case *dns.CNAME:
			target, err := normalizeName(typed.Target)
			if err != nil {
				return nil, nil, 0, fmt.Errorf("malformed trusted CNAME target: %w", err)
			}
			if _, ok := cnames[owner]; ok {
				return nil, nil, 0, errors.New("trusted DNS answer contains duplicate CNAME owners")
			}
			cnames[owner] = target
			cnamesRR[owner] = dns.Copy(record)
		case *dns.A:
			addresses[owner] = append(addresses[owner], typed)
		case *dns.RRSIG:
			return nil, nil, 0, errors.New("trusted DNS answer contains an unsupported DNSSEC signature")
		default:
			return nil, nil, 0, fmt.Errorf("trusted DNS answer contains unsupported %s record", dns.TypeToString[header.Rrtype])
		}
	}
	current := queryName
	visited := map[string]struct{}{current: {}}
	chain := make([]dns.RR, 0, 8)
	chainTTL := time.Duration(0)
	hasChainTTL := false
	for depth := 0; depth <= 16; depth++ {
		if target, ok := cnames[current]; ok {
			if len(addresses[current]) > 0 {
				return nil, nil, 0, errors.New("trusted DNS CNAME owner also has A records")
			}
			rr := cnamesRR[current]
			chain = append(chain, rr)
			duration := time.Duration(rr.Header().Ttl) * time.Second
			if duration <= 0 {
				return nil, nil, 0, errors.New("trusted DNS CNAME has a zero TTL")
			}
			if !hasChainTTL || duration < chainTTL {
				chainTTL = duration
			}
			hasChainTTL = true
			if _, exists := visited[target]; exists {
				return nil, nil, 0, errors.New("trusted DNS answer contains a CNAME loop")
			}
			visited[target] = struct{}{}
			current = target
			continue
		}
		final := addresses[current]
		for owner := range cnames {
			if _, linked := visited[owner]; !linked {
				return nil, nil, 0, errors.New("trusted DNS answer contains an unrelated CNAME record")
			}
		}
		for owner := range addresses {
			if _, linked := visited[owner]; !linked {
				return nil, nil, 0, errors.New("trusted DNS answer contains an unrelated A record")
			}
		}
		if len(final) == 0 {
			if len(chain) > 0 {
				return nil, nil, 0, errors.New("trusted DNS CNAME chain has no terminal A record")
			}
			return nil, nil, 0, nil
		}
		if len(final) > s.cfg.MaxAnswers-len(chain) {
			return nil, nil, 0, errors.New("trusted DNS address count exceeds bound")
		}
		leases := make(map[netip.Addr]time.Duration, len(final))
		for _, record := range final {
			addr, ok := netip.AddrFromSlice(record.A)
			if !ok {
				return nil, nil, 0, errors.New("trusted DNS A record has invalid address bytes")
			}
			addr = addr.Unmap()
			if !addr.Is4() {
				return nil, nil, 0, errors.New("trusted DNS A record has non-IPv4 address bytes")
			}
			if allowPrivate {
				if err := validateFullNetworkAddress(addr); err != nil {
					return nil, nil, 0, err
				}
			} else if err := validateAddress(addr, s.cfg.ExcludedPrefixes); err != nil {
				return nil, nil, 0, err
			}
			duration := time.Duration(record.Hdr.Ttl) * time.Second
			if duration <= 0 {
				return nil, nil, 0, errors.New("trusted DNS A record has a zero TTL")
			}
			if hasChainTTL && chainTTL < duration {
				duration = chainTTL
			}
			if duration <= 0 {
				return nil, nil, 0, errors.New("trusted DNS answer has a zero TTL")
			}
			if duration > s.cfg.MaxLeaseTTL {
				duration = s.cfg.MaxLeaseTTL
			}
			if previous, exists := leases[addr]; !exists || duration < previous {
				leases[addr] = duration
			}
			chain = append(chain, dns.Copy(record))
		}
		minTTL := time.Duration(0)
		for _, duration := range leases {
			if minTTL == 0 || duration < minTTL {
				minTTL = duration
			}
		}
		if minTTL <= 0 {
			return nil, nil, 0, errors.New("trusted DNS answer has no positive lease lifetime")
		}
		for _, rr := range chain {
			rr.Header().Ttl = uint32(minTTL / time.Second)
		}
		return chain, leases, minTTL, nil
	}
	return nil, nil, 0, errors.New("trusted DNS CNAME chain exceeds 16 aliases")
}

func (s *Server) beginLookup(name string, generation uint64) (uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx.Err() != nil || s.failed != nil || generation != s.generation {
		return 0, false
	}
	if !s.discoveryAllowsLocked(name, time.Now()) {
		return 0, false
	}
	if _, tracked := s.lookupEpoch[name]; !tracked && len(s.lookupEpoch) >= s.cfg.MaxNames {
		return 0, false
	}
	s.lookupSequence++
	if s.lookupSequence == 0 {
		return 0, false
	}
	s.lookupEpoch[name] = s.lookupSequence
	return s.lookupSequence, true
}

func (s *Server) acquireNameGate(ctx context.Context, name string) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	gate := s.nameGates[name]
	if gate == nil {
		if len(s.nameGates) >= s.cfg.MaxNames {
			s.mu.Unlock()
			return nil, errors.New("DNS lookup concurrency limit reached")
		}
		gate = &nameGate{token: make(chan struct{}, 1)}
		s.nameGates[name] = gate
	}
	gate.refs++
	s.mu.Unlock()

	select {
	case gate.token <- struct{}{}:
		var once sync.Once
		release := func() {
			once.Do(func() {
				<-gate.token
				s.mu.Lock()
				gate.refs--
				if gate.refs == 0 && s.nameGates[name] == gate {
					delete(s.nameGates, name)
				}
				s.mu.Unlock()
			})
		}
		if err := ctx.Err(); err != nil {
			release()
			return nil, err
		}
		return release, nil
	case <-ctx.Done():
		s.mu.Lock()
		gate.refs--
		if gate.refs == 0 && s.nameGates[name] == gate {
			delete(s.nameGates, name)
		}
		s.mu.Unlock()
		return nil, ctx.Err()
	}
}

func (s *Server) commitAnswer(ctx context.Context, name string, generation, epoch uint64, addresses map[netip.Addr]time.Duration, ttl time.Duration) error {
	s.commitMu.Lock()
	defer s.commitMu.Unlock()
	if err := s.ctx.Err(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	if s.failed != nil {
		err := s.failed
		s.mu.Unlock()
		return err
	}
	if generation != s.generation {
		s.mu.Unlock()
		return errStaleLookup
	}
	if epoch != s.lookupEpoch[name] {
		s.mu.Unlock()
		return errStaleLookup
	}
	now := time.Now()
	if !s.discoveryAllowsLocked(name, now) {
		s.mu.Unlock()
		return errors.New("DNS name was removed while lookup was in flight")
	}
	deadline := s.discoveryDeadlineForLocked(name, now)
	active := s.active[name]
	previous := make(map[netip.Addr]time.Time)
	if active != nil {
		for addr, expiry := range active.addresses {
			if expiry.After(now) {
				previous[addr] = expiry
			}
		}
	}
	for addr, duration := range addresses {
		if duration > s.cfg.MaxLeaseTTL {
			duration = s.cfg.MaxLeaseTTL
		}
		if !deadline.IsZero() && duration > deadline.Sub(now) {
			duration = deadline.Sub(now)
		}
		if duration <= 0 {
			s.mu.Unlock()
			return errors.New("DNS discovery deadline expired before lease commit")
		}
		expires := now.Add(duration)
		if old, ok := previous[addr]; !ok || expires.After(old) {
			previous[addr] = expires
		}
	}
	if !deadline.IsZero() {
		for addr, expiry := range previous {
			if expiry.After(deadline) {
				previous[addr] = deadline
			}
		}
	}
	if s.leaseReferenceCountLocked(name, len(previous)) > s.cfg.MaxLeaseRefs {
		s.mu.Unlock()
		return fmt.Errorf("DNS lease reference limit %d exceeded; refusing new answer", s.cfg.MaxLeaseRefs)
	}
	if active == nil {
		active = &activeName{}
		s.active[name] = active
	}
	active.addresses = previous
	active.nextRefresh = now.Add(refreshDelay(ttl, s.cfg.RefreshLead))
	leases := s.currentLeaseSnapshotLocked(now)
	currentGeneration := s.generation
	s.mu.Unlock()
	if err := s.backend.ReplaceDNSLeases(ctx, s.cfg.LaunchID, currentGeneration, leases.addresses, leases.names); err != nil {
		s.failClosed(err)
		return fmt.Errorf("commit DNS-derived address leases: %w", err)
	}
	return nil
}

func (s *Server) commitNegative(ctx context.Context, name string, generation, epoch uint64) error {
	s.commitMu.Lock()
	defer s.commitMu.Unlock()
	if err := s.ctx.Err(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	if s.failed != nil {
		err := s.failed
		s.mu.Unlock()
		return err
	}
	if generation != s.generation {
		s.mu.Unlock()
		return errStaleLookup
	}
	if epoch != s.lookupEpoch[name] {
		s.mu.Unlock()
		return errStaleLookup
	}
	now := time.Now()
	if !s.discoveryAllowsLocked(name, now) {
		s.mu.Unlock()
		return errors.New("DNS name was removed while lookup was in flight")
	}
	active := s.active[name]
	if active == nil {
		active = &activeName{addresses: make(map[netip.Addr]time.Time)}
		s.active[name] = active
	}
	changed := len(active.addresses) > 0
	active.addresses = make(map[netip.Addr]time.Time)
	active.nextRefresh = now.Add(defaultRefreshRetry)
	leases := s.currentLeaseSnapshotLocked(now)
	s.mu.Unlock()
	if !changed {
		return nil
	}
	if err := s.backend.ReplaceDNSLeases(ctx, s.cfg.LaunchID, generation, leases.addresses, leases.names); err != nil {
		s.failClosed(err)
		return fmt.Errorf("remove invalidated DNS-derived address leases: %w", err)
	}
	return nil
}

func refreshDelay(ttl, lead time.Duration) time.Duration {
	if ttl <= 0 {
		return defaultRefreshRetry
	}
	if lead > ttl/2 {
		lead = ttl / 2
	}
	delay := ttl - lead
	if delay < 250*time.Millisecond {
		delay = ttl / 2
	}
	if delay < 100*time.Millisecond {
		delay = 100 * time.Millisecond
	}
	return delay
}

func (s *Server) resolveForRefresh(ctx context.Context, name string) (map[netip.Addr]time.Duration, time.Duration, bool, error) {
	request := new(dns.Msg)
	request.SetQuestion(name, dns.TypeA)
	request.RecursionDesired = true
	response, err := s.resolver.exchange(ctx, request)
	if err != nil {
		return nil, 0, false, err
	}
	if response.Rcode == dns.RcodeNameError {
		return nil, 0, true, nil
	}
	if response.Rcode != dns.RcodeSuccess {
		return nil, 0, false, fmt.Errorf("refresh of %s returned DNS rcode %d", name, response.Rcode)
	}
	_, leases, ttl, err := s.validateAnswerChain(name, response, false)
	if err != nil {
		return nil, 0, true, err
	}
	if len(leases) == 0 {
		return nil, 0, true, errors.New("refresh returned no A records")
	}
	return leases, ttl, false, nil
}

func (s *Server) refreshLoop() {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case now := <-ticker.C:
			s.expireDiscovery(now)
			s.expireLeases(now)
			s.scheduleRefreshes(now)
		}
	}
}

func (s *Server) expireLeases(now time.Time) {
	s.commitMu.Lock()
	defer s.commitMu.Unlock()
	if s.ctx.Err() != nil {
		return
	}
	s.mu.Lock()
	if s.failed != nil {
		s.mu.Unlock()
		return
	}
	changed := false
	for _, active := range s.active {
		for addr, expiry := range active.addresses {
			if !expiry.After(now) {
				delete(active.addresses, addr)
				changed = true
			}
		}
	}
	if !changed {
		s.mu.Unlock()
		return
	}
	leases := s.currentLeaseSnapshotLocked(now)
	generation := s.generation
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(s.ctx, s.cfg.ResolveTimeout)
	defer cancel()
	if err := s.backend.ReplaceDNSLeases(ctx, s.cfg.LaunchID, generation, leases.addresses, leases.names); err != nil {
		s.failClosed(err)
	}
}

func (s *Server) scheduleRefreshes(now time.Time) {
	s.mu.Lock()
	due := make([]string, 0)
	for name, active := range s.active {
		if active.refreshing || active.nextRefresh.IsZero() || active.nextRefresh.After(now) {
			continue
		}
		if !s.discoveryAllowsLocked(name, now) {
			continue
		}
		active.refreshing = true
		due = append(due, name)
	}
	generation := s.generation
	s.mu.Unlock()
	for _, name := range due {
		select {
		case s.workers <- struct{}{}:
			s.wg.Add(1)
			go func(name string) {
				defer s.wg.Done()
				defer func() { <-s.workers }()
				s.refreshName(name, generation)
			}(name)
		default:
			s.mu.Lock()
			if active := s.active[name]; active != nil {
				active.refreshing = false
				active.nextRefresh = now.Add(defaultRefreshRetry)
			}
			s.mu.Unlock()
		}
	}
}

func (s *Server) refreshName(name string, generation uint64) {
	defer func() {
		s.mu.Lock()
		if active := s.active[name]; active != nil {
			active.refreshing = false
		}
		s.mu.Unlock()
	}()
	gateCtx, cancelGate := context.WithTimeout(s.ctx, s.cfg.ResolveTimeout)
	defer cancelGate()
	releaseNameGate, err := s.acquireNameGate(gateCtx, name)
	if err != nil {
		return
	}
	defer releaseNameGate()

	// The timer captured a generation before this refresh waited for the name
	// gate. Refresh only under the current policy after acquiring the gate.
	s.mu.Lock()
	if s.failed != nil || s.ctx.Err() != nil || generation != s.generation || !s.discoveryAllowsLocked(name, time.Now()) {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	epoch, ok := s.beginLookup(name, generation)
	if !ok {
		return
	}
	addresses, ttl, invalidate, err := s.resolveForRefresh(gateCtx, name)
	if err != nil {
		if invalidate {
			ctx, cancel := context.WithTimeout(s.ctx, s.cfg.ResolveTimeout)
			if commitErr := s.commitNegative(ctx, name, generation, epoch); commitErr != nil && !errors.Is(commitErr, errStaleLookup) && s.ctx.Err() == nil {
				s.failClosed(commitErr)
			}
			cancel()
		}
		s.mu.Lock()
		if active := s.active[name]; active != nil && generation == s.generation && epoch == s.lookupEpoch[name] {
			active.nextRefresh = time.Now().Add(defaultRefreshRetry)
		}
		s.mu.Unlock()
		return
	}
	if invalidate {
		ctx, cancel := context.WithTimeout(s.ctx, s.cfg.ResolveTimeout)
		if commitErr := s.commitNegative(ctx, name, generation, epoch); commitErr != nil && !errors.Is(commitErr, errStaleLookup) && s.ctx.Err() == nil {
			s.failClosed(commitErr)
		}
		cancel()
		return
	}
	s.commitMu.Lock()
	defer s.commitMu.Unlock()
	if s.ctx.Err() != nil {
		return
	}
	s.mu.Lock()
	if s.failed != nil || generation != s.generation {
		s.mu.Unlock()
		return
	}
	if epoch != s.lookupEpoch[name] {
		s.mu.Unlock()
		return
	}
	if _, allowed := s.names[name]; !allowed {
		s.mu.Unlock()
		return
	}
	now := time.Now()
	active := s.active[name]
	previous := make(map[netip.Addr]time.Time)
	if active != nil {
		for addr, expiry := range active.addresses {
			if expiry.After(now) {
				previous[addr] = expiry
			}
		}
	}
	for addr, duration := range addresses {
		if duration > s.cfg.MaxLeaseTTL {
			duration = s.cfg.MaxLeaseTTL
		}
		expires := now.Add(duration)
		if old, ok := previous[addr]; !ok || expires.After(old) {
			previous[addr] = expires
		}
	}
	if s.leaseReferenceCountLocked(name, len(previous)) > s.cfg.MaxLeaseRefs {
		if active != nil {
			active.nextRefresh = now.Add(defaultRefreshRetry)
		}
		s.mu.Unlock()
		return
	}
	if active == nil {
		active = &activeName{}
		s.active[name] = active
	}
	active.addresses = previous
	active.nextRefresh = now.Add(refreshDelay(ttl, s.cfg.RefreshLead))
	leases := s.currentLeaseSnapshotLocked(now)
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(s.ctx, s.cfg.ResolveTimeout)
	defer cancel()
	if err := s.backend.ReplaceDNSLeases(ctx, s.cfg.LaunchID, generation, leases.addresses, leases.names); err != nil {
		if !errors.Is(err, errStaleLookup) && s.ctx.Err() == nil {
			s.failClosed(err)
		}
	}
}

// localhostResponse answers localhost names with the guest's own loopback
// addresses (RFC 6761). The base image has no /etc/hosts, so without this the
// guest could not resolve localhost at all. Loopback never leaves the guest,
// so no firewall lease is involved.
func localhostResponse(request *dns.Msg, question dns.Question) []byte {
	header := dns.RR_Header{Name: question.Name, Class: dns.ClassINET, Ttl: 3600}
	switch question.Qtype {
	case dns.TypeA:
		header.Rrtype = dns.TypeA
		return responseBytes(request, []dns.RR{&dns.A{Hdr: header, A: net.IPv4(127, 0, 0, 1)}}, dns.RcodeSuccess, 0)
	case dns.TypeAAAA:
		header.Rrtype = dns.TypeAAAA
		return responseBytes(request, []dns.RR{&dns.AAAA{Hdr: header, AAAA: net.IPv6loopback}}, dns.RcodeSuccess, 0)
	}
	return responseBytes(request, nil, dns.RcodeSuccess, 0)
}
