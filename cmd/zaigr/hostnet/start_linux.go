//go:build linux

package hostnet

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type linuxRuntime struct {
	mu             sync.Mutex
	opts           Options
	launchID       string
	generation     uint64
	grants         []netip.Addr
	conn           *net.UnixConn
	responses      *bufio.Scanner
	responseQueue  chan helperResponseResult
	responseStop   chan struct{}
	responseOnce   sync.Once
	pending        int
	pendingWrite   chan error
	tap            *os.File
	maintenanceTap *os.File
	dnsUDP         *os.File
	dnsTCP         *os.File
	exitWriter     *os.File
	helper         *exec.Cmd
	slirp          *exec.Cmd
	apiSocket      string
	eventRead      *os.File
	eventMu        sync.Mutex
	eventChanged   chan struct{}
	events         []FirewallEvent
	eventSequence  uint64
	recentEvents   map[string]firewallEventState
	eventClosed    bool
	forward        []Forward
	forwardIDs     map[Forward]string
	stopped        bool
	identities     map[string]ProcessIdentity
	exits          chan ChildExit
	helperDone     chan error
	slirpDone      chan error
	helperExited   chan struct{}
	slirpExited    chan struct{}
	helperExitErr  error
	slirpExitErr   error
}

type helperResponseResult struct {
	response helperResponse
	err      error
}

func startLinux(ctx context.Context, opts Options) (Runtime, error) {
	if err := preflight(opts); err != nil {
		return nil, hostNetworkError("preflight", err)
	}
	grants, err := cleanIPv4Addresses(opts.InitialIPGrants)
	if err != nil {
		return nil, err
	}
	if err := privateRuntimeDir(opts.RuntimeDir); err != nil {
		return nil, hostNetworkError("runtime directory", err)
	}
	sock := socketPath(opts.RuntimeDir, "controller")
	_ = os.Remove(sock)
	helperLog, err := os.OpenFile(filepath.Join(opts.RuntimeDir, "network-helper.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	defer helperLog.Close()
	userNS, err := namespaceInode("/proc/self/ns/user")
	if err != nil {
		return nil, err
	}
	netNS, err := namespaceInode("/proc/self/ns/net")
	if err != nil {
		return nil, err
	}
	eventFDs, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return nil, hostNetworkError("create firewall telemetry channel", err)
	}
	eventReader := os.NewFile(uintptr(eventFDs[0]), "host-network-firewall-events")
	eventWriter := os.NewFile(uintptr(eventFDs[1]), "host-network-firewall-events-child")
	keepEvents := false
	defer func() {
		if !keepEvents {
			_ = eventReader.Close()
		}
	}()
	defer eventWriter.Close()
	helper := exec.Command(opts.Executable, helperArgs(sock, opts.LaunchID, os.Getuid(), os.Getpid(), userNS, netNS, 3)...)
	helper.ExtraFiles = []*os.File{eventWriter}
	helper.SysProcAttr = RootlessUserNamespaceSysProcAttr(true)
	helper.SysProcAttr.Setsid = true
	helper.SysProcAttr.Pdeathsig = syscall.SIGKILL
	helper.Stdout, helper.Stderr = helperLog, helperLog
	if err := helper.Start(); err != nil {
		return nil, hostNetworkError("start namespace controller", err)
	}
	targetGeneration := opts.InitialGeneration
	if targetGeneration == 0 {
		targetGeneration = 1
	}
	r := &linuxRuntime{opts: opts, launchID: opts.LaunchID, generation: 0, grants: nil, helper: helper, apiSocket: socketPath(opts.RuntimeDir, "slirp-api"), eventRead: eventReader, eventChanged: make(chan struct{}), responseStop: make(chan struct{}), recentEvents: make(map[string]firewallEventState), identities: make(map[string]ProcessIdentity), exits: make(chan ChildExit, 2), helperDone: make(chan error, 1), slirpDone: make(chan error, 1), helperExited: make(chan struct{}), slirpExited: make(chan struct{}), forwardIDs: make(map[Forward]string)}
	if err := r.trackChild("hostnet-helper", helper, r.helperDone); err != nil {
		_ = helper.Process.Kill()
		_ = helper.Wait()
		return nil, err
	}
	go r.readFirewallEvents(eventReader)
	failed := true
	defer func() {
		if failed {
			_ = r.Stop(context.Background())
		}
	}()
	var conn *net.UnixConn
	deadline := time.Now().Add(15 * time.Second)
	if err := waitUntil(ctx, deadline, func() (bool, error) {
		select {
		case <-r.helperExited:
			return false, fmt.Errorf("namespace controller exited: %v", r.helperExitErr)
		default:
		}
		c, e := net.DialTimeout("unix", sock, 100*time.Millisecond)
		if e != nil {
			return false, nil
		}
		uc, ok := c.(*net.UnixConn)
		if !ok {
			c.Close()
			return false, errors.New("controller socket is not Unix")
		}
		conn = uc
		return true, nil
	}); err != nil {
		return nil, hostNetworkError("namespace readiness", err)
	}
	r.conn = conn
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	// The first framed helper message carries both TAP descriptors and the DNS
	// sockets. TAP descriptors are never exposed in guest storage or to DNS.
	buf := make([]byte, 4096)
	oob := make([]byte, unix.CmsgSpace(4*unix.SizeofInt))
	n, oobn, flags, _, err := conn.ReadMsgUnix(buf, oob)
	if err != nil {
		if logBytes, logErr := os.ReadFile(filepath.Join(opts.RuntimeDir, "network-helper.log")); logErr == nil && len(logBytes) > 0 {
			err = fmt.Errorf("%w (namespace helper: %s)", err, strings.TrimSpace(string(logBytes)))
		}
		return nil, hostNetworkError("TAP descriptor handoff", err)
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return nil, err
	}
	var received []int
	for _, msg := range msgs {
		fds, e := unix.ParseUnixRights(&msg)
		if e == nil {
			received = append(received, fds...)
		}
	}
	closeReceived := func() {
		for _, fd := range received {
			_ = unix.Close(fd)
		}
	}
	if flags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) != 0 {
		closeReceived()
		return nil, errors.New("truncated host network descriptor handoff")
	}
	if string(buf[:n]) != descriptorReadyMarker {
		closeReceived()
		return nil, errors.New("invalid host network descriptor readiness marker")
	}
	_ = conn.SetReadDeadline(time.Time{})
	if len(received) != 4 {
		closeReceived()
		return nil, fmt.Errorf("host network helper transferred %d descriptors, want two TAPs and DNS sockets", len(received))
	}
	for _, fd := range received {
		unix.CloseOnExec(fd)
	}
	r.tap = os.NewFile(uintptr(received[0]), "zaigr-guest-tap")
	r.maintenanceTap = os.NewFile(uintptr(received[1]), "zaigr-maintenance-tap")
	r.dnsUDP = os.NewFile(uintptr(received[2]), "zaigr-dns-udp")
	r.dnsTCP = os.NewFile(uintptr(received[3]), "zaigr-dns-tcp")
	r.responses = bufio.NewScanner(conn)
	r.responses.Buffer(make([]byte, 4096), 1<<20)
	r.responseQueue = make(chan helperResponseResult, 1)
	go r.readResponses()
	// Start slirp with a dedicated read end. The only writer is returned to the
	// supervisor for lifetime ownership and is not inherited by children.
	exitRead, exitWrite, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	r.exitWriter = exitWrite
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	api := r.apiSocket
	args := []string{"--configure", "--disable-dns", "--cidr=" + UplinkCIDR, "--netns-type=pid", "--ready-fd=4", "--exit-fd=3", "--api-socket=" + api, strconv.Itoa(helper.Process.Pid), uplinkTapName}
	slirp := exec.CommandContext(ctx, opts.SlirpPath, args...)
	slirp.ExtraFiles = []*os.File{exitRead, readyWrite}
	slirp.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Pdeathsig: syscall.SIGKILL}
	slirp.Stdout, slirp.Stderr = helperLog, helperLog
	if err := slirp.Start(); err != nil {
		closeFiles(exitRead, readyRead, readyWrite)
		return nil, hostNetworkError("start rootless uplink", err)
	}
	r.slirp = slirp
	if err := r.trackChild("slirp4netns", slirp, r.slirpDone); err != nil {
		_ = slirp.Process.Kill()
		_ = slirp.Wait()
		r.slirp = nil
		return nil, err
	}
	_ = exitRead.Close()
	_ = readyWrite.Close()
	readyCh := make(chan error, 1)
	go func() {
		b := make([]byte, 1)
		_, e := readyRead.Read(b)
		if e == nil && b[0] != '1' {
			e = errors.New("invalid slirp readiness marker")
		}
		readyCh <- e
	}()
	select {
	case err := <-readyCh:
		_ = readyRead.Close()
		if err != nil {
			return nil, hostNetworkError("uplink readiness", err)
		}
	case <-ctx.Done():
		_ = readyRead.Close()
		return nil, ctx.Err()
	case <-time.After(15 * time.Second):
		_ = readyRead.Close()
		return nil, errors.New("slirp4netns readiness deadline exceeded")
	}
	if err := r.request(helperRequest{Operation: "configure-uplink", LaunchID: opts.LaunchID, Generation: 0}); err != nil {
		return nil, hostNetworkError("configure uplink", err)
	}
	if err := r.applyPolicyLocked(ctx, PolicySnapshot{LaunchID: opts.LaunchID, Generation: targetGeneration, IPGrants: grants}); err != nil {
		return nil, err
	}
	failed = false
	keepEvents = true
	return r, nil
}

func bytesTrimLine(b []byte) []byte { return []byte(strings.TrimSpace(string(b))) }

func (r *linuxRuntime) LaunchID() string   { return r.launchID }
func (r *linuxRuntime) Generation() uint64 { r.mu.Lock(); defer r.mu.Unlock(); return r.generation }
func (r *linuxRuntime) Processes() map[string]ProcessIdentity {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]ProcessIdentity, len(r.identities))
	for k, v := range r.identities {
		out[k] = v
	}
	return out
}
func (r *linuxRuntime) ChildExits() <-chan ChildExit { return r.exits }
func (r *linuxRuntime) trackChild(name string, cmd *exec.Cmd, done chan error) error {
	start, err := readProcStartTime(cmd.Process.Pid)
	if err != nil {
		return err
	}
	r.identities[name] = ProcessIdentity{PID: cmd.Process.Pid, StartTime: start}
	go func() {
		err := cmd.Wait()
		if name == "hostnet-helper" {
			r.helperExitErr = err
			close(r.helperExited)
		} else {
			r.slirpExitErr = err
			close(r.slirpExited)
		}
		done <- err
		select {
		case r.exits <- ChildExit{Name: name, Err: err}:
		default:
		}
	}()
	return nil
}
func (r *linuxRuntime) TakeTapFile() *os.File {
	r.mu.Lock()
	defer r.mu.Unlock()
	f := r.tap
	r.tap = nil
	return f
}
func (r *linuxRuntime) TakeMaintenanceTapFile() *os.File {
	r.mu.Lock()
	defer r.mu.Unlock()
	f := r.maintenanceTap
	r.maintenanceTap = nil
	return f
}
func (r *linuxRuntime) TakeDNSSockets() (*os.File, *os.File) {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, t := r.dnsUDP, r.dnsTCP
	r.dnsUDP = nil
	r.dnsTCP = nil
	return u, t
}
func (r *linuxRuntime) TakeSupervisorExitWriter() *os.File {
	r.mu.Lock()
	defer r.mu.Unlock()
	f := r.exitWriter
	r.exitWriter = nil
	return f
}

func (r *linuxRuntime) ApplyPolicy(ctx context.Context, p PolicySnapshot) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.applyPolicyLocked(ctx, p)
}

func (r *linuxRuntime) SetNetworkLease(ctx context.Context, launchID string, deadline time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if launchID != r.launchID {
		return errors.New("network lease launch identity mismatch")
	}
	if !deadline.After(time.Now()) {
		return errors.New("network lease deadline must be in the future")
	}
	return r.requestContext(ctx, helperRequest{Operation: "set-network-lease", LaunchID: launchID, Generation: r.generation, Deadline: deadline.UnixNano()})
}

func (r *linuxRuntime) SetFullNetworkLease(ctx context.Context, launchID string, deadline time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if launchID != r.launchID {
		return errors.New("full-network lease launch identity mismatch")
	}
	var deadlineNano int64
	if !deadline.IsZero() {
		if !deadline.After(time.Now()) {
			return errors.New("full-network lease deadline must be in the future")
		}
		deadlineNano = deadline.UnixNano()
	}
	return r.requestContext(ctx, helperRequest{Operation: "set-full-network-lease", LaunchID: launchID, Generation: r.generation, Deadline: deadlineNano})
}

func (r *linuxRuntime) StartMaintenanceSession(ctx context.Context, launchID, sessionID string, deadline time.Time) (MaintenanceSession, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if launchID != r.launchID || sessionID == "" {
		return MaintenanceSession{}, errors.New("maintenance session identity is invalid")
	}
	if !deadline.After(time.Now()) || deadline.After(time.Now().Add(maximumKernelLease)) {
		return MaintenanceSession{}, errors.New("maintenance session deadline is outside the kernel bound")
	}
	response, err := r.requestContextReply(ctx, helperRequest{Operation: "start-maintenance-session", LaunchID: launchID, Generation: r.generation, SessionID: sessionID, Deadline: deadline.UnixNano()})
	if err != nil {
		return MaintenanceSession{}, err
	}
	host, err := netip.ParseAddr(response.HostAddress)
	if err != nil {
		return MaintenanceSession{}, err
	}
	guest, err := netip.ParseAddr(response.GuestAddress)
	if err != nil {
		return MaintenanceSession{}, err
	}
	if host.String() != MaintenanceHostAddress || guest.String() != MaintenanceGuestAddress {
		return MaintenanceSession{}, errors.New("helper returned unexpected maintenance addresses")
	}
	return MaintenanceSession{HostAddress: host, GuestAddress: guest}, nil
}

func (r *linuxRuntime) RenewMaintenanceSession(ctx context.Context, launchID, sessionID string, deadline time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if launchID != r.launchID || sessionID == "" || !deadline.After(time.Now()) || deadline.After(time.Now().Add(maximumKernelLease)) {
		return errors.New("maintenance session identity or deadline is invalid")
	}
	return r.requestContext(ctx, helperRequest{Operation: "renew-maintenance-session", LaunchID: launchID, Generation: r.generation, SessionID: sessionID, Deadline: deadline.UnixNano()})
}

func (r *linuxRuntime) StopMaintenanceSession(ctx context.Context, launchID, sessionID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if launchID != r.launchID || sessionID == "" {
		return errors.New("maintenance session identity is invalid")
	}
	return r.requestContext(ctx, helperRequest{Operation: "stop-maintenance-session", LaunchID: launchID, Generation: r.generation, SessionID: sessionID})
}

func (r *linuxRuntime) applyPolicyLocked(ctx context.Context, p PolicySnapshot) error {
	if p.LaunchID != r.launchID {
		return errors.New("host policy launch identity mismatch")
	}
	if p.Generation <= r.generation {
		return errors.New("host policy generation must increase")
	}
	grants, err := cleanIPv4Addresses(p.IPGrants)
	if err != nil {
		return err
	}
	raw := make([]string, 0, len(grants))
	for _, a := range grants {
		raw = append(raw, a.String())
	}
	if err := r.requestContext(ctx, helperRequest{Operation: "apply-policy", LaunchID: r.launchID, Generation: p.Generation, Grants: raw}); err != nil {
		return err
	}
	r.generation = p.Generation
	r.grants = grants
	return nil
}

func (r *linuxRuntime) ReplaceDNSLeases(ctx context.Context, launchID string, generation uint64, leases map[string]map[netip.Addr]time.Time, names map[string]time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if launchID != r.launchID {
		return errors.New("DNS lease launch identity mismatch")
	}
	if generation != r.generation {
		return errors.New("DNS lease policy generation is stale")
	}
	items := make([]leaseRecord, 0)
	for name, addresses := range leases {
		for a, expiry := range addresses {
			if !a.Is4() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsPrivate() {
				return fmt.Errorf("DNS lease is not a permitted global IPv4 address: %s", a)
			}
			items = append(items, leaseRecord{Name: name, Address: a.String(), Expires: expiry.UnixNano()})
		}
	}
	permissions := make(map[string]int64, len(names))
	for name, deadline := range names {
		if deadline.IsZero() {
			permissions[name] = 0
		} else {
			permissions[name] = deadline.UnixNano()
		}
	}
	return r.requestContext(ctx, helperRequest{Operation: "replace-dns-leases", LaunchID: launchID, Generation: generation, Leases: items, DNSNames: permissions})
}

func (r *linuxRuntime) AddForward(ctx context.Context, launchID string, generation uint64, f Forward) error {
	return r.changeForward(ctx, launchID, generation, f, true)
}
func (r *linuxRuntime) RemoveForward(ctx context.Context, launchID string, generation uint64, f Forward) error {
	return r.changeForward(ctx, launchID, generation, f, false)
}
func (r *linuxRuntime) changeForward(ctx context.Context, id string, g uint64, f Forward, add bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if id != r.launchID {
		return errors.New("forward launch identity mismatch")
	}
	if g != r.generation {
		return errors.New("forward policy generation is stale")
	}
	if f.Protocol != "tcp" && f.Protocol != "udp" {
		return errors.New("forward protocol must be tcp or udp")
	}
	if f.HostPort == 0 || f.GuestPort == 0 {
		return errors.New("forward ports must be nonzero")
	}
	found := -1
	for i, x := range r.forward {
		if x == f {
			found = i
			break
		}
	}
	if add {
		if found >= 0 {
			return nil
		}
		apiID, err := r.apiForward(ctx, "add_hostfwd", f)
		if err != nil {
			return err
		}
		sharedGuestPort := false
		for _, x := range r.forward {
			if x.Protocol == f.Protocol && x.GuestPort == f.GuestPort {
				sharedGuestPort = true
				break
			}
		}
		if !sharedGuestPort {
			if err := r.requestContext(ctx, helperRequest{Operation: "forward-add", LaunchID: r.launchID, Generation: r.generation, Forward: &f}); err != nil {
				_ = r.apiRemoveForward(ctx, apiID)
				return err
			}
		}
		r.forwardIDs[f] = apiID
		r.forward = append(r.forward, f)
	}
	if !add && found >= 0 {
		id := r.forwardIDs[f]
		sharedGuestPort := false
		for i, x := range r.forward {
			if i != found && x.Protocol == f.Protocol && x.GuestPort == f.GuestPort {
				sharedGuestPort = true
				break
			}
		}
		if !sharedGuestPort {
			if err := r.requestContext(ctx, helperRequest{Operation: "forward-remove", LaunchID: r.launchID, Generation: r.generation, Forward: &f}); err != nil {
				return err
			}
		}
		if err := r.apiRemoveForward(ctx, id); err != nil {
			_ = r.requestContext(context.Background(), helperRequest{Operation: "forward-add", LaunchID: r.launchID, Generation: r.generation, Forward: &f})
			return err
		}
		delete(r.forwardIDs, f)
		r.forward = append(r.forward[:found], r.forward[found+1:]...)
	}
	return nil
}
func (r *linuxRuntime) ListForwards(context.Context) ([]Forward, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Forward(nil), r.forward...), nil
}

func (r *linuxRuntime) request(req helperRequest) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return r.requestContext(ctx, req)
}
func (r *linuxRuntime) requestContext(ctx context.Context, req helperRequest) error {
	_, err := r.requestContextReply(ctx, req)
	return err
}
func (r *linuxRuntime) requestContextReply(ctx context.Context, req helperRequest) (helperResponse, error) {
	if r.conn == nil {
		return helperResponse{}, errors.New("host network controller is disconnected")
	}
	if err := ctx.Err(); err != nil {
		return helperResponse{}, err
	}
	requestTimeout := 5 * time.Second
	if req.Operation == "start-maintenance-session" {
		requestTimeout = 12 * time.Second
	}
	rpcCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req.RequestNotAfter = deadlineFor(rpcCtx, requestTimeout).UnixNano()
	conn := r.conn
	// A timed-out request remains in flight on the shared stream. The helper
	// rejects it as expired when it resumes, and the response reader drains that
	// reply before this method sends another request. Closing the stream here
	// would make a temporarily stalled helper exit on EOF.
	for r.pending > 0 {
		if r.pendingWrite != nil {
			select {
			case err := <-r.pendingWrite:
				r.pendingWrite = nil
				if err != nil {
					r.pending--
					r.poisonControl(conn)
					return helperResponse{}, err
				}
			case <-rpcCtx.Done():
				return helperResponse{}, rpcCtx.Err()
			}
		}
		select {
		case result := <-r.responseQueue:
			r.pending--
			if result.err != nil {
				r.poisonControl(conn)
				return helperResponse{}, result.err
			}
			// This is the response for a request whose caller already timed out.
			// Its late result cannot satisfy the new request being prepared here.
		case <-rpcCtx.Done():
			return helperResponse{}, rpcCtx.Err()
		}
	}
	if err := rpcCtx.Err(); err != nil {
		return helperResponse{}, err
	}
	b, err := json.Marshal(req)
	if err != nil {
		return helperResponse{}, err
	}
	b = append(b, '\n')
	r.pending++
	writeDone := make(chan error, 1)
	r.pendingWrite = writeDone
	go func() { writeDone <- writeHelperRequest(conn, b) }()
	select {
	case err := <-writeDone:
		r.pendingWrite = nil
		if err != nil {
			r.pending--
			r.poisonControl(conn)
			return helperResponse{}, err
		}
	case <-rpcCtx.Done():
		return helperResponse{}, rpcCtx.Err()
	}
	select {
	case result := <-r.responseQueue:
		r.pending--
		if result.err != nil {
			r.poisonControl(conn)
			return helperResponse{}, result.err
		}
		if err := rpcCtx.Err(); err != nil {
			return helperResponse{}, err
		}
		if !result.response.OK {
			return helperResponse{}, errors.New(result.response.Error)
		}
		return result.response, nil
	case <-rpcCtx.Done():
		return helperResponse{}, rpcCtx.Err()
	}
}

func writeHelperRequest(conn *net.UnixConn, request []byte) error {
	for len(request) > 0 {
		n, err := conn.Write(request)
		if err != nil {
			return err
		}
		if n == 0 {
			return errors.New("short write to host network helper")
		}
		request = request[n:]
	}
	return nil
}

func (r *linuxRuntime) poisonControl(conn *net.UnixConn) {
	_ = conn.Close()
	if r.conn == conn {
		r.conn = nil
	}
}

func (r *linuxRuntime) readResponses() {
	for r.responses.Scan() {
		var response helperResponse
		if err := json.Unmarshal(r.responses.Bytes(), &response); err != nil {
			r.queueResponse(helperResponseResult{err: fmt.Errorf("decode bounded helper response: %w", err)})
			return
		}
		if !r.queueResponse(helperResponseResult{response: response}) {
			return
		}
	}
	err := r.responses.Err()
	if err == nil {
		err = errors.New("host network helper closed control channel")
	}
	r.queueResponse(helperResponseResult{err: err})
}

func (r *linuxRuntime) queueResponse(result helperResponseResult) bool {
	select {
	case r.responseQueue <- result:
		return true
	case <-r.responseStop:
		return false
	}
}

func deadlineFor(ctx context.Context, maximum time.Duration) time.Time {
	deadline := time.Now().Add(maximum)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		return d
	}
	return deadline
}

func (r *linuxRuntime) apiForward(ctx context.Context, execute string, f Forward) (string, error) {
	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", r.apiSocket)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	request := map[string]any{"execute": execute, "arguments": map[string]any{"proto": f.Protocol, "host_addr": "127.0.0.1", "host_port": f.HostPort, "guest_addr": "10.0.3.100", "guest_port": f.GuestPort}}
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return "", err
	}
	_ = conn.SetDeadline(deadlineFor(ctx, 2*time.Second))
	var response map[string]any
	dec := json.NewDecoder(conn)
	dec.UseNumber()
	if err := dec.Decode(&response); err != nil {
		return "", err
	}
	if e, ok := response["error"]; ok {
		return "", fmt.Errorf("slirp forward API: %v", e)
	}
	if result, ok := response["return"].(map[string]any); ok {
		if id, ok := result["id"].(json.Number); ok && id.String() != "" {
			return id.String(), nil
		}
	}
	if execute == "remove_hostfwd" {
		return "", nil
	}
	return "", errors.New("slirp forward API omitted forwarding ID")
}
func (r *linuxRuntime) apiRemoveForward(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("missing slirp forwarding ID")
	}
	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", r.apiSocket)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadlineFor(ctx, 2*time.Second))
	parsedID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return errors.New("invalid slirp forwarding ID")
	}
	if err := json.NewEncoder(conn).Encode(map[string]any{"execute": "remove_hostfwd", "arguments": map[string]any{"id": parsedID}}); err != nil {
		return err
	}
	var resp map[string]any
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return err
	}
	if e, ok := resp["error"]; ok {
		return fmt.Errorf("slirp remove forward API: %v", e)
	}
	return nil
}

func (r *linuxRuntime) Stop(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return nil
	}
	r.stopped = true
	var errs []error
	r.responseOnce.Do(func() { close(r.responseStop) })
	if r.conn != nil {
		if r.pending == 0 {
			_ = r.conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
			_ = json.NewEncoder(r.conn).Encode(helperRequest{Operation: "stop", LaunchID: r.launchID, Generation: r.generation})
		}
		_ = r.conn.Close()
		r.conn = nil
	}
	if r.exitWriter != nil {
		_ = r.exitWriter.Close()
		r.exitWriter = nil
	}
	for _, p := range []*exec.Cmd{r.slirp, r.helper} {
		if p != nil && p.Process != nil {
			_ = p.Process.Signal(syscall.SIGTERM)
			done := r.helperDone
			if p == r.slirp {
				done = r.slirpDone
			}
			select {
			case err := <-done:
				if err != nil {
					var ee *exec.ExitError
					if !errors.As(err, &ee) {
						errs = append(errs, err)
					}
				}
			case <-ctx.Done():
				_ = p.Process.Kill()
				<-done
				errs = append(errs, ctx.Err())
			case <-time.After(2 * time.Second):
				_ = p.Process.Kill()
				<-done
			}
		}
	}
	if r.tap != nil {
		_ = r.tap.Close()
		r.tap = nil
	}
	if r.maintenanceTap != nil {
		_ = r.maintenanceTap.Close()
		r.maintenanceTap = nil
	}
	closeFiles(r.dnsUDP, r.dnsTCP)
	r.dnsUDP = nil
	r.dnsTCP = nil
	r.eventMu.Lock()
	if !r.eventClosed {
		r.eventClosed = true
		close(r.eventChanged)
	}
	r.eventMu.Unlock()
	if r.eventRead != nil {
		_ = r.eventRead.Close()
	}
	_ = os.Remove(r.apiSocket)
	return errors.Join(errs...)
}

func readProcStartTime(pid int) (string, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", err
	}
	line := string(b)
	end := strings.LastIndex(line, ")")
	if end < 0 {
		return "", errors.New("malformed process stat")
	}
	fields := strings.Fields(line[end+1:])
	if len(fields) < 20 {
		return "", errors.New("short process stat")
	}
	return fields[19], nil
}
