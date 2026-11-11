// Package vmssh owns the persistent SSH transports for one supervised VM and
// exposes them to short-lived CLI processes through a private Unix socket.
package vmssh

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mdlayher/socket"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

const (
	protocolVersion = 1
	maxFrameBytes   = 1 << 20
	copyBufferSize  = 32 << 10
	setupTimeout    = 15 * time.Second
	setupCancelWait = 500 * time.Millisecond
	roleDialTimeout = 8 * time.Second
	requestQueueLen = 32
	maxRoleSetups   = 32
)

// DialFunc opens a connection to guest SSH. It is injectable so the session
// path can be exercised without requiring a VM; production uses DialVSock.
type DialFunc func(context.Context, uint32, uint32) (net.Conn, error)

// DialVSock opens a context-cancellable host-to-guest AF_VSOCK connection.
// It opens and connects the socket directly so the operation can honor ctx.
func DialVSock(ctx context.Context, cid, port uint32) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conn, err := socket.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0, "vsock", nil)
	if err != nil {
		return nil, fmt.Errorf("open guest vsock CID %d port %d: %w", cid, port, err)
	}
	remote, err := conn.Connect(ctx, &unix.SockaddrVM{CID: cid, Port: port})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("dial guest vsock CID %d port %d: %w", cid, port, err)
	}
	local, err := conn.Getsockname()
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("get local vsock address: %w", err)
	}
	localVM, localOK := local.(*unix.SockaddrVM)
	remoteVM, remoteOK := remote.(*unix.SockaddrVM)
	if !localOK || !remoteOK {
		_ = conn.Close()
		return nil, fmt.Errorf("vsock connect returned an unexpected address type")
	}
	return &vsockConn{Conn: conn, local: vmAddr{cid: localVM.CID, port: localVM.Port}, remote: vmAddr{cid: remoteVM.CID, port: remoteVM.Port}}, nil
}

type vmAddr struct {
	cid  uint32
	port uint32
}

func (addr vmAddr) Network() string { return "vsock" }
func (addr vmAddr) String() string  { return fmt.Sprintf("%d:%d", addr.cid, addr.port) }

type vsockConn struct {
	*socket.Conn
	local, remote net.Addr
}

func (conn *vsockConn) LocalAddr() net.Addr  { return conn.local }
func (conn *vsockConn) RemoteAddr() net.Addr { return conn.remote }

// Request describes one SSH channel. User must be "root" or "user". A PTY
// request can either run a command or start a login shell when Command is empty.
type Request struct {
	User     string `json:"user"`
	Command  string `json:"command,omitempty"`
	PTY      bool   `json:"pty,omitempty"`
	Terminal string `json:"terminal,omitempty"`
	Width    int    `json:"width,omitempty"`
	Height   int    `json:"height,omitempty"`
	ForcePTY bool   `json:"force_pty,omitempty"`
	Input    bool   `json:"input,omitempty"`
	// Env holds the caller's locale and color settings (see ForwardedEnv).
	// The guest's sshd ignores names outside its AcceptEnv list.
	Env     map[string]string `json:"env,omitempty"`
	Version int               `json:"version"`
}

// ForwardedEnv picks the variables OpenSSH sends by default (Debian's
// "SendEnv LANG LC_* COLORTERM NO_COLOR") out of environ, so commands in the
// guest use the host terminal's language, character set and colors, as they
// did when zaigr ran the ssh client.
func ForwardedEnv(environ []string) map[string]string {
	var env map[string]string
	for _, entry := range environ {
		name, value, ok := strings.Cut(entry, "=")
		if !ok || !forwardableEnv(name, value) {
			continue
		}
		if env == nil {
			env = make(map[string]string)
		}
		env[name] = value
	}
	return env
}

func forwardableEnv(name, value string) bool {
	if len(value) > 256 || strings.ContainsRune(value, 0) {
		return false
	}
	switch name {
	case "LANG", "COLORTERM", "NO_COLOR":
		return true
	}
	suffix, ok := strings.CutPrefix(name, "LC_")
	if !ok || suffix == "" {
		return false
	}
	for _, r := range suffix {
		if (r < 'A' || r > 'Z') && r != '_' {
			return false
		}
	}
	return true
}

type frame struct {
	Type   string `json:"type"`
	Data   []byte `json:"data,omitempty"`
	Signal string `json:"signal,omitempty"`
	Width  int    `json:"width,omitempty"`
	Height int    `json:"height,omitempty"`
	Status int    `json:"status,omitempty"`
	Error  string `json:"error,omitempty"`
}

type roleClient struct {
	client *ssh.Client
	user   string
}

type roleReconnect struct {
	done   chan struct{}
	client *ssh.Client
	err    error
}

// Broker owns one long-lived SSH transport per guest identity and a local RPC
// listener used by CLI processes that attach commands or terminals.
type Broker struct {
	cid      uint32
	socket   string
	dial     DialFunc
	keys     map[string]ssh.Signer
	listener *net.UnixListener

	ctx    context.Context
	cancel context.CancelFunc

	mu         sync.Mutex
	clients    map[string]*ssh.Client
	roleErrs   map[string]error
	dialErrs   map[string]error
	reconnects map[string]*roleReconnect
	setups     map[string]chan struct{}
	active     map[*net.UnixConn]struct{}
	ready      map[string]chan error
	closeErr   error
	wg         sync.WaitGroup
}

// Start opens the private RPC socket and begins establishing persistent
// authenticated SSH connections to the guest's vsock port 22.
func Start(ctx context.Context, cid uint32, socket, rootKeyPath, userKeyPath string, dial DialFunc) (*Broker, error) {
	if cid < 3 {
		return nil, fmt.Errorf("guest vsock CID must be at least 3")
	}
	if socket == "" || !filepath.IsAbs(socket) {
		return nil, fmt.Errorf("SSH broker socket path must be absolute")
	}
	if len(socket) > 107 {
		return nil, fmt.Errorf("SSH broker socket path exceeds the Unix socket path limit")
	}
	if dial == nil {
		return nil, fmt.Errorf("SSH broker dialer is required")
	}
	keys := make(map[string]ssh.Signer, 2)
	for _, item := range []struct{ user, path string }{{"root", rootKeyPath}, {"user", userKeyPath}} {
		data, err := os.ReadFile(item.path)
		if err != nil {
			return nil, fmt.Errorf("read %s SSH key: %w", item.user, err)
		}
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("parse %s SSH key: %w", item.user, err)
		}
		keys[item.user] = signer
	}

	if err := os.MkdirAll(filepath.Dir(socket), 0700); err != nil {
		return nil, fmt.Errorf("create SSH broker directory: %w", err)
	}
	if err := os.Chmod(filepath.Dir(socket), 0700); err != nil {
		return nil, fmt.Errorf("secure SSH broker directory: %w", err)
	}
	if _, err := os.Lstat(socket); err == nil {
		return nil, fmt.Errorf("SSH broker socket path already exists: %s", socket)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect SSH broker socket path: %w", err)
	}
	addr := &net.UnixAddr{Name: socket, Net: "unix"}
	listener, err := net.ListenUnix("unix", addr)
	if err != nil {
		return nil, fmt.Errorf("listen on SSH broker socket: %w", err)
	}
	if err := os.Chmod(socket, 0600); err != nil {
		_ = listener.Close()
		_ = os.Remove(socket)
		return nil, fmt.Errorf("secure SSH broker socket: %w", err)
	}
	brokerCtx, cancel := context.WithCancel(ctx)
	b := &Broker{
		cid: cid, socket: socket, dial: dial, keys: keys, listener: listener,
		ctx: brokerCtx, cancel: cancel,
		clients: make(map[string]*ssh.Client), roleErrs: make(map[string]error), dialErrs: make(map[string]error), reconnects: make(map[string]*roleReconnect), setups: map[string]chan struct{}{
			"root": make(chan struct{}, maxRoleSetups), "user": make(chan struct{}, maxRoleSetups),
		}, active: make(map[*net.UnixConn]struct{}),
		ready: map[string]chan error{"root": make(chan error, 1), "user": make(chan error, 1)},
	}
	for _, user := range []string{"root", "user"} {
		b.wg.Add(1)
		go b.connectRole(user)
	}
	b.wg.Add(1)
	go b.acceptLoop()
	return b, nil
}

func (b *Broker) connectRole(user string) {
	defer b.wg.Done()
	delay := 100 * time.Millisecond
	for {
		if err := b.ctx.Err(); err != nil {
			b.ready[user] <- err
			return
		}
		client, err := b.dialRoleClient(b.ctx, user)
		if err == nil {
			b.mu.Lock()
			if b.ctx.Err() != nil {
				b.mu.Unlock()
				_ = client.Close()
				b.ready[user] <- b.ctx.Err()
				return
			}
			b.clients[user] = client
			delete(b.dialErrs, user)
			b.mu.Unlock()
			b.ready[user] <- nil
			return
		}
		b.mu.Lock()
		b.dialErrs[user] = err
		b.mu.Unlock()
		select {
		case <-b.ctx.Done():
			b.ready[user] <- b.ctx.Err()
			return
		case <-time.After(delay):
		}
		if delay < time.Second {
			delay *= 2
			if delay > time.Second {
				delay = time.Second
			}
		}
	}
}

func (b *Broker) dialRoleClient(ctx context.Context, user string) (*ssh.Client, error) {
	connectCtx, cancel := context.WithTimeout(ctx, roleDialTimeout)
	defer cancel()
	conn, err := b.dial(connectCtx, b.cid, 22)
	if err != nil {
		return nil, err
	}
	stopCloseOnCancel := context.AfterFunc(connectCtx, func() { _ = conn.Close() })
	defer stopCloseOnCancel()
	if err := conn.SetDeadline(time.Now().Add(roleDialTimeout)); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("set guest SSH handshake deadline: %w", err)
	}
	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(b.keys[user])},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         roleDialTimeout,
	}
	clientConn, chans, reqs, err := ssh.NewClientConn(conn, fmt.Sprintf("vsock:%d:22", b.cid), config)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := connectCtx.Err(); err != nil {
		_ = clientConn.Close()
		return nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = clientConn.Close()
		return nil, fmt.Errorf("clear guest SSH handshake deadline: %w", err)
	}
	if !stopCloseOnCancel() && connectCtx.Err() != nil {
		_ = clientConn.Close()
		return nil, connectCtx.Err()
	}
	return ssh.NewClient(clientConn, chans, reqs), nil
}

// WaitReady waits until root and user SSH authentication have both succeeded.
func (b *Broker) WaitReady(ctx context.Context) error {
	for _, user := range []string{"root", "user"} {
		select {
		case err := <-b.ready[user]:
			if err != nil {
				return fmt.Errorf("wait for %s SSH readiness: %w", user, err)
			}
		case <-ctx.Done():
			b.mu.Lock()
			var details []string
			for _, pendingUser := range []string{"root", "user"} {
				if err := b.dialErrs[pendingUser]; err != nil {
					detail := err.Error()
					if len(detail) > 256 {
						detail = detail[:256] + "…"
					}
					details = append(details, pendingUser+": "+detail)
				}
			}
			b.mu.Unlock()
			if len(details) == 0 {
				return ctx.Err()
			}
			return fmt.Errorf("%w; latest SSH connection failures: %s", ctx.Err(), strings.Join(details, "; "))
		}
	}
	return nil
}

func (b *Broker) acceptLoop() {
	defer b.wg.Done()
	for {
		conn, err := b.listener.AcceptUnix()
		if err != nil {
			if b.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		b.mu.Lock()
		if b.ctx.Err() != nil {
			b.mu.Unlock()
			_ = conn.Close()
			return
		}
		b.active[conn] = struct{}{}
		b.mu.Unlock()
		b.wg.Add(1)
		go func() {
			defer b.wg.Done()
			defer func() {
				b.mu.Lock()
				delete(b.active, conn)
				b.mu.Unlock()
				_ = conn.Close()
			}()
			_ = b.serveRequest(conn)
		}()
	}
}

func (b *Broker) serveRequest(conn *net.UnixConn) error {
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	decoder := &frameDecoder{reader: bufio.NewReaderSize(conn, 64<<10)}
	var req Request
	if err := decoder.Decode(&req); err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Time{})
	if req.Version != protocolVersion {
		return b.sendFrame(conn, frame{Type: "error", Error: "unsupported SSH broker protocol version"})
	}
	if req.User != "root" && req.User != "user" {
		return b.sendFrame(conn, frame{Type: "error", Error: "invalid guest SSH identity"})
	}
	for name, value := range req.Env {
		if !forwardableEnv(name, value) {
			return b.sendFrame(conn, frame{Type: "error", Error: "invalid forwarded environment variable"})
		}
	}
	b.mu.Lock()
	client := b.clients[req.User]
	roleErr := b.roleErrs[req.User]
	b.mu.Unlock()
	if roleErr != nil {
		return b.sendFrame(conn, frame{Type: "error", Error: fmt.Sprintf("persistent %s SSH connection is unavailable after a failed session setup (%v); restart the VM", req.User, roleErr)})
	}
	if client == nil {
		return b.sendFrame(conn, frame{Type: "error", Error: "persistent guest SSH connection is unavailable; restart the VM"})
	}
	_ = conn.SetDeadline(time.Time{})
	requests := startRequestMonitor(conn, decoder, req)
	if requests.disconnectedNow() {
		return nil
	}
	setupSlots := b.setups[req.User]
	select {
	case setupSlots <- struct{}{}:
	default:
		return b.sendFrame(conn, frame{Type: "error", Error: fmt.Sprintf("too many concurrent %s SSH session setups; retry the command manually", req.User)})
	}
	var releaseSlot sync.Once
	releaseSetupSlot := func() { releaseSlot.Do(func() { <-setupSlots }) }
	defer releaseSetupSlot()
	setupDone := make(chan struct{})
	setupExpired := make(chan struct{})
	watchDone := make(chan struct{})
	setupClientMu := sync.Mutex{}
	setupClient := client
	go func() {
		defer close(watchDone)
		timer := time.NewTimer(setupTimeout)
		defer timer.Stop()
		select {
		case <-setupDone:
			return
		case <-requests.disconnected:
			grace := time.NewTimer(setupCancelWait)
			defer grace.Stop()
			select {
			case <-setupDone:
				return
			case <-grace.C:
				select {
				case <-setupDone:
					return
				default:
				}
				setupClientMu.Lock()
				expectedClient := setupClient
				setupClientMu.Unlock()
				b.failRoleTransport(req.User, expectedClient, fmt.Errorf("SSH setup remained blocked after the caller disconnected"))
			}
		case <-timer.C:
			select {
			case <-setupDone:
				return
			default:
			}
			close(setupExpired)
			setupClientMu.Lock()
			expectedClient := setupClient
			setupClientMu.Unlock()
			b.failRoleTransport(req.User, expectedClient, fmt.Errorf("SSH setup exceeded %s", setupTimeout))
		}
	}()
	finishSetup := func() {
		close(setupDone)
		<-watchDone
		releaseSetupSlot()
	}
	// NewSession opens only an SSH channel; no guest command has been issued yet.
	session, err := client.NewSession()
	if isDeadSSHTransportError(err) && !requests.disconnectedNow() && !setupExpiredNow(setupExpired) {
		replacement, reconnectErr := b.reconnectRoleClient(req.User, client)
		if reconnectErr == nil {
			client = replacement
			setupClientMu.Lock()
			setupClient = replacement
			setupClientMu.Unlock()
			if !requests.disconnectedNow() && !setupExpiredNow(setupExpired) {
				session, err = client.NewSession()
			}
		} else {
			err = errors.Join(err, fmt.Errorf("reconnect guest SSH transport: %w", reconnectErr))
		}
	}
	if err != nil {
		finishSetup()
		if requests.disconnectedNow() {
			return nil
		}
		if setupExpiredNow(setupExpired) {
			b.failRoleTransport(req.User, client, fmt.Errorf("SSH setup exceeded %s: %w", setupTimeout, err))
			return b.sendFrame(conn, frame{Type: "error", Error: fmt.Sprintf("guest SSH setup timed out while opening a channel: %v; restart the VM", err)})
		}
		if isDeadSSHTransportError(err) {
			b.failRoleTransport(req.User, client, fmt.Errorf("guest SSH channel remained unavailable after reconnect: %w", err))
		}
		return b.sendFrame(conn, frame{Type: "error", Error: fmt.Sprintf("open guest SSH channel: %v", err)})
	}
	defer session.Close()
	if requests.disconnectedNow() {
		finishSetup()
		return nil
	}
	if setupExpiredNow(setupExpired) {
		finishSetup()
		_ = session.Close()
		return b.sendFrame(conn, frame{Type: "error", Error: "guest SSH session setup exceeded its deadline; restart the VM"})
	}

	stdinReader, stdinWriter := io.Pipe()
	session.Stdin = stdinReader
	stdout, err := session.StdoutPipe()
	if err != nil {
		finishSetup()
		_ = stdinReader.Close()
		_ = stdinWriter.Close()
		return b.sendFrame(conn, frame{Type: "error", Error: err.Error()})
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		finishSetup()
		_ = stdinReader.Close()
		_ = stdinWriter.Close()
		return b.sendFrame(conn, frame{Type: "error", Error: err.Error()})
	}
	for name, value := range req.Env {
		// Like the OpenSSH client, carry on when sshd refuses a name.
		_ = session.Setenv(name, value)
	}
	pty := req.PTY || req.ForcePTY
	if requests.disconnectedNow() {
		finishSetup()
		_ = session.Close()
		_ = stdinReader.Close()
		_ = stdinWriter.Close()
		return nil
	}
	if setupExpiredNow(setupExpired) {
		finishSetup()
		_ = session.Close()
		_ = stdinReader.Close()
		_ = stdinWriter.Close()
		return b.sendFrame(conn, frame{Type: "error", Error: "guest SSH session setup exceeded its deadline; command was not started; restart the VM"})
	}
	if pty {
		term := req.Terminal
		if term == "" {
			term = "xterm-256color"
		}
		width, height := req.Width, req.Height
		if width < 1 {
			width = 80
		}
		if height < 1 {
			height = 24
		}
		modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
		if err := session.RequestPty(term, height, width, modes); err != nil {
			finishSetup()
			_ = stdinReader.Close()
			_ = stdinWriter.Close()
			if requests.disconnectedNow() {
				return nil
			}
			if setupExpiredNow(setupExpired) {
				return b.sendFrame(conn, frame{Type: "error", Error: fmt.Sprintf("guest SSH setup timed out while requesting a PTY: %v; restart the VM", err)})
			}
			return b.sendFrame(conn, frame{Type: "error", Error: fmt.Sprintf("request guest PTY: %v", err)})
		}
	}
	if requests.disconnectedNow() {
		finishSetup()
		_ = stdinReader.Close()
		_ = stdinWriter.Close()
		return nil
	}
	if setupExpiredNow(setupExpired) {
		finishSetup()
		_ = session.Close()
		_ = stdinReader.Close()
		_ = stdinWriter.Close()
		return b.sendFrame(conn, frame{Type: "error", Error: "guest SSH session setup exceeded its deadline; restart the VM"})
	}

	startIssued := false
	if pty && req.Command == "" {
		startIssued = true
		err = session.Shell()
	} else {
		if req.Command == "" {
			err = errors.New("empty command for non-shell SSH request")
		} else {
			if requests.disconnectedNow() {
				finishSetup()
				_ = stdinReader.Close()
				_ = stdinWriter.Close()
				return nil
			}
			if setupExpiredNow(setupExpired) {
				finishSetup()
				_ = session.Close()
				_ = stdinReader.Close()
				_ = stdinWriter.Close()
				return b.sendFrame(conn, frame{Type: "error", Error: "guest SSH session setup exceeded its deadline; command was not started; restart the VM"})
			}
			startIssued = true
			err = session.Start(req.Command)
		}
	}
	finishSetup()
	if err != nil {
		_ = session.Close()
		_ = stdinReader.Close()
		_ = stdinWriter.Close()
		if requests.disconnectedNow() {
			return nil
		}
		if startIssued && (setupExpiredNow(setupExpired) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed)) {
			return b.sendFrame(conn, frame{Type: "unknown", Error: fmt.Sprintf("SSH transport failed while starting the command; command outcome may be unknown: %v", err)})
		}
		return b.sendFrame(conn, frame{Type: "error", Error: fmt.Sprintf("start guest SSH session: %v", err)})
	}
	writer := &frameWriter{conn: conn}
	var output sync.WaitGroup
	output.Add(2)
	go func() {
		defer output.Done()
		if _, err := copyFrames(writer, "stdout", stdout); err != nil {
			_ = session.Close()
		}
	}()
	go func() {
		defer output.Done()
		if _, err := copyFrames(writer, "stderr", stderr); err != nil {
			_ = session.Close()
		}
	}()

	inputQueue := make(chan []byte, 1)
	inputDone := make(chan struct{})
	go func() {
		defer close(inputDone)
		for chunk := range inputQueue {
			if _, err := stdinWriter.Write(chunk); err != nil {
				_ = session.Close()
				return
			}
			if err := writer.send(frame{Type: "input-ack"}); err != nil {
				_ = session.Close()
				return
			}
		}
		_ = stdinWriter.Close()
	}()
	controlDone := make(chan struct{})
	go func() {
		defer close(controlDone)
		inputClosed := false
		closeInput := func() {
			if !inputClosed {
				inputClosed = true
				close(inputQueue)
			}
		}
		defer closeInput()
		for {
			requestEvent, ok := <-requests.events
			if !ok || requestEvent.err != nil {
				_ = session.Close()
				_ = stdinReader.Close()
				return
			}
			event := requestEvent.frame
			switch event.Type {
			case "input":
				if inputClosed {
					_ = session.Close()
					return
				}
				select {
				case inputQueue <- event.Data:
				default:
					_ = session.Close()
					_ = stdinReader.Close()
					return
				}
			case "eof":
				closeInput()
			case "resize":
				if req.PTY && event.Width > 0 && event.Height > 0 {
					_ = session.WindowChange(event.Height, event.Width)
				}
			case "signal":
				if event.Signal != "" {
					_ = session.Signal(ssh.Signal(event.Signal))
				}
			case "close":
				_ = session.Close()
				_ = stdinReader.Close()
				return
			default:
				_ = session.Close()
				_ = stdinReader.Close()
				return
			}
		}
	}()

	waitErr := session.Wait()
	_ = stdinReader.Close()
	_ = conn.SetReadDeadline(time.Now())
	<-controlDone
	<-inputDone
	output.Wait()
	if waitErr != nil {
		var exitErr *ssh.ExitError
		if errors.As(waitErr, &exitErr) {
			return writer.send(frame{Type: "exit", Status: exitErr.ExitStatus()})
		}
		return writer.send(frame{Type: "unknown", Error: waitErr.Error()})
	}
	return writer.send(frame{Type: "exit", Status: 0})
}

type requestEvent struct {
	frame frame
	err   error
}

type requestMonitor struct {
	events       chan requestEvent
	disconnected chan struct{}
}

func startRequestMonitor(conn *net.UnixConn, decoder *frameDecoder, req Request) *requestMonitor {
	monitor := &requestMonitor{
		events:       make(chan requestEvent, requestQueueLen),
		disconnected: make(chan struct{}),
	}
	go func() {
		defer close(monitor.events)
		markDisconnected := func() {
			select {
			case <-monitor.disconnected:
			default:
				close(monitor.disconnected)
			}
		}
		for {
			var event frame
			if err := decoder.Decode(&event); err != nil {
				markDisconnected()
				select {
				case monitor.events <- requestEvent{err: err}:
				default:
				}
				return
			}
			if err := validateRequestEvent(event, req); err != nil {
				markDisconnected()
				_ = conn.Close()
				select {
				case monitor.events <- requestEvent{err: err}:
				default:
				}
				return
			}
			if event.Type == "close" {
				markDisconnected()
				select {
				case monitor.events <- requestEvent{frame: event}:
				default:
				}
				return
			}
			select {
			case monitor.events <- requestEvent{frame: event}:
			default:
				markDisconnected()
				_ = conn.Close()
				return
			}
		}
	}()
	return monitor
}

func validateRequestEvent(event frame, req Request) error {
	pty := req.PTY || req.ForcePTY
	switch event.Type {
	case "input":
		if !req.Input || len(event.Data) > copyBufferSize {
			return fmt.Errorf("invalid or oversized SSH input frame")
		}
	case "eof", "close":
		if len(event.Data) != 0 {
			return fmt.Errorf("unexpected data in SSH %s frame", event.Type)
		}
	case "resize":
		if !pty || len(event.Data) != 0 || event.Width < 1 || event.Height < 1 {
			return fmt.Errorf("invalid SSH resize frame")
		}
	case "signal":
		if !pty || len(event.Data) != 0 || event.Signal == "" {
			return fmt.Errorf("invalid SSH signal frame")
		}
	default:
		return fmt.Errorf("invalid SSH request event %q", event.Type)
	}
	return nil
}

func (monitor *requestMonitor) disconnectedNow() bool {
	select {
	case <-monitor.disconnected:
		return true
	default:
		return false
	}
}

func setupExpiredNow(expired <-chan struct{}) bool {
	select {
	case <-expired:
		return true
	default:
		return false
	}
}

func isDeadSSHTransportError(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed)
}

func (b *Broker) reconnectRoleClient(user string, failed *ssh.Client) (*ssh.Client, error) {
	// Coalesce callers for this failed transport; later failures recover only
	// when a fresh request observes them, with no background retry loop.
	b.mu.Lock()
	if roleErr := b.roleErrs[user]; roleErr != nil {
		b.mu.Unlock()
		return nil, roleErr
	}
	if current := b.clients[user]; current != failed {
		if current != nil {
			b.mu.Unlock()
			return current, nil
		}
		b.mu.Unlock()
		return nil, errors.New("persistent guest SSH connection disappeared during recovery")
	}
	if reconnect := b.reconnects[user]; reconnect != nil {
		b.mu.Unlock()
		select {
		case <-reconnect.done:
			return reconnect.client, reconnect.err
		case <-b.ctx.Done():
			return nil, b.ctx.Err()
		}
	}
	reconnect := &roleReconnect{done: make(chan struct{})}
	b.reconnects[user] = reconnect
	b.mu.Unlock()

	replacement, reconnectErr := b.dialRoleClient(b.ctx, user)
	var closeOld, closeReplacement *ssh.Client
	b.mu.Lock()
	if reconnectErr == nil && b.ctx.Err() != nil {
		reconnectErr = b.ctx.Err()
	}
	if reconnectErr == nil {
		if roleErr := b.roleErrs[user]; roleErr != nil {
			reconnectErr = roleErr
		} else if b.clients[user] != failed {
			if current := b.clients[user]; current != nil {
				reconnect.client = current
			} else {
				reconnectErr = errors.New("persistent guest SSH connection changed during recovery")
			}
		} else {
			b.clients[user] = replacement
			delete(b.dialErrs, user)
			reconnect.client = replacement
			closeOld = failed
			replacement = nil
		}
	}
	if reconnectErr != nil && b.ctx.Err() == nil && b.roleErrs[user] == nil {
		b.roleErrs[user] = fmt.Errorf("reconnect guest SSH transport: %w", reconnectErr)
		reconnectErr = b.roleErrs[user]
		if b.clients[user] == failed {
			closeOld = failed
			b.clients[user] = nil
		}
	}
	if replacement != nil {
		closeReplacement = replacement
	}
	reconnect.err = reconnectErr
	if b.reconnects[user] == reconnect {
		delete(b.reconnects, user)
	}
	close(reconnect.done)
	b.mu.Unlock()

	if closeOld != nil {
		_ = closeOld.Close()
	}
	if closeReplacement != nil {
		_ = closeReplacement.Close()
	}
	if reconnect.err != nil {
		return nil, reconnect.err
	}
	return reconnect.client, nil
}

func (b *Broker) failRoleTransport(user string, expected *ssh.Client, cause error) {
	b.mu.Lock()
	if b.roleErrs[user] != nil || b.clients[user] != expected {
		b.mu.Unlock()
		return
	}
	b.roleErrs[user] = cause
	client := b.clients[user]
	b.mu.Unlock()
	if client != nil {
		_ = client.Close()
	}
}

type frameWriter struct {
	conn *net.UnixConn
	mu   sync.Mutex
}

func (writer *frameWriter) send(value frame) error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	_ = writer.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	return json.NewEncoder(writer.conn).Encode(value)
}

func (b *Broker) sendFrame(conn *net.UnixConn, value frame) error {
	return (&frameWriter{conn: conn}).send(value)
}

func copyFrames(writer *frameWriter, kind string, source io.Reader) (int64, error) {
	buffer := make([]byte, copyBufferSize)
	var total int64
	for {
		n, err := source.Read(buffer)
		if n > 0 {
			if sendErr := writer.send(frame{Type: kind, Data: append([]byte(nil), buffer[:n]...)}); sendErr != nil {
				return total, sendErr
			}
			total += int64(n)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return total, nil
			}
			return total, err
		}
	}
}

// Close tears down the local broker and both persistent SSH transports. It
// never retries an in-flight command; the caller receives an unknown-outcome
// error if its RPC connection disappears while a command is running.
func (b *Broker) Close() error {
	if b == nil {
		return nil
	}
	b.cancel()
	if b.listener != nil {
		_ = b.listener.Close()
	}
	b.mu.Lock()
	for conn := range b.active {
		_ = conn.Close()
	}
	for _, client := range b.clients {
		_ = client.Close()
	}
	b.mu.Unlock()
	b.wg.Wait()
	if err := os.Remove(b.socket); err != nil && !errors.Is(err, os.ErrNotExist) {
		b.closeErr = fmt.Errorf("remove SSH broker socket: %w", err)
	}
	return b.closeErr
}

// Run attaches one command or interactive channel to a running broker. A
// broken RPC connection returns an error and is never replayed.
func Run(ctx context.Context, socket string, req Request, input io.Reader, output, errorOutput io.Writer) error {
	return run(ctx, socket, req, input, output, errorOutput, nil)
}

// RunInteractive creates a PTY-backed SSH session through the broker. It
// restores the caller's terminal on every return and forwards resize and
// process-signal events while preserving the remote command's exit status.
//
// The local terminal stays fully raw, like OpenSSH's `ssh -t`: Ctrl+C, Ctrl+Z
// and Ctrl+\ travel to the guest as keystrokes. The guest terminal then signals
// the foreground program, or hands the key to a program that reads keys itself,
// such as an agent's terminal UI. Turning them into local signals would instead
// reach the session's first process (for a preset, its launcher) and end it.
//
// When the session ends without an exit status, for example because the VM
// stopped, the guest program never got to switch off the terminal modes it
// turned on, so RunInteractive switches them off itself.
func RunInteractive(ctx context.Context, socket, user, command string, terminal *os.File, output, errorOutput io.Writer) error {
	req := Request{User: user, Command: command, PTY: true, ForcePTY: true, Input: true, Terminal: os.Getenv("TERM"), Env: ForwardedEnv(os.Environ())}
	if req.Terminal == "" {
		req.Terminal = "xterm-256color"
	}
	interactive := false
	if terminal != nil && term.IsTerminal(int(terminal.Fd())) {
		state, err := term.MakeRaw(int(terminal.Fd()))
		if err != nil {
			return fmt.Errorf("put local terminal in raw mode: %w", err)
		}
		defer func() { _ = term.Restore(int(terminal.Fd()), state) }()
		interactive = true
		if width, height, err := term.GetSize(int(terminal.Fd())); err == nil {
			req.Width, req.Height = width, height
		}
	}
	if req.Width < 1 {
		req.Width = 80
	}
	if req.Height < 1 {
		req.Height = 24
	}
	err := run(ctx, socket, req, terminal, output, errorOutput, terminal)
	var exitErr *ExitError
	if interactive && err != nil && !errors.As(err, &exitErr) {
		_, _ = io.WriteString(terminal, terminalModeReset+"\r\n")
	}
	return err
}

// terminalModeReset switches off modes a full-screen program in the guest may
// have turned on: mouse reporting, focus events, bracketed paste, the alternate
// screen, application cursor keys and keypad, a hidden cursor, and text
// attributes. Left on, the local shell prints every mouse movement as escape
// codes. Each sequence is a no-op when its mode is already off.
const terminalModeReset = "\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1005l\x1b[?1006l\x1b[?1015l" +
	"\x1b[?1004l\x1b[?2004l\x1b[?1047l\x1b[?1l\x1b>\x1b[?25h\x1b[0m"

func run(ctx context.Context, socket string, req Request, input io.Reader, output, errorOutput io.Writer, terminal *os.File) (runErr error) {
	if req.User != "root" && req.User != "user" {
		return fmt.Errorf("invalid guest SSH identity")
	}
	if input != nil {
		req.Input = true
	}
	conn, err := dialUnix(ctx, socket)
	if err != nil {
		return err
	}
	defer conn.Close()
	if req.PTY {
		req.ForcePTY = true
	}
	req.Version = protocolVersion
	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(req); err != nil {
		return fmt.Errorf("send SSH broker request: %w", err)
	}
	decoder := &frameDecoder{reader: bufio.NewReaderSize(conn, 64<<10)}
	writeMu := sync.Mutex{}
	writeFrame := func(value frame) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		return encoder.Encode(value)
	}
	stopOnCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopOnCancel()
	var eventSignals chan os.Signal
	var stopSignals chan struct{}
	if terminal != nil {
		eventSignals = make(chan os.Signal, 16)
		stopSignals = make(chan struct{})
		signal.Notify(eventSignals, syscall.SIGWINCH, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
		defer signal.Stop(eventSignals)
		defer close(stopSignals)
		go func() {
			for {
				select {
				case <-stopSignals:
					return
				case <-ctx.Done():
					return
				case received := <-eventSignals:
					if received == syscall.SIGWINCH {
						width, height, sizeErr := term.GetSize(int(terminal.Fd()))
						if sizeErr == nil && width > 0 && height > 0 {
							_ = writeFrame(frame{Type: "resize", Width: width, Height: height})
						}
						continue
					}
					if sig, ok := received.(syscall.Signal); ok {
						if name := signalName(sig); name != "" {
							_ = writeFrame(frame{Type: "signal", Signal: name})
						}
					}
				}
			}
		}()
	}
	streamCtx, stopStream := context.WithCancel(ctx)
	inputDone := make(chan error, 1)
	inputCredits := make(chan struct{}, 1)
	inputCredits <- struct{}{}
	if req.Input && input != nil {
		go func() {
			inputDone <- streamInput(streamCtx, input, writeFrame, inputCredits)
		}()
	} else {
		inputDone <- writeFrame(frame{Type: "eof"})
	}
	defer func() {
		stopStream()
		if _, pollable := input.(*os.File); pollable {
			select {
			case inputErr := <-inputDone:
				if inputErr != nil && !errors.Is(inputErr, context.Canceled) && !errors.Is(inputErr, net.ErrClosed) {
					runErr = errors.Join(runErr, fmt.Errorf("stop terminal input stream: %w", inputErr))
				}
			case <-time.After(time.Second):
				runErr = errors.Join(runErr, errors.New("terminal input stream did not stop after SSH session ended"))
			}
		}
	}()
	for {
		var response frame
		if err := decoder.Decode(&response); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("receive guest SSH session result (command outcome may be unknown): %w", err)
		}
		switch response.Type {
		case "stdout":
			if output != nil {
				if _, err := output.Write(response.Data); err != nil {
					return err
				}
			}
		case "stderr":
			if errorOutput != nil {
				if _, err := errorOutput.Write(response.Data); err != nil {
					return err
				}
			}
		case "exit":
			if response.Status != 0 {
				return &ExitError{Status: response.Status}
			}
			return nil
		case "error":
			return errors.New(response.Error)
		case "unknown":
			return &OutcomeUnknownError{Reason: response.Error}
		case "input-ack":
			select {
			case inputCredits <- struct{}{}:
			default:
				return errors.New("unexpected SSH input credit")
			}
		default:
			return fmt.Errorf("invalid SSH broker response type %q", response.Type)
		}
	}
}

// ExitError preserves a guest command's ordinary exit status.
type ExitError struct{ Status int }

func (err *ExitError) Error() string {
	return "guest command exited with status " + strconv.Itoa(err.Status)
}

// OutcomeUnknownError means the guest command may have run but its completion
// could not be confirmed because the persistent SSH transport failed.
type OutcomeUnknownError struct{ Reason string }

func (err *OutcomeUnknownError) Error() string {
	return "guest command outcome may be unknown: " + err.Reason
}

func dialUnix(ctx context.Context, socket string) (*net.UnixConn, error) {
	if !filepath.IsAbs(socket) {
		return nil, fmt.Errorf("SSH broker socket path must be absolute")
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, fmt.Errorf("connect to SSH broker: %w", err)
	}
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("SSH broker connection is not Unix-domain")
	}
	return unixConn, nil
}

// String returns a compact printable description for broker diagnostics.
func (b *Broker) String() string {
	return fmt.Sprintf("vsock SSH broker cid=%d socket=%s", b.cid, b.socket)
}

// Ensure syscall signals map to the SSH protocol names used by x/crypto/ssh.
func signalName(sig syscall.Signal) string {
	switch sig {
	case syscall.SIGINT:
		return "INT"
	case syscall.SIGTERM:
		return "TERM"
	case syscall.SIGHUP:
		return "HUP"
	case syscall.SIGQUIT:
		return "QUIT"
	default:
		return ""
	}
}

func streamInput(ctx context.Context, input io.Reader, writeFrame func(frame) error, credits <-chan struct{}) error {
	if file, ok := input.(*os.File); ok {
		fd := int(file.Fd())
		buffer := make([]byte, copyBufferSize)
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			pollFD := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			_, err := unix.Poll(pollFD, 100)
			if err != nil {
				if errors.Is(err, syscall.EINTR) {
					continue
				}
				return err
			}
			if pollFD[0].Revents&unix.POLLNVAL != 0 {
				return os.ErrClosed
			}
			if pollFD[0].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLERR) == 0 {
				continue
			}
			n, readErr := unix.Read(fd, buffer)
			if n > 0 {
				select {
				case <-credits:
				case <-ctx.Done():
					return ctx.Err()
				}
				if err := writeFrame(frame{Type: "input", Data: append([]byte(nil), buffer[:n]...)}); err != nil {
					return err
				}
			}
			if readErr != nil {
				if errors.Is(readErr, syscall.EINTR) || errors.Is(readErr, syscall.EAGAIN) {
					continue
				}
				return readErr
			}
			if n == 0 {
				return writeFrame(frame{Type: "eof"})
			}
		}
	}
	buffer := make([]byte, copyBufferSize)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, readErr := input.Read(buffer)
		if n > 0 {
			select {
			case <-credits:
			case <-ctx.Done():
				return ctx.Err()
			}
			if err := writeFrame(frame{Type: "input", Data: append([]byte(nil), buffer[:n]...)}); err != nil {
				return err
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return writeFrame(frame{Type: "eof"})
			}
			return readErr
		}
	}
}

type frameDecoder struct{ reader *bufio.Reader }

func (decoder *frameDecoder) Decode(destination any) error {
	line := make([]byte, 0, 256)
	for {
		part, err := decoder.reader.ReadSlice('\n')
		if len(line)+len(part) > maxFrameBytes {
			return fmt.Errorf("SSH broker frame exceeds %d bytes", maxFrameBytes)
		}
		line = append(line, part...)
		if err == nil {
			return json.Unmarshal(line, destination)
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return err
		}
	}
}
