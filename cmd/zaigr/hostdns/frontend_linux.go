//go:build linux

package hostdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const frontendPollInterval = 500 * time.Millisecond

// RunFrontend serves DNS over inherited UDP/TCP sockets and forwards requests
// to the private host broker over Unix stream IPC. It refuses to handle guest
// packets unless every Linux capability set is empty and no_new_privs is set.
func RunFrontend(ctx context.Context, cfg FrontendConfig) error {
	if cfg.IPCPath == "" {
		return errors.New("host DNS frontend: private IPC path is required")
	}
	if cfg.UDPFD < 0 || cfg.TCPFD < 0 || cfg.UDPFD == cfg.TCPFD {
		return errors.New("host DNS frontend: distinct inherited UDP and TCP socket descriptors are required")
	}
	if err := requireCapabilityFreeNoNewPrivs(); err != nil {
		return err
	}
	limits := cfg.Limits
	if limits.MaxMessageBytes == 0 {
		limits.MaxMessageBytes = defaultMaxMessageBytes
	}
	if limits.MaxMessageBytes < 512 || limits.MaxMessageBytes > 65535 {
		return errors.New("host DNS frontend: message bound must be in 512..65535")
	}
	if limits.MaxConcurrent == 0 {
		limits.MaxConcurrent = defaultMaxConcurrent
	}
	if limits.MaxConcurrent < 1 || limits.MaxConcurrent > 4096 {
		return errors.New("host DNS frontend: concurrency bound must be in 1..4096")
	}
	if limits.UDPPayloadBytes == 0 {
		limits.UDPPayloadBytes = defaultUDPPayload
	}
	if limits.UDPPayloadBytes < 512 || limits.UDPPayloadBytes > 4096 {
		return errors.New("host DNS frontend: UDP payload bound must be in 512..4096")
	}
	udp, err := inheritedPacketConn(cfg.UDPFD)
	if err != nil {
		return fmt.Errorf("host DNS frontend: use inherited UDP socket: %w", err)
	}
	tcp, err := inheritedListener(cfg.TCPFD)
	if err != nil {
		udp.Close()
		return fmt.Errorf("host DNS frontend: use inherited TCP socket: %w", err)
	}
	defer udp.Close()
	defer tcp.Close()
	if err := validateListenerAddresses(udp, tcp); err != nil {
		return err
	}
	if cfg.ReadyFD > 0 {
		ready := os.NewFile(uintptr(cfg.ReadyFD), "zaigr-hostdns-ready")
		if ready == nil {
			return errors.New("host DNS frontend: invalid readiness descriptor")
		}
		if _, err := ready.Write([]byte{1}); err != nil {
			_ = ready.Close()
			return fmt.Errorf("host DNS frontend: signal readiness: %w", err)
		}
		if err := ready.Close(); err != nil {
			return fmt.Errorf("host DNS frontend: close readiness descriptor: %w", err)
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sem := make(chan struct{}, limits.MaxConcurrent)
	results := make(chan error, 2)
	stopClose := context.AfterFunc(ctx, func() {
		_ = udp.Close()
		_ = tcp.Close()
	})
	defer stopClose()
	go func() { results <- serveUDP(ctx, udp, cfg.IPCPath, limits, sem) }()
	go func() { results <- serveTCP(ctx, tcp, cfg.IPCPath, limits, sem) }()
	firstErr := <-results
	cancel()
	udp.Close()
	tcp.Close()
	secondErr := <-results
	if firstErr != nil && !errors.Is(firstErr, context.Canceled) && !errors.Is(firstErr, net.ErrClosed) {
		return firstErr
	}
	if secondErr != nil && !errors.Is(secondErr, context.Canceled) && !errors.Is(secondErr, net.ErrClosed) {
		return secondErr
	}
	return nil
}

func validateListenerAddresses(udp net.PacketConn, tcp net.Listener) error {
	const expectedIP = "10.0.2.3"
	udpAddr, ok := udp.LocalAddr().(*net.UDPAddr)
	if !ok || udpAddr.Port != 53 || udpAddr.IP.String() != expectedIP {
		return fmt.Errorf("host DNS frontend: UDP socket must be bound to %s:53", expectedIP)
	}
	tcpAddr, ok := tcp.Addr().(*net.TCPAddr)
	if !ok || tcpAddr.Port != 53 || tcpAddr.IP.String() != expectedIP {
		return fmt.Errorf("host DNS frontend: TCP socket must be bound to %s:53", expectedIP)
	}
	return nil
}

func inheritedPacketConn(fd int) (net.PacketConn, error) {
	file := os.NewFile(uintptr(fd), "zaigr-hostdns-udp")
	if file == nil {
		return nil, errors.New("invalid UDP descriptor")
	}
	conn, err := net.FilePacketConn(file)
	_ = file.Close()
	if err != nil {
		return nil, err
	}
	if _, ok := conn.(*net.UDPConn); !ok {
		conn.Close()
		return nil, fmt.Errorf("inherited UDP descriptor is %T, expected *net.UDPConn", conn)
	}
	return conn, nil
}

func inheritedListener(fd int) (net.Listener, error) {
	file := os.NewFile(uintptr(fd), "zaigr-hostdns-tcp")
	if file == nil {
		return nil, errors.New("invalid TCP descriptor")
	}
	listener, err := net.FileListener(file)
	_ = file.Close()
	if err != nil {
		return nil, err
	}
	if _, ok := listener.Addr().(*net.TCPAddr); !ok {
		listener.Close()
		return nil, fmt.Errorf("inherited TCP descriptor has address type %T", listener.Addr())
	}
	return listener, nil
}

func serveUDP(ctx context.Context, conn net.PacketConn, ipcPath string, limits FrontendLimits, sem chan struct{}) error {
	buffer := make([]byte, limits.MaxMessageBytes+1)
	var workers sync.WaitGroup
	var writeMu sync.Mutex
	for {
		if ctx.Err() != nil {
			workers.Wait()
			return nil
		}
		if err := conn.SetReadDeadline(time.Now().Add(frontendPollInterval)); err != nil {
			return err
		}
		n, peer, err := conn.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				workers.Wait()
				return nil
			}
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				continue
			}
			return fmt.Errorf("host DNS frontend UDP receive: %w", err)
		}
		if n < 12 || n > limits.MaxMessageBytes {
			continue
		}
		if ctx.Err() != nil {
			workers.Wait()
			return nil
		}
		query := append([]byte(nil), buffer[:n]...)
		select {
		case sem <- struct{}{}:
			workers.Add(1)
			go func(peer net.Addr, query []byte) {
				defer workers.Done()
				defer func() { <-sem }()
				response, err := exchangeIPC(ctx, ipcPath, peer, query, limits.MaxMessageBytes)
				if err != nil || len(response) == 0 {
					return
				}
				response, err = truncateUDPResponse(query, response, limits.UDPPayloadBytes)
				if err != nil || ctx.Err() != nil {
					return
				}
				writeMu.Lock()
				_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
				_, _ = conn.WriteTo(response, peer)
				writeMu.Unlock()
			}(peer, query)
		default:
			// Drop under load instead of allocating an unbounded request queue.
		}
	}
}

func truncateUDPResponse(queryPacket, responsePacket []byte, maxPayload int) ([]byte, error) {
	query := new(dns.Msg)
	if err := query.Unpack(queryPacket); err != nil {
		return responsePacket, nil
	}
	limit := 512
	if opt := query.IsEdns0(); opt != nil {
		limit = int(opt.UDPSize())
		if limit < 512 {
			limit = 512
		}
	}
	if limit > maxPayload {
		limit = maxPayload
	}
	response := new(dns.Msg)
	if err := response.Unpack(responsePacket); err != nil {
		return nil, err
	}
	response.Truncate(limit)
	return response.Pack()
}

func serveTCP(ctx context.Context, listener net.Listener, ipcPath string, limits FrontendLimits, sem chan struct{}) error {
	var workers sync.WaitGroup
	for {
		if ctx.Err() != nil {
			workers.Wait()
			return nil
		}
		if tcpListener, ok := listener.(*net.TCPListener); ok {
			_ = tcpListener.SetDeadline(time.Now().Add(frontendPollInterval))
		}
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				workers.Wait()
				return nil
			}
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				continue
			}
			return fmt.Errorf("host DNS frontend TCP accept: %w", err)
		}
		select {
		case sem <- struct{}{}:
			workers.Add(1)
			go func(conn net.Conn) {
				defer workers.Done()
				defer func() { <-sem }()
				defer conn.Close()
				serveTCPConn(ctx, conn, ipcPath, limits)
			}(conn)
		default:
			conn.Close()
		}
		if ctx.Err() != nil {
			workers.Wait()
			return nil
		}
	}
}

func serveTCPConn(ctx context.Context, conn net.Conn, ipcPath string, limits FrontendLimits) {
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClose()
	for requestCount := 0; requestCount < 64; requestCount++ {
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		query, err := readFrame(conn, limits.MaxMessageBytes)
		if err != nil {
			return
		}
		response, err := exchangeIPC(ctx, ipcPath, conn.RemoteAddr(), query, limits.MaxMessageBytes)
		if err != nil || len(response) == 0 {
			return
		}
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if err := writeFrame(conn, response); err != nil {
			return
		}
	}
}

func exchangeIPC(ctx context.Context, path string, peer net.Addr, query []byte, limit int) ([]byte, error) {
	var source [4]byte
	host, _, err := net.SplitHostPort(peer.String())
	if err != nil {
		return nil, errors.New("host DNS frontend could not parse query source address")
	}
	address, err := netip.ParseAddr(host)
	if err != nil || !address.Is4() {
		return nil, errors.New("host DNS frontend rejected a non-IPv4 query source")
	}
	copy(source[:], address.AsSlice())
	dialer := net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClose()
	deadline := time.Now().Add(7 * time.Second)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)
	message := make([]byte, 4+len(query))
	copy(message[:4], source[:])
	copy(message[4:], query)
	if err := writeFrame(conn, message); err != nil {
		return nil, err
	}
	return readFrame(conn, limit)
}

func requireCapabilityFreeNoNewPrivs() error {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return fmt.Errorf("host DNS frontend: inspect process capabilities: %w", err)
	}
	fields := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok {
			fields[key] = strings.TrimSpace(value)
		}
	}
	for _, key := range []string{"CapEff", "CapPrm", "CapInh", "CapBnd", "CapAmb"} {
		value, ok := fields[key]
		if !ok {
			return fmt.Errorf("host DNS frontend: process status lacks %s", key)
		}
		capabilities, err := strconv.ParseUint(value, 16, 64)
		if err != nil || capabilities != 0 {
			return fmt.Errorf("host DNS frontend: %s is not empty (%s)", key, value)
		}
	}
	if fields["NoNewPrivs"] != "1" {
		return errors.New("host DNS frontend: no_new_privs must be set before handling guest packets")
	}
	return nil
}
