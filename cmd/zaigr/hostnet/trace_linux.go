//go:build linux

package hostnet

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"syscall"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const (
	traceLifetime    = 2 * time.Second
	maxTracedPackets = 4096
	traceNLType      = unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_TRACE
)

type tracePacket struct {
	event FirewallEvent
	seen  time.Time
}

type traceObserver struct {
	output      int
	packets     map[uint32]tracePacket
	pausedUntil time.Time
	pending     uint64
}

// startFirewallTraceObserver reads actual nftables trace verdicts. It parses
// and emits tuple fields only; any additional bytes in trace headers are
// discarded and never persisted or forwarded.
func startFirewallTraceObserver(outputFD int) {
	if outputFD < 3 {
		return
	}
	observer := &traceObserver{output: outputFD, packets: make(map[uint32]tracePacket)}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		observer.gap("could not open nftables trace listener", 0)
		return
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 1<<20); err != nil {
		observer.gap("could not size nftables trace listener", 0)
		_ = unix.Close(fd)
		return
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: 1 << (unix.NFNLGRP_NFTRACE - 1)}); err != nil {
		observer.gap("could not subscribe to nftables trace events", 0)
		_ = unix.Close(fd)
		return
	}
	go observer.run(fd)
}

func (observer *traceObserver) run(fd int) {
	defer unix.Close(fd)
	poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	buf := make([]byte, 64<<10)
	for {
		ready, pollErr := unix.Poll(poll, 1000)
		if pollErr != nil {
			if errors.Is(pollErr, unix.EINTR) {
				continue
			}
			observer.clearAndGap("nftables trace listener failed", 0)
			return
		}
		observer.expire(time.Now())
		if ready == 0 {
			observer.flushPending()
			continue
		}
		n, _, flags, from, recvErr := unix.Recvmsg(fd, buf, nil, 0)
		if recvErr != nil {
			if errors.Is(recvErr, unix.EINTR) {
				continue
			}
			if errors.Is(recvErr, unix.ENOBUFS) {
				observer.clearAndGap("kernel nftables trace buffer overflowed", 0)
				continue
			}
			observer.clearAndGap("nftables trace listener failed", 0)
			return
		}
		peer, ok := from.(*unix.SockaddrNetlink)
		if !ok || peer.Pid != 0 || flags&unix.MSG_TRUNC != 0 {
			observer.clearAndGap("invalid or truncated nftables trace notification", 0)
			continue
		}
		messages, parseErr := syscall.ParseNetlinkMessage(buf[:n])
		if parseErr != nil {
			observer.clearAndGap("could not decode nftables trace notification", 0)
			continue
		}
		for _, message := range messages {
			if int(message.Header.Type) != traceNLType {
				continue
			}
			if err := observer.consume(message.Data); err != nil {
				observer.clearAndGap("could not decode nftables packet verdict", 0)
			}
		}
	}
}

func (o *traceObserver) consume(data []byte) error {
	if len(data) < 4 {
		return errors.New("short nfgenmsg")
	}
	attrs, err := netlink.UnmarshalAttributes(data[4:])
	if err != nil {
		return err
	}
	var table, chain string
	var traceType, verdict, policy int32 = -1, -99, -99
	var traceID uint32
	var haveID bool
	var networkHeader, transportHeader []byte
	for _, attr := range attrs {
		switch attr.Type & 0x3fff {
		case unix.NFTA_TRACE_TABLE:
			table = strings.TrimRight(string(attr.Data), "\x00")
		case unix.NFTA_TRACE_CHAIN:
			chain = strings.TrimRight(string(attr.Data), "\x00")
		case unix.NFTA_TRACE_TYPE:
			if len(attr.Data) == 4 {
				traceType = int32(binary.BigEndian.Uint32(attr.Data))
			}
		case unix.NFTA_TRACE_ID:
			if len(attr.Data) == 4 {
				traceID, haveID = binary.BigEndian.Uint32(attr.Data), true
			}
		case unix.NFTA_TRACE_NETWORK_HEADER:
			networkHeader = attr.Data
		case unix.NFTA_TRACE_TRANSPORT_HEADER:
			transportHeader = attr.Data
		case unix.NFTA_TRACE_VERDICT:
			verdict, err = traceVerdict(attr.Data)
			if err != nil {
				return err
			}
		case unix.NFTA_TRACE_POLICY:
			if len(attr.Data) == 4 {
				policy = int32(binary.BigEndian.Uint32(attr.Data))
			}
		}
	}
	if table != nftTableName || !haveID {
		return nil
	}
	now := time.Now()
	if now.Before(o.pausedUntil) {
		return nil
	}
	if chain == "pre_guard" && traceType == int32(unix.NFT_TRACETYPE_RULE) && len(networkHeader) > 0 {
		packet, parseErr := firewallTupleFromHeaders(networkHeader, transportHeader)
		if parseErr != nil {
			// A terminal event without a cached tuple below reports the gap.
			return nil
		}
		if previous, ok := o.packets[traceID]; ok {
			if !sameFirewallTuple(previous.event, packet) {
				o.pause("conflicting nftables trace identifiers", now)
			}
			return nil // preserve the earliest, pre-DNAT destination
		}
		if len(o.packets) >= maxTracedPackets {
			var oldestID uint32
			var oldest time.Time
			for id, candidate := range o.packets {
				if oldest.IsZero() || candidate.seen.Before(oldest) {
					oldestID, oldest = id, candidate.seen
				}
			}
			delete(o.packets, oldestID)
			o.pause("nftables trace correlation cache is full", now)
			return nil
		}
		packet.Time = now.UTC()
		o.packets[traceID] = tracePacket{event: packet, seen: now}
	}
	decision := ""
	if traceType == int32(unix.NFT_TRACETYPE_RULE) {
		if verdict == int32(exprVerdictDrop) && (chain == "pre_guard" || chain == "input" || chain == "forward") {
			decision = "blocked"
		} else if verdict == int32(exprVerdictAccept) && (chain == "input" || chain == "forward") {
			decision = "allowed"
		}
	} else if traceType == int32(unix.NFT_TRACETYPE_POLICY) && (chain == "input" || chain == "forward") {
		if policy == int32(exprVerdictDrop) {
			decision = "blocked"
		} else if policy == int32(exprVerdictAccept) {
			decision = "allowed"
		}
	}
	if decision == "" {
		return nil
	}
	packet, ok := o.packets[traceID]
	delete(o.packets, traceID)
	if !ok {
		o.gap("terminal firewall verdict had no original packet header", 1)
		return nil
	}
	event := packet.event
	event.Time = now.UTC()
	event.Decision = decision
	o.emit(event)
	return nil
}

func firewallTupleFromHeaders(networkHeader, transportHeader []byte) (FirewallEvent, error) {
	if len(networkHeader) == 0 {
		return FirewallEvent{}, errors.New("missing network header")
	}
	var event FirewallEvent
	switch networkHeader[0] >> 4 {
	case 4:
		if len(networkHeader) < 20 {
			return event, errors.New("short IPv4 header")
		}
		var src, dst [4]byte
		copy(src[:], networkHeader[12:16])
		copy(dst[:], networkHeader[16:20])
		event.Source, event.Destination = netip.AddrFrom4(src), netip.AddrFrom4(dst)
		switch networkHeader[9] {
		case unix.IPPROTO_TCP:
			event.Protocol = "TCP"
		case unix.IPPROTO_UDP:
			event.Protocol = "UDP"
		case unix.IPPROTO_ICMP:
			event.Protocol = "ICMP"
		default:
			event.Protocol = fmt.Sprintf("IP protocol %d", networkHeader[9])
		}
	case 6:
		if len(networkHeader) < 40 {
			return event, errors.New("short IPv6 header")
		}
		var src, dst [16]byte
		copy(src[:], networkHeader[8:24])
		copy(dst[:], networkHeader[24:40])
		event.Source, event.Destination = netip.AddrFrom16(src), netip.AddrFrom16(dst)
		switch networkHeader[6] {
		case unix.IPPROTO_TCP:
			event.Protocol = "TCP"
		case unix.IPPROTO_UDP:
			event.Protocol = "UDP"
		case unix.IPPROTO_ICMPV6:
			event.Protocol = "ICMPv6"
		default:
			event.Protocol = fmt.Sprintf("IPv6 next-header %d", networkHeader[6])
		}
	default:
		return event, errors.New("unknown IP version")
	}
	if event.Protocol == "TCP" || event.Protocol == "UDP" {
		if len(transportHeader) >= 4 {
			event.SourcePort = binary.BigEndian.Uint16(transportHeader[:2])
			event.DestinationPort = binary.BigEndian.Uint16(transportHeader[2:4])
			event.PortsAvailable = true
		}
	}
	return event, nil
}

const (
	exprVerdictDrop   = 0
	exprVerdictAccept = 1
)

func traceVerdict(data []byte) (int32, error) {
	attrs, err := netlink.UnmarshalAttributes(data)
	if err != nil {
		return -1, err
	}
	for _, attr := range attrs {
		if attr.Type&0x3fff == unix.NFTA_VERDICT_CODE && len(attr.Data) == 4 {
			return int32(binary.BigEndian.Uint32(attr.Data)), nil
		}
	}
	return -1, nil
}

func sameFirewallTuple(a, b FirewallEvent) bool {
	return a.Protocol == b.Protocol && a.Source == b.Source && a.Destination == b.Destination && a.SourcePort == b.SourcePort && a.DestinationPort == b.DestinationPort && a.PortsAvailable == b.PortsAvailable
}

func (o *traceObserver) pause(reason string, now time.Time) {
	o.packets = make(map[uint32]tracePacket)
	o.pausedUntil = now.Add(traceLifetime)
	o.gap(reason, 0)
}

func (o *traceObserver) expire(now time.Time) {
	var expired uint64
	for id, packet := range o.packets {
		if now.Sub(packet.seen) > traceLifetime {
			delete(o.packets, id)
			expired++
		}
	}
	if expired > 0 {
		o.gap("nftables trace verdict could not be correlated", expired)
	}
}

func (o *traceObserver) clearAndGap(reason string, count uint64) {
	o.packets = make(map[uint32]tracePacket)
	o.pausedUntil = time.Now().Add(traceLifetime)
	o.gap(reason, count)
}

func (o *traceObserver) gap(reason string, count uint64) {
	o.emit(FirewallEvent{Time: time.Now().UTC(), Gap: true, Dropped: count, Reason: reason})
}

func (o *traceObserver) emit(event FirewallEvent) {
	if o.pending > 0 && !event.Gap {
		gap := FirewallEvent{Time: time.Now().UTC(), Gap: true, Dropped: o.pending, Reason: "firewall event queue overflowed"}
		if o.write(gap) {
			o.pending = 0
		}
	}
	if !o.write(event) {
		o.pending++
	}
}

func (o *traceObserver) flushPending() {
	if o.pending == 0 {
		return
	}
	if o.write(FirewallEvent{Time: time.Now().UTC(), Gap: true, Dropped: o.pending, Reason: "firewall event queue overflowed"}) {
		o.pending = 0
	}
}

func (o *traceObserver) write(event FirewallEvent) bool {
	data, err := json.Marshal(event)
	if err != nil || len(data) > 4096 {
		return false
	}
	n, err := unix.Write(o.output, data)
	return err == nil && n == len(data)
}
