//go:build linux

package hostnet

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const guestTapName = "zgr_gst"
const maintenanceTapName = "zgr_mnt"
const uplinkTapName = "zgr_upl"
const nftTableName = "zaigr"
const maximumKernelLease = 10 * time.Second
const maximumMaintenanceSessions = 16
const startupNFTablesRuleBatchSize = 24

type helperRequest struct {
	Operation       string           `json:"operation"`
	LaunchID        string           `json:"launch_id"`
	Generation      uint64           `json:"generation"`
	Grants          []string         `json:"grants,omitempty"`
	Leases          []leaseRecord    `json:"leases,omitempty"`
	DNSNames        map[string]int64 `json:"dns_names,omitempty"`
	Forward         *Forward         `json:"forward,omitempty"`
	Enabled         bool             `json:"enabled,omitempty"`
	Deadline        int64            `json:"deadline,omitempty"`
	RequestNotAfter int64            `json:"request_not_after,omitempty"`
	SessionID       string           `json:"session_id,omitempty"`
	HostAddress     string           `json:"host_address,omitempty"`
	GuestAddress    string           `json:"guest_address,omitempty"`
}

type leaseRecord struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Expires int64  `json:"expires"`
}
type helperResponse struct {
	OK           bool   `json:"ok"`
	Error        string `json:"error,omitempty"`
	Interface    string `json:"interface,omitempty"`
	HostAddress  string `json:"host_address,omitempty"`
	GuestAddress string `json:"guest_address,omitempty"`
}

type maintenanceSessionLease struct{ deadline time.Time }

func validateMaintenanceDeadline(deadline, requestNotAfter time.Time) error {
	now := time.Now()
	if !deadline.After(now) || deadline.After(now.Add(maximumKernelLease)) {
		return errors.New("maintenance session deadline is outside the kernel bound")
	}
	if !requestNotAfter.IsZero() && !requestNotAfter.After(now) {
		return errors.New("host network helper request has expired")
	}
	return nil
}

func setMaintenanceNetworkLease(deadline, requestNotAfter time.Time) error {
	if !requestNotAfter.IsZero() && !requestNotAfter.After(time.Now()) {
		return errors.New("host network helper request has expired")
	}
	c, err := nftables.New()
	if err != nil {
		return err
	}
	t := &nftables.Table{Name: nftTableName, Family: nftables.TableFamilyINet}
	s, err := c.GetSetByName(t, "maintenance_network")
	if err != nil {
		return err
	}
	addr := netip.MustParseAddr(MaintenanceGuestAddress)
	elem := nftables.SetElement{Key: addr.AsSlice()}
	items, err := c.GetSetElements(s)
	if err != nil {
		return err
	}
	for _, item := range items {
		if string(item.Key) == string(elem.Key) {
			if err := c.SetDeleteElements(s, []nftables.SetElement{elem}); err != nil {
				return err
			}
			break
		}
	}
	if !deadline.IsZero() {
		ttl := deadline.Sub(time.Now())
		if ttl <= 0 || ttl > maximumKernelLease {
			return errors.New("maintenance lease deadline is outside the kernel bound")
		}
		elem.Timeout = ttl
		if err := c.SetAddElements(s, []nftables.SetElement{elem}); err != nil {
			return err
		}
	}
	if !requestNotAfter.IsZero() && !requestNotAfter.After(time.Now()) {
		return errors.New("host network helper request has expired")
	}
	return c.Flush()
}

func maintenanceMaxDeadline(sessions map[string]maintenanceSessionLease, now time.Time) time.Time {
	var max time.Time
	for id, session := range sessions {
		if !session.deadline.After(now) {
			delete(sessions, id)
			continue
		}
		if session.deadline.After(max) {
			max = session.deadline
		}
	}
	return max
}

func maintenanceStart(req helperRequest, sessions map[string]maintenanceSessionLease) (MaintenanceSession, error) {
	if len(req.SessionID) < 16 || len(req.SessionID) > 64 {
		return MaintenanceSession{}, errors.New("invalid maintenance session identity")
	}
	deadline := time.Unix(0, req.Deadline)
	reqDeadline := helperRequestDeadline(req)
	if err := validateMaintenanceDeadline(deadline, reqDeadline); err != nil {
		return MaintenanceSession{}, err
	}
	wasActive := maintenanceMaxDeadline(sessions, time.Now()).After(time.Now())
	if _, ok := sessions[req.SessionID]; ok {
		return MaintenanceSession{}, errors.New("maintenance session ID is already active")
	}
	if len(sessions) >= maximumMaintenanceSessions {
		return MaintenanceSession{}, errors.New("maintenance session limit reached")
	}
	if !wasActive {
		if err := setMaintenanceNetworkLease(time.Time{}, reqDeadline); err != nil {
			return MaintenanceSession{}, err
		}
		if err := deleteTrackedSourceAddress(netip.MustParseAddr(MaintenanceGuestAddress)); err != nil {
			return MaintenanceSession{}, err
		}
	}
	sessions[req.SessionID] = maintenanceSessionLease{deadline: deadline}
	if err := setMaintenanceNetworkLease(maintenanceMaxDeadline(sessions, time.Now()), reqDeadline); err != nil {
		delete(sessions, req.SessionID)
		return MaintenanceSession{}, err
	}
	return MaintenanceSession{HostAddress: netip.MustParseAddr(MaintenanceHostAddress), GuestAddress: netip.MustParseAddr(MaintenanceGuestAddress)}, nil
}

func maintenanceRenew(req helperRequest, sessions map[string]maintenanceSessionLease) error {
	if len(req.SessionID) < 16 || len(req.SessionID) > 64 {
		return errors.New("invalid maintenance session identity")
	}
	item, ok := sessions[req.SessionID]
	if !ok {
		return errors.New("maintenance session does not exist")
	}
	if !item.deadline.After(time.Now()) {
		delete(sessions, req.SessionID)
		_ = setMaintenanceNetworkLease(maintenanceMaxDeadline(sessions, time.Now()), helperRequestDeadline(req))
		return errors.New("maintenance session expired and cannot be renewed")
	}
	deadline := time.Unix(0, req.Deadline)
	if err := validateMaintenanceDeadline(deadline, helperRequestDeadline(req)); err != nil {
		return err
	}
	item.deadline = deadline
	sessions[req.SessionID] = item
	return setMaintenanceNetworkLease(maintenanceMaxDeadline(sessions, time.Now()), helperRequestDeadline(req))
}

func maintenanceStop(req helperRequest, sessions map[string]maintenanceSessionLease) error {
	if len(req.SessionID) < 16 || len(req.SessionID) > 64 {
		return errors.New("invalid maintenance session identity")
	}
	delete(sessions, req.SessionID)
	max := maintenanceMaxDeadline(sessions, time.Now())
	if err := setMaintenanceNetworkLease(max, helperRequestDeadline(req)); err != nil {
		return err
	}
	return nil
}

const descriptorReadyMarker = "Z"

// RunHelper is the private re-exec entry point. Start launches it directly in
// a mapped user and private network namespace using the caller's executable.
func RunHelper(socketPath, launchID string, expectedHostUID, expectedParentPID int, hostUserNS, hostNetNS uint64, eventFD int) error {
	if launchID == "" || !filepath.IsAbs(socketPath) {
		return errors.New("invalid host network helper arguments")
	}
	if os.Geteuid() != 0 {
		return errors.New("host network helper did not enter its user namespace")
	}
	for _, item := range []struct {
		name     string
		expected uint64
	}{{"user", hostUserNS}, {"net", hostNetNS}} {
		got, err := namespaceInode("/proc/self/ns/" + item.name)
		if err != nil {
			return err
		}
		if got == item.expected {
			return fmt.Errorf("host network helper did not enter a private %s namespace", item.name)
		}
	}
	uidMap, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		return err
	}
	uidMapped := false
	for _, line := range strings.Split(string(uidMap), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "0" && fields[1] == strconv.Itoa(expectedHostUID) && fields[2] == "1" {
			uidMapped = true
			break
		}
	}
	if !uidMapped {
		return errors.New("host network helper user namespace does not map root to invoking host UID")
	}
	if err := os.MkdirAll(filepath.Dir(socketPath), 0700); err != nil {
		return err
	}
	_ = os.Remove(socketPath)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := os.Chmod(socketPath, 0600); err != nil {
		return err
	}
	if err := setUpNamespace(); err != nil {
		return err
	}
	conn, err := listener.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return errors.New("host network controller peer is not Unix")
	}
	var peer *unix.Ucred
	raw, err := uc.SyscallConn()
	if err != nil {
		return err
	}
	if err := raw.Control(func(fd uintptr) { peer, err = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return err
	}
	if err != nil {
		return err
	}
	if peer == nil || peer.Pid != int32(expectedParentPID) || peer.Uid != 0 {
		return errors.New("host network controller peer UID mismatch")
	}
	tap, err := openTap(guestTapName)
	if err != nil {
		return fmt.Errorf("open guest TAP: %w", err)
	}
	defer tap.Close()
	maintenanceTap, err := openTap(maintenanceTapName)
	if err != nil {
		return fmt.Errorf("open maintenance TAP: %w", err)
	}
	defer maintenanceTap.Close()
	if err := configureGuestTap(guestTapName); err != nil {
		return fmt.Errorf("configure guest TAP: %w", err)
	}
	if err := configureMaintenanceTap(maintenanceTapName); err != nil {
		return fmt.Errorf("configure maintenance TAP: %w", err)
	}
	if err := installDefaultPolicy(launchID); err != nil {
		return fmt.Errorf("install default host policy: %w", err)
	}
	if eventFD < 3 {
		return errors.New("host network helper has no firewall telemetry channel")
	}
	unix.CloseOnExec(eventFD)
	startFirewallTraceObserver(eventFD)
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("10.0.2.3"), Port: 53})
	if err != nil {
		return fmt.Errorf("bind guest DNS UDP socket: %w", err)
	}
	defer udp.Close()
	tcp, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("10.0.2.3"), Port: 53})
	if err != nil {
		return fmt.Errorf("bind guest DNS TCP socket: %w", err)
	}
	defer tcp.Close()
	udpFile, err := udp.File()
	if err != nil {
		return err
	}
	defer udpFile.Close()
	tcpFile, err := tcp.File()
	if err != nil {
		return err
	}
	defer tcpFile.Close()
	if err := sendFDs(conn, []*os.File{tap, maintenanceTap, udpFile, tcpFile}, descriptorReadyMarker); err != nil {
		return err
	}
	enc := json.NewEncoder(conn)
	scanner := bufio.NewScanner(conn)
	// Name identity adds up to 100,000 bounded names and 8192 lease refs.
	// Keep the private request bounded while accommodating that policy limit.
	scanner.Buffer(make([]byte, 4096), 32<<20)
	var generation uint64
	var fullLeaseDeadline time.Time
	var networkLeaseDeadline time.Time
	var conntrackGrants = make(map[netip.Addr]bool)
	dnsFlows := newDNSFlowState()
	maintenance := make(map[string]maintenanceSessionLease)
	for {
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return err
			}
			return nil
		}
		var req helperRequest
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			return fmt.Errorf("decode bounded host network request: %w", err)
		}
		resp := helperResponse{OK: true}
		if req.LaunchID != launchID {
			resp = helperResponse{Error: "launch identity mismatch"}
		} else if req.RequestNotAfter != 0 && !time.Unix(0, req.RequestNotAfter).After(time.Now()) {
			resp = helperResponse{Error: "host network helper request has expired"}
		} else if req.Generation < generation {
			resp = helperResponse{Error: "stale policy generation"}
		} else {
			switch req.Operation {
			case "apply-policy":
				if err := reconcileExpiredFullLease(&fullLeaseDeadline, conntrackGrants, dnsFlows); err != nil {
					resp.Error = err.Error()
					break
				}
				if req.Generation != generation+1 {
					resp.Error = "policy generation must advance exactly once"
					break
				}
				parsed := make([]netip.Addr, 0, len(req.Grants))
				for _, raw := range req.Grants {
					a, e := netip.ParseAddr(raw)
					if e != nil || !a.Is4() {
						resp.Error = "invalid IPv4 grant"
						break
					}
					parsed = append(parsed, a)
				}
				if resp.Error == "" {
					newManual := addressSet(parsed)
					if err := replaceGrantSetUntil(parsed, helperRequestDeadline(req)); err != nil {
						resp.Error = err.Error()
					} else {
						// Withdraw first, then remove only tuples without any remaining
						// manual or admitted DNS authorization. DNS TTL expiry is not revocation.
						removed := make(map[netip.Addr]bool)
						for address := range conntrackGrants {
							if !newManual[address] {
								removed[address] = true
							}
						}
						if err := dnsFlows.inheritLiveFlows(removed); err != nil {
							resp.Error = err.Error()
							break
						}
						if err := purgeGuestFlows(unauthorizedGuestFlowFilter{manual: newManual, dns: dnsFlows, targets: removed}); err != nil {
							resp.Error = err.Error()
							break
						}
						conntrackGrants = newManual
						generation = req.Generation
					}
				}
			case "replace-dns-leases":
				if err := reconcileExpiredFullLease(&fullLeaseDeadline, conntrackGrants, dnsFlows); err != nil {
					resp.Error = err.Error()
					break
				}
				if req.Generation != generation {
					resp.Error = "DNS lease generation does not match active policy"
					break
				}
				if err := dnsFlows.replace(req, conntrackGrants); err != nil {
					resp.Error = err.Error()
				}
			case "set-full-network-lease":
				if req.Generation != generation {
					resp.Error = "full-network lease generation does not match active policy"
					break
				}
				deadline := time.Time{}
				if req.Deadline != 0 {
					deadline = time.Unix(0, req.Deadline)
				}
				requestNotAfter := time.Time{}
				if req.RequestNotAfter != 0 {
					requestNotAfter = time.Unix(0, req.RequestNotAfter)
				}
				if err := setFullNetworkLease(&fullLeaseDeadline, deadline, conntrackGrants, dnsFlows, requestNotAfter); err != nil {
					resp.Error = err.Error()
				}
			case "start-maintenance-session":
				session, startErr := maintenanceStart(req, maintenance)
				if startErr != nil {
					resp.Error = startErr.Error()
					break
				}
				resp.HostAddress = session.HostAddress.String()
				resp.GuestAddress = session.GuestAddress.String()
			case "renew-maintenance-session":
				if err := maintenanceRenew(req, maintenance); err != nil {
					resp.Error = err.Error()
				}
			case "stop-maintenance-session":
				if err := maintenanceStop(req, maintenance); err != nil {
					resp.Error = err.Error()
				}
			case "set-network-lease":
				if req.Generation != generation || req.Deadline == 0 || !time.Unix(0, req.Deadline).After(time.Now()) {
					resp.Error = "network lease identity, generation, or deadline is invalid"
					break
				}
				requestNotAfter := time.Time{}
				if req.RequestNotAfter != 0 {
					requestNotAfter = time.Unix(0, req.RequestNotAfter)
				}
				if err := setNetworkLiveLease(&networkLeaseDeadline, time.Unix(0, req.Deadline), requestNotAfter); err != nil {
					resp.Error = err.Error()
				}
			case "configure-uplink":
				if err := configureUplink(); err != nil {
					resp.Error = err.Error()
				}
			case "forward-add", "forward-remove":
				if req.Forward == nil || (req.Forward.Protocol != "tcp" && req.Forward.Protocol != "udp") || req.Forward.GuestPort == 0 {
					resp.Error = "invalid host forward"
					break
				}
				if err := setForwardPort(req.Forward.Protocol, req.Forward.GuestPort, req.Operation == "forward-add"); err != nil {
					resp.Error = err.Error()
				}
			case "stop":
				_ = enc.Encode(helperResponse{OK: true})
				return nil
			default:
				resp.Error = "unsupported host network operation"
			}
		}
		resp.OK = resp.Error == ""
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
}

func timeUntil(unixNano int64) time.Duration { return time.Unix(0, unixNano).Sub(time.Now()) }

func addressSet(addrs []netip.Addr) map[netip.Addr]bool {
	m := make(map[netip.Addr]bool, len(addrs))
	for _, a := range addrs {
		m[a] = true
	}
	return m
}
func containsAddr(addrs []netip.Addr, a netip.Addr) bool {
	for _, x := range addrs {
		if x == a {
			return true
		}
	}
	return false
}
func deleteTrackedAddress(a netip.Addr) error {
	filter := &netlink.ConntrackFilter{}
	if err := filter.AddIP(netlink.ConntrackOrigDstIP, a.AsSlice()); err != nil {
		return fmt.Errorf("filter conntrack destination %s: %w", a, err)
	}
	if err := deleteConntrackFlows(filter); err != nil {
		return fmt.Errorf("delete conntrack for %s: %w", a, err)
	}
	return nil
}

func deleteTrackedSourceAddress(a netip.Addr) error {
	filter := &netlink.ConntrackFilter{}
	if err := filter.AddIP(netlink.ConntrackOrigSrcIP, a.AsSlice()); err != nil {
		return fmt.Errorf("filter conntrack source %s: %w", a, err)
	}
	if err := deleteConntrackFlows(filter); err != nil {
		return fmt.Errorf("delete conntrack for source %s: %w", a, err)
	}
	return nil
}

func setUpNamespace() error {
	link, err := netlink.LinkByName("lo")
	if err != nil {
		return err
	}
	return netlink.LinkSetUp(link)
}

func openTap(name string) (*os.File, error) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		f.Close()
		return nil, err
	}
	ifr.SetUint16(unix.IFF_TAP | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(int(f.Fd()), unix.TUNSETIFF, ifr); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func configureGuestTap(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	for _, cidr := range []string{"10.0.2.2/24", "10.0.2.3/24"} {
		addr, _ := netlink.ParseAddr(cidr)
		if err := netlink.AddrAdd(link, addr); err != nil && !errors.Is(err, syscall.EEXIST) {
			return err
		}
	}
	return netlink.LinkSetUp(link)
}

func configureMaintenanceTap(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	addr, _ := netlink.ParseAddr(MaintenanceHostAddress + "/24")
	if err := netlink.AddrAdd(link, addr); err != nil && !errors.Is(err, syscall.EEXIST) {
		return err
	}
	if err := netlink.LinkSetMTU(link, 1500); err != nil {
		return err
	}
	return netlink.LinkSetUp(link)
}

func configureUplink() error {
	link, err := netlink.LinkByName(uplinkTapName)
	if err != nil {
		return fmt.Errorf("slirp uplink interface is missing: %w", err)
	}
	addr, _ := netlink.ParseAddr("10.0.3.100/24")
	if err := netlink.AddrAdd(link, addr); err != nil && !errors.Is(err, syscall.EEXIST) {
		return err
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644); err != nil {
		return err
	}
	gw := net.ParseIP("10.0.3.2")
	r := netlink.Route{LinkIndex: link.Attrs().Index, Gw: gw, Dst: nil}
	if err := netlink.RouteAdd(&r); err != nil && !errors.Is(err, syscall.EEXIST) {
		return err
	}
	return nil
}

func installDefaultPolicy(launchID string) error {
	conn, err := nftables.New()
	if err != nil {
		return err
	}
	t := &nftables.Table{Name: nftTableName, Family: nftables.TableFamilyINet}
	conn.AddTable(t)
	dropPolicy := nftables.ChainPolicyDrop
	acceptPolicy := nftables.ChainPolicyAccept
	input := conn.AddChain(&nftables.Chain{Name: "input", Table: t, Hooknum: nftables.ChainHookInput, Priority: nftables.ChainPriorityFilter, Type: nftables.ChainTypeFilter, Policy: &dropPolicy})
	output := conn.AddChain(&nftables.Chain{Name: "output", Table: t, Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityFilter, Type: nftables.ChainTypeFilter, Policy: &acceptPolicy})
	fwd := conn.AddChain(&nftables.Chain{Name: "forward", Table: t, Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityFilter, Type: nftables.ChainTypeFilter, Policy: &dropPolicy})
	pre := conn.AddChain(&nftables.Chain{Name: "prerouting", Table: t, Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityNATDest, Type: nftables.ChainTypeNAT})
	post := conn.AddChain(&nftables.Chain{Name: "postrouting", Table: t, Hooknum: nftables.ChainHookPostrouting, Priority: nftables.ChainPriorityNATSource, Type: nftables.ChainTypeNAT})
	conn.AddSet(&nftables.Set{Table: t, Name: "ip_grants", KeyType: nftables.TypeIPAddr}, nil)
	conn.AddSet(&nftables.Set{Table: t, Name: "dns_leases", KeyType: nftables.TypeIPAddr, IsMap: true, DataType: nftables.TypeMark, HasTimeout: true}, nil)
	conn.AddSet(&nftables.Set{Table: t, Name: "dns_flow_marks", KeyType: nftables.TypeMark, HasTimeout: true}, nil)
	conn.AddSet(&nftables.Set{Table: t, Name: "full_network", KeyType: nftables.TypeInteger, HasTimeout: true}, nil)
	conn.AddSet(&nftables.Set{Table: t, Name: "maintenance_network", KeyType: nftables.TypeIPAddr, HasTimeout: true}, nil)
	conn.AddSet(&nftables.Set{Table: t, Name: "network_live", KeyType: nftables.TypeInteger, HasTimeout: true}, nil)
	conn.AddSet(&nftables.Set{Table: t, Name: "tcp_forward_ports", KeyType: nftables.TypeInetService}, nil)
	conn.AddSet(&nftables.Set{Table: t, Name: "udp_forward_ports", KeyType: nftables.TypeInetService}, nil)
	for _, name := range []string{"maintenance_gate_accept_to_uplink", "maintenance_gate_accept_from_uplink", "maintenance_gate_drop_to_uplink", "maintenance_gate_drop_from_uplink"} {
		conn.AddObj(&nftables.CounterObj{Table: t, Name: name})
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("install host network nftables skeleton: %w", err)
	}
	// nftables rule requests ask the kernel for echoed rule replies and ACKs
	// (NLM_F_ECHO); Conn.Flush sends the whole batch before reading any replies.
	// Keep the startup rule batch bounded to limit netlink queue pressure. The
	// count of 24 is empirically tested with a 64 KiB effective receive buffer,
	// not a guarantee for every kernel or future rule shape. This is startup-only:
	// the TAP is not handed to the parent until all policy succeeds, and live
	// grant/lease updates retain their existing atomic batches.
	startupRuleCount := 0
	var startupRuleErr error
	var flushStartupRules func() error
	addStartupRule := func(rule *nftables.Rule) {
		if startupRuleErr != nil {
			return
		}
		conn.AddRule(rule)
		startupRuleCount++
		if startupRuleCount >= startupNFTablesRuleBatchSize {
			startupRuleErr = flushStartupRules()
			startupRuleCount = 0
		}
	}
	flushStartupRules = func() error {
		if startupRuleErr != nil {
			return startupRuleErr
		}
		err := conn.Flush()
		startupRuleCount = 0
		return err
	}
	// The namespace itself is the VM identity. Only its guest TAP may forward;
	// default-drop remains in force until an exact destination grant exists.
	addStartupRule(&nftables.Rule{Table: t, Chain: input, Exprs: []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifName("lo")}, &expr.Verdict{Kind: expr.VerdictAccept},
	}})
	// DNS is reachable only on the guest-facing interface and only at the
	// broker address. The frontend sockets are inherited from this namespace.
	for _, proto := range []byte{6, 17} {
		exprs := join(matchIIF(guestTapName), networkLive(), matchIPv4(12, netip.MustParseAddr("10.0.2.15")), matchL4(proto), matchIPv4(16, netip.MustParseAddr("10.0.2.3")), matchPort(2, 53), accept())
		addStartupRule(&nftables.Rule{Table: t, Chain: input, Exprs: exprs})
	}
	// The shared maintenance namespace uses its dedicated host DNS endpoint.
	for _, proto := range []byte{6, 17} {
		addStartupRule(gateRule(t, input, join(matchIIF(maintenanceTapName), networkLive(), matchNFProto(unix.NFPROTO_IPV4), matchIPv4(12, netip.MustParseAddr(MaintenanceGuestAddress)), lookupIPv4(12, "maintenance_network"), matchL4(proto), matchIPv4(16, netip.MustParseAddr("10.0.2.3")), matchPort(2, 53)), "maintenance_dns_accept_in"))
		addStartupRule(gateRule(t, output, join(matchOIF(maintenanceTapName), networkLive(), matchNFProto(unix.NFPROTO_IPV4), matchIPv4(12, netip.MustParseAddr("10.0.2.3")), matchPort(0, 53), matchIPv4(16, netip.MustParseAddr(MaintenanceGuestAddress)), lookupIPv4(16, "maintenance_network"), matchL4(proto)), "maintenance_dns_accept_out"))
	}
	addStartupRule(gateDrop(t, input, join(matchIIF(maintenanceTapName)), "maintenance_gate_drop_to_uplink"))
	addStartupRule(gateDrop(t, output, join(matchOIF(maintenanceTapName)), "maintenance_gate_drop_from_uplink"))
	if err := flushStartupRules(); err != nil {
		return fmt.Errorf("install maintenance DNS nftables rules: %w", err)
	}
	// Drop non-IPv4 and direct uplink traffic before NAT. The guest-facing
	// 10.0.2.2 alias is the only way to reach the host; it is DNATed to slirp's
	// host alias only while that exact original destination is granted.
	guard := conn.AddChain(&nftables.Chain{Name: "pre_guard", Table: t, Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityRef(-101), Type: nftables.ChainTypeFilter})
	// Reject wrong source, inactive lease, and IPv6 at prerouting before any
	// anti-spoof or NAT rules can process ingress from the maintenance TAP.
	addStartupRule(gateDrop(t, guard, join(matchIIF(maintenanceTapName), matchNFProto(unix.NFPROTO_IPV6)), "maintenance_gate_drop_to_uplink"))
	addStartupRule(gateDrop(t, guard, join(matchIIF(maintenanceTapName), matchNFProto(unix.NFPROTO_IPV4), matchIPv4Not(12, netip.MustParseAddr(MaintenanceGuestAddress))), "maintenance_gate_drop_to_uplink"))
	addStartupRule(gateDrop(t, guard, join(matchIIF(maintenanceTapName), matchNFProto(unix.NFPROTO_IPV4), lookupIPv4Not(12, "maintenance_network")), "maintenance_gate_drop_to_uplink"))
	addStartupRule(gateDrop(t, guard, join(matchIIF(maintenanceTapName), matchNFProto(unix.NFPROTO_IPV4), matchIPv4(12, netip.MustParseAddr(MaintenanceGuestAddress)), lookupIPv4(12, "maintenance_network"), networkLiveNot()), "maintenance_gate_drop_to_uplink"))
	// NFTRACE is observer-only. Tag guest-originated packets before anti-spoof,
	// NAT, and policy rules so the kernel can report the original destination
	// together with the actual terminal input/forward verdict. Conntrack reply
	// direction is deliberately excluded to avoid logging replies to host
	// published connections as guest connection attempts.
	addStartupRule(&nftables.Rule{Table: t, Chain: guard, Exprs: join(matchIIF(guestTapName), matchNFProto(unix.NFPROTO_IPV6), setNFTrace())})
	addStartupRule(&nftables.Rule{Table: t, Chain: guard, Exprs: join(matchIIF(guestTapName), matchNFProto(unix.NFPROTO_IPV4), matchConntrackStateAny(expr.CtStateBitINVALID|expr.CtStateBitUNTRACKED), setNFTrace())})
	addStartupRule(&nftables.Rule{Table: t, Chain: guard, Exprs: join(matchIIF(guestTapName), matchNFProto(unix.NFPROTO_IPV4), matchConntrackDirection(0), setNFTrace())})
	addStartupRule(&nftables.Rule{Table: t, Chain: guard, Exprs: join(matchIIF(guestTapName), matchNFProto(unix.NFPROTO_IPV6), drop())})
	// Replies to host-created published forwards leave through the guest TAP
	// toward the slirp-side address. Admit only established conntrack tuples
	// whose original destination was the host-forward address; the general
	// direct-uplink drop below still blocks guest-created traffic.
	for _, proto := range []byte{6, 17} {
		addStartupRule(&nftables.Rule{Table: t, Chain: guard, Exprs: join(matchIIF(guestTapName), matchNFProto(unix.NFPROTO_IPV4), matchIPv4(12, netip.MustParseAddr("10.0.2.15")), matchL4(proto), matchConntrackState(expr.CtStateBitESTABLISHED), matchConntrackOriginalDestination("10.0.3.100"), accept())})
	}
	// Each forwarded data packet checks owner liveness and the timed singleton
	// lease, including established return packets.
	for _, proto := range []byte{6, 17} {
		addStartupRule(gateRule(t, fwd, join(matchIIF(maintenanceTapName), matchOIF(uplinkTapName), networkLive(), matchNFProto(unix.NFPROTO_IPV4), matchIPv4(12, netip.MustParseAddr(MaintenanceGuestAddress)), lookupIPv4(12, "maintenance_network"), matchL4(proto)), "maintenance_gate_accept_to_uplink"))
		addStartupRule(gateRule(t, fwd, join(matchIIF(uplinkTapName), matchOIF(maintenanceTapName), networkLive(), matchNFProto(unix.NFPROTO_IPV4), matchIPv4(16, netip.MustParseAddr(MaintenanceGuestAddress)), lookupIPv4(16, "maintenance_network"), matchL4(proto), matchConntrackState(expr.CtStateBitESTABLISHED), matchConntrackOriginalSourceLookup("maintenance_network")), "maintenance_gate_accept_from_uplink"))
	}
	addStartupRule(gateDrop(t, fwd, join(matchIIF(maintenanceTapName)), "maintenance_gate_drop_to_uplink"))
	addStartupRule(gateDrop(t, fwd, join(matchOIF(maintenanceTapName)), "maintenance_gate_drop_from_uplink"))
	if err := flushStartupRules(); err != nil {
		return fmt.Errorf("install maintenance TAP routing gates: %w", err)
	}
	addStartupRule(&nftables.Rule{Table: t, Chain: guard, Exprs: join(matchIIF(guestTapName), matchNFProto(unix.NFPROTO_IPV4), matchIPv4Masked(16, "10.0.3.0", "255.255.255.0"), drop())})
	addStartupRule(&nftables.Rule{Table: t, Chain: guard, Exprs: join(matchIIF(guestTapName), matchNFProto(unix.NFPROTO_IPV4), matchIPv4(16, netip.MustParseAddr(UplinkHost)), drop())})
	// Guest packets with any source other than the assigned address are dropped
	// before routing, including packets that spoof a privileged-looking source port.
	addStartupRule(&nftables.Rule{Table: t, Chain: guard, Exprs: join(matchIIF(guestTapName), matchNFProto(unix.NFPROTO_IPV4), matchIPv4Not(12, netip.MustParseAddr("10.0.2.15")), drop())})
	addStartupRule(&nftables.Rule{Table: t, Chain: guard, Exprs: join(matchIIF(maintenanceTapName), matchNFProto(unix.NFPROTO_IPV4), matchIPv4(12, netip.MustParseAddr(MaintenanceGuestAddress)), matchIPv4Masked(16, "10.0.3.0", "255.255.255.0"), drop())})
	if err := flushStartupRules(); err != nil {
		return fmt.Errorf("install maintenance interface anti-spoof and NAT rules: %w", err)
	}
	for _, reserved := range []struct{ addr, mask string }{{"127.0.0.0", "255.0.0.0"}, {"0.0.0.0", "255.0.0.0"}, {"169.254.0.0", "255.255.0.0"}, {"224.0.0.0", "240.0.0.0"}} {
		addStartupRule(&nftables.Rule{Table: t, Chain: guard, Exprs: join(matchIIF(guestTapName), matchNFProto(unix.NFPROTO_IPV4), matchIPv4Masked(16, reserved.addr, reserved.mask), drop())})
	}
	// A published host forward arrives at the slirp-side address and is translated
	// to the guest. Original-tuple checks below distinguish this host-created
	// flow from a guest flow that merely chooses source port 22.
	for _, proto := range []struct {
		number byte
		set    string
	}{{6, "tcp_forward_ports"}, {17, "udp_forward_ports"}} {
		addStartupRule(&nftables.Rule{Table: t, Chain: pre, Exprs: join(matchIIF(maintenanceTapName), networkLive(), matchNFProto(unix.NFPROTO_IPV4), matchIPv4(12, netip.MustParseAddr(MaintenanceGuestAddress)), lookupIPv4(12, "maintenance_network"), matchL4(proto.number), matchIPv4(16, netip.MustParseAddr(GuestGateway)), natTo(expr.NATTypeDestNAT, UplinkHost))})
		addStartupRule(&nftables.Rule{Table: t, Chain: pre, Exprs: join(matchIIF(uplinkTapName), matchL4(proto.number), matchIPv4(16, netip.MustParseAddr("10.0.3.100")), lookupPort(2, proto.set), natTo(expr.NATTypeDestNAT, "10.0.2.15"))})
	}
	// Explicit host alias: only TCP/UDP and only if the original destination
	// itself is present in the manual IP set. No rule accepts translated slirp
	// traffic without checking this live set on every packet.
	fullAlias := []expr.Any{&expr.Immediate{Register: 1, Data: []byte{0, 0, 0, 0}}, &expr.Lookup{SourceRegister: 1, SetName: "full_network"}}
	addStartupRule(&nftables.Rule{Table: t, Chain: pre, Exprs: join(matchIIF(guestTapName), networkLive(), matchIPv4(16, netip.MustParseAddr(GuestGateway)), fullAlias, natTo(expr.NATTypeDestNAT, UplinkHost))})
	for _, proto := range []byte{6, 17} {
		addStartupRule(&nftables.Rule{Table: t, Chain: pre, Exprs: join(matchIIF(guestTapName), networkLive(), matchL4(proto), matchIPv4(16, netip.MustParseAddr(GuestGateway)), lookupIPv4(16, "ip_grants"), natTo(expr.NATTypeDestNAT, UplinkHost))})
	}
	// Invalid conntrack state and spoofed guest sources are always rejected.
	addStartupRule(&nftables.Rule{Table: t, Chain: fwd, Exprs: join(matchConntrackState(expr.CtStateBitINVALID), drop())})
	if err := flushStartupRules(); err != nil {
		return err
	}
	// Only DNS-admitted conntrack entries may continue after answer expiry.
	// The mark's permission survives rotation while an authorizing name remains
	// allowed. Never accept generic established traffic: full-network sessions
	// and host forwards have separate lifetimes and admission rules.
	for _, proto := range []byte{6, 17} {
		for _, iface := range []string{guestTapName, uplinkTapName} {
			addStartupRule(&nftables.Rule{Table: t, Chain: fwd, Exprs: join(matchIIF(iface), networkLive(), matchNFProto(unix.NFPROTO_IPV4), matchConntrackOriginalSource("10.0.2.15"), matchL4(proto), matchConntrackState(expr.CtStateBitESTABLISHED), matchConntrackOriginalPortNot(53), matchConntrackOriginalPortNot(853), lookupDNSFlowMark(), accept())})
		}
		// Attach host-owned authorization only at admission, never from guest
		// packet marks. Put this ahead of manual grants to retain shared references.
		addStartupRule(&nftables.Rule{Table: t, Chain: fwd, Exprs: join(matchIIF(guestTapName), networkLive(), matchNFProto(unix.NFPROTO_IPV4), matchIPv4(12, netip.MustParseAddr("10.0.2.15")), matchL4(proto), matchConntrackState(expr.CtStateBitNEW), matchConntrackOriginalPortNot(53), matchConntrackOriginalPortNot(853), admitDNSFlow(), accept())})
	}
	if err := flushStartupRules(); err != nil {
		return fmt.Errorf("install DNS connection authorization (host kernel requires CONFIG_NF_CONNTRACK_MARK): %w", err)
	}
	// Manual exact IP grants intentionally cover every transport port.
	for _, proto := range []byte{6, 17} {
		addStartupRule(&nftables.Rule{Table: t, Chain: fwd, Exprs: join(matchIIF(guestTapName), networkLive(), matchNFProto(unix.NFPROTO_IPV4), matchIPv4(12, netip.MustParseAddr("10.0.2.15")), matchL4(proto), matchConntrackOriginalLookup("ip_grants"), accept())})
		addStartupRule(&nftables.Rule{Table: t, Chain: fwd, Exprs: join(matchIIF(uplinkTapName), networkLive(), matchNFProto(unix.NFPROTO_IPV4), matchL4(proto), matchConntrackOriginalLookup("ip_grants"), accept())})
	}
	// A host-owned full-network lease temporarily permits IPv4 TCP and UDP
	// from the assigned guest. Its singleton nft set element expires in the
	// kernel unless the supervisor renews it. Direct namespace/uplink aliases,
	// spoofed sources, loopback, link-local and multicast were rejected above.
	for _, direction := range []struct {
		iface  string
		offset uint32
	}{{guestTapName, 12}, {uplinkTapName, 16}} {
		for _, proto := range []byte{6, 17} {
			full := []expr.Any{&expr.Immediate{Register: 1, Data: []byte{0, 0, 0, 0}}, &expr.Lookup{SourceRegister: 1, SetName: "full_network"}}
			addStartupRule(&nftables.Rule{Table: t, Chain: fwd, Exprs: join(matchIIF(direction.iface), networkLive(), matchNFProto(unix.NFPROTO_IPV4), matchIPv4(direction.offset, netip.MustParseAddr("10.0.2.15")), matchL4(proto), full, accept())})
		}
	}
	// New host-forwarded flows require a currently configured port. Once a
	// connection is established, its original host-facing tuple remains valid
	// until that connection closes, even if the listener is removed. Guest
	// packets cannot create this tuple: guest ingress to 10.0.3/24 is dropped
	// above and conntrack loose pickup is disabled.
	for _, proto := range []struct {
		number byte
		set    string
	}{{6, "tcp_forward_ports"}, {17, "udp_forward_ports"}} {
		addStartupRule(&nftables.Rule{Table: t, Chain: fwd, Exprs: join(matchIIF(uplinkTapName), matchNFProto(unix.NFPROTO_IPV4), matchIPv4(16, netip.MustParseAddr("10.0.2.15")), matchL4(proto.number), matchConntrackState(expr.CtStateBitESTABLISHED), matchConntrackOriginalDestination("10.0.3.100"), accept())})
		addStartupRule(&nftables.Rule{Table: t, Chain: fwd, Exprs: join(matchIIF(uplinkTapName), matchNFProto(unix.NFPROTO_IPV4), matchIPv4(16, netip.MustParseAddr("10.0.2.15")), matchL4(proto.number), matchConntrackState(expr.CtStateBitNEW), matchConntrackOriginalDestination("10.0.3.100"), lookupConntrackOriginalPort(proto.set), accept())})
		addStartupRule(&nftables.Rule{Table: t, Chain: fwd, Exprs: join(matchIIF(guestTapName), matchNFProto(unix.NFPROTO_IPV4), matchIPv4(12, netip.MustParseAddr("10.0.2.15")), matchL4(proto.number), matchConntrackState(expr.CtStateBitESTABLISHED), matchConntrackOriginalDestination("10.0.3.100"), accept())})
	}
	// SNAT guest-originated egress to the slirp-side TAP address.
	addStartupRule(&nftables.Rule{Table: t, Chain: post, Exprs: join(matchIPv4(12, netip.MustParseAddr("10.0.2.15")), natTo(expr.NATTypeSourceNAT, "10.0.3.100"))})
	addStartupRule(&nftables.Rule{Table: t, Chain: post, Exprs: join(matchIPv4Masked(12, "10.0.4.0", "255.255.255.0"), natTo(expr.NATTypeSourceNAT, "10.0.3.100"))})
	if err := flushStartupRules(); err != nil {
		return err
	}
	return disableLooseTCPConntrack()
}

// disableLooseTCPConntrack runs after the rules above: on distribution kernels
// nf_conntrack is a module, and its sysctls exist only once the kernel has
// loaded it for the ct rules. The TAP is not handed over before this returns.
func disableLooseTCPConntrack() error {
	const path = "/proc/sys/net/netfilter/nf_conntrack_tcp_loose"
	if err := os.WriteFile(path, []byte("0"), 0644); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.New("disable loose TCP conntrack pickup: the kernel's nf_conntrack module is not loaded and was not loaded automatically; load it with 'sudo modprobe nf_conntrack' and keep it loaded with 'echo nf_conntrack | sudo tee /etc/modules-load.d/zaigr.conf'")
		}
		return fmt.Errorf("disable loose TCP conntrack pickup: %w", err)
	}
	loose, err := os.ReadFile(path)
	if err != nil || strings.TrimSpace(string(loose)) != "0" {
		return fmt.Errorf("loose TCP conntrack pickup is enabled")
	}
	return nil
}

func matchIIF(name string) []expr.Any {
	return []expr.Any{&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifName(name)}}
}
func matchOIF(name string) []expr.Any {
	return []expr.Any{&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifName(name)}}
}
func matchL4(proto byte) []expr.Any {
	return []expr.Any{&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}}}
}
func matchNFProto(proto uint8) []expr.Any {
	return []expr.Any{&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}}}
}
func matchIPv4Masked(offset uint32, address, mask string) []expr.Any {
	return []expr.Any{&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: 4}, &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: net.ParseIP(mask).To4(), Xor: []byte{0, 0, 0, 0}}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: net.ParseIP(address).To4()}}
}
func matchIPv4(offset uint32, addr netip.Addr) []expr.Any {
	return []expr.Any{&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: 4}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: addr.AsSlice()}}
}
func matchIPv4Not(offset uint32, addr netip.Addr) []expr.Any {
	return []expr.Any{&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: 4}, &expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: addr.AsSlice()}}
}
func lookupIPv4Not(offset uint32, set string) []expr.Any {
	return []expr.Any{&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: 4}, &expr.Lookup{SourceRegister: 1, SetName: set, Invert: true}}
}
func gateRule(table *nftables.Table, chain *nftables.Chain, exprs []expr.Any, comment string) *nftables.Rule {
	exprs = append(exprs, gateCounterExpr(comment), &expr.Verdict{Kind: expr.VerdictAccept})
	return &nftables.Rule{Table: table, Chain: chain, Exprs: exprs, UserData: userdata.AppendString(nil, userdata.TypeComment, comment)}
}
func gateDrop(table *nftables.Table, chain *nftables.Chain, exprs []expr.Any, comment string) *nftables.Rule {
	exprs = append(exprs, gateCounterExpr(comment), &expr.Verdict{Kind: expr.VerdictDrop})
	return &nftables.Rule{Table: table, Chain: chain, Exprs: exprs, UserData: userdata.AppendString(nil, userdata.TypeComment, comment)}
}
func gateCounterExpr(comment string) expr.Any {
	switch comment {
	case "maintenance_gate_accept_to_uplink", "maintenance_gate_accept_from_uplink", "maintenance_gate_drop_to_uplink", "maintenance_gate_drop_from_uplink":
		return &expr.Objref{Type: int(nftables.ObjTypeCounter), Name: comment}
	default:
		return &expr.Counter{}
	}
}
func matchPort(offset uint32, port uint16) []expr.Any {
	return []expr.Any{&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: offset, Len: 2}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(port >> 8), byte(port)}}}
}
func lookupIPv4(offset uint32, set string) []expr.Any {
	return []expr.Any{&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: 4}, &expr.Lookup{SourceRegister: 1, SetName: set}}
}
func lookupPort(offset uint32, set string) []expr.Any {
	return []expr.Any{&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: offset, Len: 2}, &expr.Lookup{SourceRegister: 1, SetName: set}}
}
func lookupConntrackOriginalPort(set string) []expr.Any {
	return []expr.Any{&expr.Ct{Register: 1, Key: expr.CtKeyPROTODST, Direction: 0}, &expr.Lookup{SourceRegister: 1, SetName: set}}
}
func matchConntrackState(state uint32) []expr.Any {
	var raw [4]byte
	binary.NativeEndian.PutUint32(raw[:], state)
	return []expr.Any{&expr.Ct{Register: 1, Key: expr.CtKeySTATE}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: raw[:]}}
}
func matchConntrackStateAny(mask uint32) []expr.Any {
	var rawMask [4]byte
	binary.NativeEndian.PutUint32(rawMask[:], mask)
	zero := []byte{0, 0, 0, 0}
	return []expr.Any{&expr.Ct{Register: 1, Key: expr.CtKeySTATE}, &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: rawMask[:], Xor: zero}, &expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: zero}}
}
func matchConntrackDirection(direction byte) []expr.Any {
	return []expr.Any{&expr.Ct{Register: 1, Key: expr.CtKeyDIRECTION}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{direction}}}
}
func setNFTrace() []expr.Any {
	return []expr.Any{&expr.Immediate{Register: 1, Data: []byte{1, 0, 0, 0}}, &expr.Meta{Key: expr.MetaKeyNFTRACE, SourceRegister: true, Register: 1}}
}
func matchConntrackOriginalDestination(address string) []expr.Any {
	return []expr.Any{&expr.Ct{Register: 1, Key: expr.CtKeyDST, Direction: 0}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: net.ParseIP(address).To4()}}
}
func matchConntrackOriginalPort(port uint16) []expr.Any {
	return []expr.Any{&expr.Ct{Register: 1, Key: expr.CtKeyPROTODST, Direction: 0}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(port >> 8), byte(port)}}}
}
func matchConntrackOriginalPortNot(port uint16) []expr.Any {
	return []expr.Any{&expr.Ct{Register: 1, Key: expr.CtKeyPROTODST, Direction: 0}, &expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{byte(port >> 8), byte(port)}}}
}
func matchConntrackOriginalLookup(set string) []expr.Any {
	return []expr.Any{&expr.Ct{Register: 1, Key: expr.CtKeyDST, Direction: 0}, &expr.Lookup{SourceRegister: 1, SetName: set}}
}
func matchConntrackOriginalSourceLookup(set string) []expr.Any {
	return []expr.Any{&expr.Ct{Register: 1, Key: expr.CtKeySRC, Direction: 0}, &expr.Lookup{SourceRegister: 1, SetName: set}}
}
func natTo(kind expr.NATType, address string) []expr.Any {
	return []expr.Any{&expr.Immediate{Register: 1, Data: netip.MustParseAddr(address).AsSlice()}, &expr.NAT{Type: kind, Family: uint32(unix.NFPROTO_IPV4), RegAddrMin: 1, RegAddrMax: 1}}
}
func accept() []expr.Any { return []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}} }
func drop() []expr.Any   { return []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}} }
func join(parts ...[]expr.Any) []expr.Any {
	var out []expr.Any
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func replaceGrantSet(addrs []netip.Addr) error {
	return replaceGrantSetUntil(addrs, time.Time{})
}

func replaceGrantSetUntil(addrs []netip.Addr, requestNotAfter time.Time) error {
	return replaceAddressSetUntil("ip_grants", addrs, requestNotAfter)
}

func replaceAddressSetUntil(name string, addrs []netip.Addr, requestNotAfter time.Time) error {
	c, err := nftables.New()
	if err != nil {
		return err
	}
	t := &nftables.Table{Name: nftTableName, Family: nftables.TableFamilyINet}
	s, err := c.GetSetByName(t, name)
	if err != nil {
		return err
	}
	if !requestNotAfter.IsZero() && !requestNotAfter.After(time.Now()) {
		return errors.New("host network helper request has expired")
	}
	c.FlushSet(s)
	elems := make([]nftables.SetElement, 0, len(addrs))
	for _, a := range addrs {
		elems = append(elems, nftables.SetElement{Key: a.AsSlice()})
	}
	if err := c.SetAddElements(s, elems); err != nil {
		return err
	}
	if !requestNotAfter.IsZero() && !requestNotAfter.After(time.Now()) {
		return errors.New("host network helper request has expired")
	}
	return c.Flush()
}

func helperRequestDeadline(req helperRequest) time.Time {
	if req.RequestNotAfter == 0 {
		return time.Time{}
	}
	return time.Unix(0, req.RequestNotAfter)
}

func networkLive() []expr.Any {
	return []expr.Any{&expr.Immediate{Register: 1, Data: []byte{0, 0, 0, 0}}, &expr.Lookup{SourceRegister: 1, SetName: "network_live"}}
}

func networkLiveNot() []expr.Any {
	return []expr.Any{&expr.Immediate{Register: 1, Data: []byte{0, 0, 0, 0}}, &expr.Lookup{SourceRegister: 1, SetName: "network_live", Invert: true}}
}

func setNetworkLiveLease(previous *time.Time, deadline time.Time, requestNotAfter time.Time) error {
	now := time.Now()
	if !deadline.After(now) {
		return errors.New("network liveness deadline has expired")
	}
	if deadline.After(now.Add(maximumKernelLease)) {
		return errors.New("network liveness deadline exceeds the kernel lease bound")
	}
	if previous == nil || !previous.After(now) {
		// The gate has been absent or expired. Keep it closed until every old
		// guest-originated tuple is gone, so a resumed supervisor cannot revive
		// flows from a pre-expiry manual, DNS, or full-network grant.
		if err := setTimedLeaseSet("network_live", time.Time{}); err != nil {
			return err
		}
		if err := deleteTrackedGuestFlows(); err != nil {
			return err
		}
	}
	if !requestNotAfter.IsZero() && !requestNotAfter.After(time.Now()) {
		return errors.New("host network helper request has expired")
	}
	if err := setTimedLeaseSetUntil("network_live", deadline, requestNotAfter); err != nil {
		return err
	}
	*previous = deadline
	return nil
}

func setFullNetworkLease(previous *time.Time, deadline time.Time, manual map[netip.Addr]bool, dns *dnsFlowState, requestNotAfter time.Time) error {
	now := time.Now()
	if deadline.IsZero() {
		if err := setTimedLeaseSet("full_network", time.Time{}); err != nil {
			return err
		}
		if previous != nil && !previous.IsZero() {
			if err := purgeUnauthorizedGuestFlows(manual, dns); err != nil {
				return err
			}
		}
		*previous = time.Time{}
		return nil
	}
	if !deadline.After(now) {
		return errors.New("full-network lease deadline has expired")
	}
	if deadline.After(now.Add(maximumKernelLease)) {
		return errors.New("full-network lease deadline exceeds the kernel lease bound")
	}
	if previous == nil || !previous.After(now) {
		if err := purgeUnauthorizedGuestFlows(manual, dns); err != nil {
			return err
		}
	}
	if !requestNotAfter.IsZero() && !requestNotAfter.After(time.Now()) {
		return errors.New("host network helper request has expired")
	}
	if err := setTimedLeaseSetUntil("full_network", deadline, requestNotAfter); err != nil {
		return err
	}
	*previous = deadline
	return nil
}

func reconcileExpiredFullLease(previous *time.Time, manual map[netip.Addr]bool, dns *dnsFlowState) error {
	if previous == nil || previous.IsZero() || previous.After(time.Now()) {
		return nil
	}
	if err := setTimedLeaseSet("full_network", time.Time{}); err != nil {
		return err
	}
	if err := purgeUnauthorizedGuestFlows(manual, dns); err != nil {
		return err
	}
	*previous = time.Time{}
	return nil
}

type unauthorizedGuestFlowFilter struct {
	targets map[netip.Addr]bool
	manual  map[netip.Addr]bool
	dns     *dnsFlowState
}

func (f unauthorizedGuestFlowFilter) MatchConntrackFlow(flow *netlink.ConntrackFlow) bool {
	if flow == nil || flow.FamilyType != unix.AF_INET || flow.Forward.SrcIP.String() != "10.0.2.15" {
		return false
	}
	if flow.Forward.Protocol != unix.IPPROTO_TCP && flow.Forward.Protocol != unix.IPPROTO_UDP {
		return false
	}
	destination, ok := netip.AddrFromSlice(flow.Forward.DstIP)
	if !ok {
		return false
	}
	destination = destination.Unmap()
	if f.targets != nil && !f.targets[destination] {
		return false
	}
	if f.manual[destination] {
		return false
	}
	if f.dns.allows(flow) {
		return false
	}
	return true
}

func purgeUnauthorizedGuestFlows(manual map[netip.Addr]bool, dns *dnsFlowState) error {
	if err := dns.inheritLiveFlows(nil); err != nil {
		return err
	}
	return purgeGuestFlows(unauthorizedGuestFlowFilter{manual: manual, dns: dns})
}

func purgeGuestFlows(filter unauthorizedGuestFlowFilter) error {
	if filter.targets != nil && len(filter.targets) == 0 {
		return nil
	}
	return deleteConntrackFlows(filter)
}

// deleteConntrackFlows verifies deletion because netlink v1.3.0 discards
// individual DELETE errors. An empty table or a filter with no matches succeeds.
func deleteConntrackFlows(filter netlink.CustomConntrackFilter) error {
	h, err := netlink.NewHandle(unix.NETLINK_NETFILTER)
	if err != nil {
		return fmt.Errorf("open bounded conntrack netlink handle: %w", err)
	}
	defer h.Close()
	if err := h.SetSocketTimeout(4 * time.Second); err != nil {
		return fmt.Errorf("bound conntrack netlink timeout: %w", err)
	}
	if err := injectConntrackDeleteFailure(h, filter); err != nil {
		return err
	}
	if _, err := h.ConntrackDeleteFilters(netlink.ConntrackTable, netlink.FAMILY_V4, filter); err != nil {
		return fmt.Errorf("delete matching conntrack flows: %w", err)
	}
	flows, err := h.ConntrackTableList(netlink.ConntrackTable, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("verify conntrack cleanup: %w", err)
	}
	for _, flow := range flows {
		if filter.MatchConntrackFlow(flow) {
			return errors.New("matching conntrack flow remained after cleanup")
		}
	}
	return nil
}

func setTimedLeaseSet(name string, deadline time.Time) error {
	return setTimedLeaseSetUntil(name, deadline, time.Time{})
}

func setTimedLeaseSetUntil(name string, deadline, requestNotAfter time.Time) error {
	c, err := nftables.New()
	if err != nil {
		return err
	}
	t := &nftables.Table{Name: nftTableName, Family: nftables.TableFamilyINet}
	s, err := c.GetSetByName(t, name)
	if err != nil {
		return err
	}
	if !requestNotAfter.IsZero() && !requestNotAfter.After(time.Now()) {
		return errors.New("host network helper request has expired")
	}
	c.FlushSet(s)
	if !deadline.IsZero() {
		now := time.Now()
		ttl := deadline.Sub(now)
		if ttl <= 0 {
			return fmt.Errorf("%s lease deadline has expired", name)
		}
		if ttl > maximumKernelLease {
			return fmt.Errorf("%s lease deadline exceeds the kernel lease bound", name)
		}
		if err := c.SetAddElements(s, []nftables.SetElement{{Key: []byte{0, 0, 0, 0}, Timeout: ttl}}); err != nil {
			return err
		}
	}
	if !requestNotAfter.IsZero() && !requestNotAfter.After(time.Now()) {
		return errors.New("host network helper request has expired")
	}
	return c.Flush()
}

func deleteTrackedGuestFlows() error {
	filter := &netlink.ConntrackFilter{}
	if err := filter.AddIP(netlink.ConntrackOrigSrcIP, net.ParseIP("10.0.2.15")); err != nil {
		return fmt.Errorf("filter guest-originated conntrack entries: %w", err)
	}
	if err := deleteConntrackFlows(filter); err != nil {
		return fmt.Errorf("delete guest-originated conntrack entries: %w", err)
	}
	return nil
}

func setForwardPort(protocol string, port uint16, add bool) error {
	c, err := nftables.New()
	if err != nil {
		return err
	}
	name := "tcp_forward_ports"
	if protocol == "udp" {
		name = "udp_forward_ports"
	}
	t := &nftables.Table{Name: nftTableName, Family: nftables.TableFamilyINet}
	s, err := c.GetSetByName(t, name)
	if err != nil {
		return err
	}
	e := nftables.SetElement{Key: []byte{byte(port >> 8), byte(port)}}
	if add {
		if err := c.SetAddElements(s, []nftables.SetElement{e}); err != nil {
			return err
		}
	} else {
		if err := c.SetDeleteElements(s, []nftables.SetElement{e}); err != nil {
			return err
		}
	}
	return c.Flush()
}

func matchConntrackOriginalPortIn(set string) []expr.Any { return lookupConntrackOriginalPort(set) }

func ifName(s string) []byte { b := make([]byte, 16); copy(b, strings.TrimSpace(s)); return b }

func sendFDs(conn net.Conn, files []*os.File, payload any) error {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return errors.New("helper control connection is not Unix")
	}
	b, ok := payload.(string)
	if !ok || b != descriptorReadyMarker {
		return errors.New("invalid descriptor handoff marker")
	}
	fdInts := make([]int, 0, len(files))
	for _, file := range files {
		if file == nil {
			return errors.New("missing descriptor in helper handoff")
		}
		fdInts = append(fdInts, int(file.Fd()))
	}
	n, _, err := uc.WriteMsgUnix([]byte(b), syscall.UnixRights(fdInts...), nil)
	if err != nil {
		return err
	}
	if n != len(b) {
		return fmt.Errorf("short descriptor handoff marker: wrote %d of %d bytes", n, len(b))
	}
	return nil
}
