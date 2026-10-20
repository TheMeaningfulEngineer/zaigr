//go:build linux

package hostnet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const maximumDNSFlowReferences = 8192

// An address gets a launch-local conntrack mark. Its owners are exact names
// which authorized that address, retained independently of their DNS TTLs.
// Shared IP permissions remain shared; this is not hostname authentication.
// Once the last owner is revoked, its mark is never reused in this launch.
type dnsFlowPermission struct {
	mark   uint32
	owners map[string]time.Time
}

type dnsFlowState struct {
	permissions map[netip.Addr]*dnsFlowPermission
	leases      map[netip.Addr]time.Time
	nextMark    uint32
}

func newDNSFlowState() *dnsFlowState {
	return &dnsFlowState{permissions: make(map[netip.Addr]*dnsFlowPermission), leases: make(map[netip.Addr]time.Time)}
}

func permissionDeadline(owners map[string]time.Time, now time.Time) (time.Time, bool) {
	var deadline time.Time
	for _, expiry := range owners {
		if expiry.IsZero() {
			return time.Time{}, true
		}
		if expiry.After(now) && expiry.After(deadline) {
			deadline = expiry
		}
	}
	return deadline, !deadline.IsZero()
}

func (s *dnsFlowState) allows(flow *netlink.ConntrackFlow) bool {
	if flow == nil || flow.Mark == 0 || flow.Forward.DstPort == 53 || flow.Forward.DstPort == 853 {
		return false
	}
	address, ok := netip.AddrFromSlice(flow.Forward.DstIP)
	if !ok {
		return false
	}
	permission := s.permissions[address.Unmap()]
	if permission == nil || permission.mark != flow.Mark {
		return false
	}
	_, allowed := permissionDeadline(permission.owners, time.Now())
	return allowed
}

// A manual or full-network grant may predate DNS resolution. At its removal,
// transfer existing eligible tuples to the still-live DNS permission before
// cleanup. The broader grant has already been withdrawn, so no new unmarked
// connection can race this handoff. Never transfer using a historical answer.
func (s *dnsFlowState) inheritLiveFlows(targets map[netip.Addr]bool) error {
	if targets != nil && len(targets) == 0 {
		return nil
	}
	h, err := netlink.NewHandle(unix.NETLINK_NETFILTER)
	if err != nil {
		return err
	}
	defer h.Close()
	if err := h.SetSocketTimeout(4 * time.Second); err != nil {
		return err
	}
	flows, err := h.ConntrackTableList(netlink.ConntrackTable, netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	for _, flow := range flows {
		if flow.Forward.SrcIP.String() != "10.0.2.15" || (flow.Forward.Protocol != unix.IPPROTO_TCP && flow.Forward.Protocol != unix.IPPROTO_UDP) || flow.Forward.DstPort == 53 || flow.Forward.DstPort == 853 {
			continue
		}
		address, ok := netip.AddrFromSlice(flow.Forward.DstIP)
		if !ok {
			continue
		}
		address = address.Unmap()
		if targets != nil && !targets[address] {
			continue
		}
		permission := s.permissions[address]
		if permission == nil || !s.leases[address].After(time.Now()) || flow.Mark == permission.mark {
			continue
		}
		if _, allowed := permissionDeadline(permission.owners, time.Now()); !allowed {
			continue
		}
		flow.Mark = permission.mark
		flow.ProtoInfo = nil // Do not overwrite evolving TCP state from a dump.
		if err := h.ConntrackUpdate(netlink.ConntrackTable, netlink.FAMILY_V4, flow); err != nil && !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("transfer existing flow to live DNS permission: %w", err)
		}
	}
	return nil
}

func (s *dnsFlowState) replace(req helperRequest, manual map[netip.Addr]bool) error {
	now := time.Now()
	if len(req.Leases) > maximumDNSFlowReferences || len(req.DNSNames) > 100000 {
		return errors.New("DNS policy exceeds the bounded reference limit")
	}
	names := make(map[string]time.Time, len(req.DNSNames))
	for name, raw := range req.DNSNames {
		if name == "" || len(name) > 254 {
			return errors.New("invalid DNS permission name")
		}
		if raw == 0 {
			names[name] = time.Time{}
		} else if deadline := time.Unix(0, raw); deadline.After(now) {
			names[name] = deadline
		}
	}
	// Validate the complete input before withdrawing any permission.
	for _, lease := range req.Leases {
		address, err := netip.ParseAddr(lease.Address)
		if err != nil || !address.Is4() {
			return errors.New("invalid DNS lease address")
		}
		if _, ok := req.DNSNames[lease.Name]; !ok {
			return errors.New("DNS lease lacks an authorizing name")
		}
	}
	retained := newDNSFlowState()
	retained.nextMark = s.nextMark
	var revoked []netip.Addr
	for address, old := range s.permissions {
		owners := make(map[string]time.Time)
		for name, priorDeadline := range old.owners {
			// An expired transient permission cannot be revived by renewal.
			if !priorDeadline.IsZero() && !priorDeadline.After(now) {
				continue
			}
			if deadline, ok := names[name]; ok {
				owners[name] = deadline
			}
		}
		if len(owners) == 0 {
			revoked = append(revoked, address)
			continue
		}
		retained.permissions[address] = &dnsFlowPermission{mark: old.mark, owners: owners}
	}
	// The intermediate revocation barrier may retain only admission supplied
	// by the new snapshot, not a removed owner's old lease on a shared IP.
	for _, lease := range req.Leases {
		address := netip.MustParseAddr(lease.Address)
		deadline, allowed := names[lease.Name]
		expiry := time.Unix(0, lease.Expires)
		if !deadline.IsZero() && expiry.After(deadline) {
			expiry = deadline
		}
		if retained.permissions[address] != nil && allowed && expiry.After(now) && expiry.After(retained.leases[address]) {
			retained.leases[address] = expiry
		}
	}

	if len(revoked) > 0 {
		// Close admission and continuation before deleting tuples. A subsequent
		// regrant receives a fresh mark and cannot resurrect an old connection.
		if err := retained.install(helperRequestDeadline(req)); err != nil {
			return err
		}
		for _, address := range revoked {
			if !manual[address] {
				if err := deleteTrackedAddress(address); err != nil {
					return err
				}
			}
		}
	}
	retained.leases = make(map[netip.Addr]time.Time)
	for _, lease := range req.Leases {
		deadline, allowed := names[lease.Name]
		expiry := time.Unix(0, lease.Expires)
		if !deadline.IsZero() && expiry.After(deadline) {
			expiry = deadline
		}
		if !allowed || !expiry.After(now) {
			continue
		}
		address := netip.MustParseAddr(lease.Address)
		permission := retained.permissions[address]
		if permission == nil {
			if retained.nextMark == ^uint32(0) {
				return errors.New("DNS conntrack mark space exhausted")
			}
			retained.nextMark++
			permission = &dnsFlowPermission{mark: retained.nextMark, owners: make(map[string]time.Time)}
			retained.permissions[address] = permission
		}
		permission.owners[lease.Name] = deadline
		if expiry.After(retained.leases[address]) {
			retained.leases[address] = expiry
		}
	}
	// Retired addresses with no remaining connections can be forgotten. Do this
	// at the bound, rather than dumping conntrack on every DNS response. Only
	// collect addresses whose previous kernel admission has already expired;
	// otherwise a new flow could race the snapshot below.
	if retained.referenceCount() > maximumDNSFlowReferences {
		if err := retained.collectUnused(s.leases, now); err != nil {
			return err
		}
		if retained.referenceCount() > maximumDNSFlowReferences {
			return errors.New("DNS established-flow reference limit reached")
		}
	}
	if err := retained.install(helperRequestDeadline(req)); err != nil {
		return err
	}
	*s = *retained
	return nil
}

func (s *dnsFlowState) referenceCount() int {
	count := 0
	for _, permission := range s.permissions {
		count += len(permission.owners)
	}
	return count
}

func (s *dnsFlowState) collectUnused(previous map[netip.Addr]time.Time, now time.Time) error {
	h, err := netlink.NewHandle(unix.NETLINK_NETFILTER)
	if err != nil {
		return err
	}
	defer h.Close()
	if err := h.SetSocketTimeout(4 * time.Second); err != nil {
		return err
	}
	flows, err := h.ConntrackTableList(netlink.ConntrackTable, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("collect DNS flow permissions: %w", err)
	}
	used := make(map[uint32]bool)
	for _, flow := range flows {
		used[flow.Mark] = true
	}
	for address, permission := range s.permissions {
		if !previous[address].After(now) && !s.leases[address].After(now) && !used[permission.mark] {
			delete(s.permissions, address)
			delete(s.leases, address)
		}
	}
	return nil
}

func markBytes(mark uint32) []byte {
	data := make([]byte, 4)
	binary.NativeEndian.PutUint32(data, mark)
	return data
}

func (s *dnsFlowState) install(requestNotAfter time.Time) error {
	c, err := nftables.New()
	if err != nil {
		return err
	}
	table := &nftables.Table{Name: nftTableName, Family: nftables.TableFamilyINet}
	leases, err := c.GetSetByName(table, "dns_leases")
	if err != nil {
		return err
	}
	marks, err := c.GetSetByName(table, "dns_flow_marks")
	if err != nil {
		return err
	}
	now := time.Now()
	if !requestNotAfter.IsZero() && !requestNotAfter.After(now) {
		return errors.New("host network helper request has expired")
	}
	admission := make([]nftables.SetElement, 0, len(s.leases))
	continuation := make([]nftables.SetElement, 0, len(s.permissions))
	for address, permission := range s.permissions {
		deadline, allowed := permissionDeadline(permission.owners, now)
		if !allowed {
			continue
		}
		element := nftables.SetElement{Key: markBytes(permission.mark)}
		if !deadline.IsZero() {
			element.Timeout = deadline.Sub(now)
		}
		continuation = append(continuation, element)
		expiry := s.leases[address]
		if !deadline.IsZero() && expiry.After(deadline) {
			expiry = deadline
		}
		if expiry.After(now) {
			admission = append(admission, nftables.SetElement{Key: address.AsSlice(), Val: markBytes(permission.mark), Timeout: expiry.Sub(now)})
		}
	}
	c.FlushSet(leases)
	c.FlushSet(marks)
	if err := c.SetAddElements(leases, admission); err != nil {
		return err
	}
	if err := c.SetAddElements(marks, continuation); err != nil {
		return err
	}
	if !requestNotAfter.IsZero() && !requestNotAfter.After(time.Now()) {
		return errors.New("host network helper request has expired")
	}
	return c.Flush()
}

func matchConntrackOriginalSource(address string) []expr.Any {
	return []expr.Any{&expr.Ct{Register: 1, Key: expr.CtKeySRC, Direction: 0}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: netip.MustParseAddr(address).AsSlice()}}
}

func lookupDNSFlowMark() []expr.Any {
	return []expr.Any{&expr.Ct{Register: 1, Key: expr.CtKeyMARK}, &expr.Lookup{SourceRegister: 1, SetName: "dns_flow_marks"}}
}

func admitDNSFlow() []expr.Any {
	return []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeyDST, Direction: 0},
		&expr.Lookup{SourceRegister: 1, DestRegister: 1, IsDestRegSet: true, SetName: "dns_leases"},
		&expr.Ct{Register: 1, SourceRegister: true, Key: expr.CtKeyMARK},
	}
}
