// Package hostnet owns the host-side network boundary for one VM.
//
// A Runtime is tied to one launch ID and one private user/network namespace.
// Callers must not use guest state as input to policy decisions.
package hostnet

import (
	"context"
	"net/netip"
	"os"
	"time"
)

const (
	GuestAddress            = "10.0.2.15/24"
	GuestGateway            = "10.0.2.2"
	GuestDNS                = "10.0.2.3"
	UplinkCIDR              = "10.0.3.0/24"
	UplinkHost              = "10.0.3.2"
	MaintenanceHostAddress  = "10.0.4.1"
	MaintenanceGuestAddress = "10.0.4.2"
)

// Options describes the trusted, host-owned inputs needed to create one
// fail-closed VM network. RuntimeDir must be private (0700) and outside every
// guest export. Executable is normally os.Executable().
type Options struct {
	LaunchID          string
	RuntimeDir        string
	Executable        string
	SlirpPath         string
	InitialIPGrants   []netip.Addr
	InitialGeneration uint64
}

// PolicySnapshot is the complete policy for one VM. Replacing a snapshot is
// atomic; individual grant updates should be serialized by the caller.
type PolicySnapshot struct {
	LaunchID   string
	Generation uint64
	IPGrants   []netip.Addr
}

// Forward describes a host-published TCP port. HostPort must bind on loopback
// only. GuestPort is the port exposed by the VM.
type Forward struct {
	HostPort  uint16 `json:"host_port"`
	GuestPort uint16 `json:"guest_port"`
	Protocol  string `json:"protocol"`
}

type ProcessIdentity struct {
	PID       int
	StartTime string
}
type ChildExit struct {
	Name string
	Err  error
}

// FirewallEvent reports an observed terminal packet verdict in the private
// host firewall. It describes only the firewall decision, not remote
// connectivity or application success.
type FirewallEvent struct {
	Sequence        uint64     `json:"sequence,omitempty"`
	Time            time.Time  `json:"time"`
	Protocol        string     `json:"protocol,omitempty"`
	Source          netip.Addr `json:"source,omitempty"`
	SourcePort      uint16     `json:"source_port,omitempty"`
	Destination     netip.Addr `json:"destination,omitempty"`
	DestinationPort uint16     `json:"destination_port,omitempty"`
	PortsAvailable  bool       `json:"ports_available,omitempty"`
	Decision        string     `json:"decision,omitempty"`
	Gap             bool       `json:"gap,omitempty"`
	Dropped         uint64     `json:"dropped,omitempty"`
	Reason          string     `json:"reason,omitempty"`
}

// MaintenanceSession identifies one shared maintenance-network lease. These
// fixed addresses are host-owned and are never selected by guest input.
type MaintenanceSession struct {
	HostAddress  netip.Addr
	GuestAddress netip.Addr
}

// Runtime is the host controller handle for a running network. TakeTapFile
// and TakeMaintenanceTapFile each transfer one host-side descriptor to the
// caller exactly once. The caller must close them after QEMU inherits them.
// Runtime.Stop never closes a descriptor after that transfer.
type Runtime interface {
	LaunchID() string
	Generation() uint64
	Processes() map[string]ProcessIdentity
	ChildExits() <-chan ChildExit
	NextFirewallEvent(context.Context, uint64) (FirewallEvent, error)
	TakeTapFile() *os.File
	TakeMaintenanceTapFile() *os.File
	TakeDNSSockets() (*os.File, *os.File)
	TakeSupervisorExitWriter() *os.File
	ApplyPolicy(context.Context, PolicySnapshot) error
	SetNetworkLease(context.Context, string, time.Time) error
	SetFullNetworkLease(context.Context, string, time.Time) error
	StartMaintenanceSession(context.Context, string, string, time.Time) (MaintenanceSession, error)
	RenewMaintenanceSession(context.Context, string, string, time.Time) error
	StopMaintenanceSession(context.Context, string, string) error
	ReplaceDNSLeases(context.Context, string, uint64, map[string]map[netip.Addr]time.Time, map[string]time.Time) error
	AddForward(context.Context, string, uint64, Forward) error
	RemoveForward(context.Context, string, uint64, Forward) error
	ListForwards(context.Context) ([]Forward, error)
	Stop(context.Context) error
}
