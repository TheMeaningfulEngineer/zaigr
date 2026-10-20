//go:build linux

package hostnet

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/vishvananda/netlink"
)

// injectConntrackDeleteFailure is an explicit test-only diagnostic switch,
// compiled in like the misc test-helpers commands. It is inert unless the host
// test sets ZAIGR_TEST_CONNTRACK_DELETE_FAILURE to an absolute marker path.
// Creating that file with an IPv4 address arms failure for an actual matching
// original-destination entry; deleting it disarms failure. The sibling .log
// records the attempted deletion before returning the injected error.
func injectConntrackDeleteFailure(h *netlink.Handle, filter netlink.CustomConntrackFilter) error {
	path := os.Getenv("ZAIGR_TEST_CONNTRACK_DELETE_FAILURE")
	if path == "" {
		return nil
	}
	if !filepath.IsAbs(path) {
		return errors.New("test conntrack deletion failure marker must be an absolute path")
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read test conntrack deletion failure marker: %w", err)
	}
	address, err := netip.ParseAddr(strings.TrimSpace(string(data)))
	if err != nil || !address.Is4() {
		return errors.New("test conntrack deletion failure marker must contain an IPv4 address")
	}
	flows, err := h.ConntrackTableList(netlink.ConntrackTable, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("inspect test conntrack deletion target: %w", err)
	}
	for _, flow := range flows {
		if flow == nil || flow.Forward.DstIP.String() != address.String() || !filter.MatchConntrackFlow(flow) {
			continue
		}
		failure := fmt.Sprintf("injected-host-conntrack-failure: deletion for %s attempted and failed", address)
		log, err := os.OpenFile(path+".log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("open test conntrack deletion failure log: %w", err)
		}
		_, writeErr := fmt.Fprintln(log, failure)
		if err := errors.Join(writeErr, log.Close()); err != nil {
			return fmt.Errorf("write test conntrack deletion failure log: %w", err)
		}
		return errors.New(failure)
	}
	return nil
}
