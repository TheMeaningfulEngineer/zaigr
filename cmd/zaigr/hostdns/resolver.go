package hostdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type upstreamResolver struct {
	servers []string
	timeout time.Duration
}

func newUpstreamResolver(cfg Config) (*upstreamResolver, error) {
	servers := append([]string(nil), cfg.ResolverServers...)
	if len(servers) == 0 {
		if _, err := os.Stat(cfg.ResolverConfigPath); err != nil {
			return nil, fmt.Errorf("host DNS: inspect trusted resolver configuration %q: %w", cfg.ResolverConfigPath, err)
		}
		resolverConfig, err := dns.ClientConfigFromFile(cfg.ResolverConfigPath)
		if err != nil {
			return nil, fmt.Errorf("host DNS: parse trusted resolver configuration: %w", err)
		}
		port := resolverConfig.Port
		if port == "" {
			port = "53"
		}
		for _, server := range resolverConfig.Servers {
			servers = append(servers, net.JoinHostPort(server, port))
		}
	}
	if len(servers) == 0 || len(servers) > 16 {
		return nil, fmt.Errorf("host DNS: trusted resolver count %d is outside 1..16", len(servers))
	}
	for i, address := range servers {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			// Accept an IP literal without a port and use the DNS default port.
			ip, parseErr := netip.ParseAddr(address)
			if parseErr != nil {
				return nil, fmt.Errorf("host DNS: invalid trusted resolver %q: %w", address, err)
			}
			servers[i] = net.JoinHostPort(ip.String(), "53")
			continue
		}
		ip, err := netip.ParseAddr(host)
		if err != nil || port == "" {
			return nil, fmt.Errorf("host DNS: trusted resolver must be an IP socket address, got %q", address)
		}
		if _, err := net.LookupPort("udp", port); err != nil {
			return nil, fmt.Errorf("host DNS: invalid resolver port in %q: %w", address, err)
		}
		servers[i] = net.JoinHostPort(ip.String(), port)
	}
	return &upstreamResolver{servers: servers, timeout: cfg.ResolveTimeout}, nil
}

func (r *upstreamResolver) exchange(ctx context.Context, request *dns.Msg) (*dns.Msg, error) {
	var lastErr error
	for _, server := range r.servers {
		client := &dns.Client{Net: "udp", Timeout: r.timeout, UDPSize: defaultUDPPayload}
		response, _, err := client.ExchangeContext(ctx, request.Copy(), server)
		if err != nil {
			lastErr = err
			continue
		}
		if response.Truncated {
			tcpClient := &dns.Client{Net: "tcp", Timeout: r.timeout}
			response, _, err = tcpClient.ExchangeContext(ctx, request.Copy(), server)
			if err != nil {
				lastErr = err
				continue
			}
		}
		if err := validateUpstreamEnvelope(request, response); err != nil {
			lastErr = err
			continue
		}
		return response, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no trusted resolver answered")
	}
	return nil, lastErr
}

func validateUpstreamEnvelope(request, response *dns.Msg) error {
	if response == nil {
		return errors.New("trusted resolver returned an empty DNS message")
	}
	if !response.Response || response.Opcode != dns.OpcodeQuery || response.Id != request.Id {
		return errors.New("trusted resolver response has a mismatched transaction header")
	}
	if response.Truncated {
		return errors.New("trusted resolver response is truncated after TCP fallback")
	}
	if len(request.Question) != 1 || len(response.Question) != 1 {
		return errors.New("trusted resolver response has an unexpected question count")
	}
	requestQuestion, responseQuestion := request.Question[0], response.Question[0]
	if !strings.EqualFold(requestQuestion.Name, responseQuestion.Name) ||
		requestQuestion.Qtype != responseQuestion.Qtype || requestQuestion.Qclass != responseQuestion.Qclass {
		return errors.New("trusted resolver response question does not match the request")
	}
	if len(response.Answer) > 4096 || len(response.Ns) > 4096 || len(response.Extra) > 4096 {
		return errors.New("trusted resolver response exceeds the record-count bound")
	}
	return nil
}

func validateAddress(addr netip.Addr, exclusions []netip.Prefix) error {
	if !addr.IsValid() {
		return errors.New("invalid address")
	}
	addr = addr.Unmap()
	if !addr.Is4() || !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
		return fmt.Errorf("address %s is not a permitted public IPv4 destination", addr)
	}
	for _, prefix := range specialIPv4Prefixes {
		if prefix.Contains(addr) {
			return fmt.Errorf("address %s is reserved for special use", addr)
		}
	}
	for _, prefix := range exclusions {
		if prefix.Contains(addr) {
			return fmt.Errorf("address %s overlaps a host or internal-network exclusion %s", addr, prefix)
		}
	}
	return nil
}

func validateFullNetworkAddress(addr netip.Addr) error {
	addr = addr.Unmap()
	if !addr.IsValid() || !addr.Is4() || !addr.IsGlobalUnicast() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
		return fmt.Errorf("address %s is not a usable IPv4 destination", addr)
	}
	for _, prefix := range specialIPv4Prefixes {
		if prefix.Contains(addr) && !addr.IsPrivate() {
			return fmt.Errorf("address %s is reserved for special use", addr)
		}
	}
	return nil
}

// The special-use blocks track IANA's IPv4 Special-Purpose Address Registry.
// Host-owned public addresses and site-local routes are passed separately in
// Config.ExcludedPrefixes because IANA global-unicast status cannot identify
// those local exclusions.
var specialIPv4Prefixes = mustPrefixes(
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.31.196.0/24",
	"192.52.193.0/24",
	"192.88.99.0/24",
	"192.168.0.0/16",
	"192.175.48.0/24",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/4",
	"240.0.0.0/4",
)

func mustPrefixes(values ...string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefixes = append(prefixes, netip.MustParsePrefix(value))
	}
	return prefixes
}
