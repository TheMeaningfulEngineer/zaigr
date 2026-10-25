package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"zaigr/cmd/zaigr/hostdns"
	"zaigr/cmd/zaigr/hostnet"
)

var hostNetworkBuiltinDomains = []string{"deb.debian.org", "debian.map.fastlydns.net", "security.debian.org"}

// loadHostNetworkInitialPolicy reads only the persisted host-owned policy for
// this project plus the global exact-domain policy. Old setup firewall records
// that are not exact DNS names are skipped, never widened or interpreted as
// patterns by the new backend.
func loadHostNetworkInitialPolicy(store projectStore) (names []string, generation uint64, ipGrants []netip.Addr, err error) {
	projectFirewall, err := readProtectedHostPolicyFile(store.Path, "firewall")
	if err != nil {
		return nil, 0, nil, err
	}
	projectNames := parseHostPolicyNames(projectFirewall)
	manualFirewall, err := readProtectedHostPolicyFile(store.Path, projectFirewallDomainsFile)
	if err != nil {
		return nil, 0, nil, err
	}
	manualNames, err := parseProtectedFirewallDomains(manualFirewall, "manual project firewall")
	if err != nil {
		return nil, 0, nil, err
	}
	globalFirewall, err := readProtectedHostPolicyFile(zaigDir(), "firewall")
	if err != nil {
		return nil, 0, nil, err
	}
	globalNames := parseHostPolicyNames(globalFirewall)
	nameSet := make(map[string]struct{}, len(projectNames)+len(globalNames))
	for _, builtin := range hostNetworkBuiltinDomains {
		nameSet[builtin] = struct{}{}
	}
	for _, raw := range append(append(projectNames, manualNames...), globalNames...) {
		name, validateErr := validateHostDNSPolicyName(raw)
		if validateErr != nil {
			// Lines from older setups, such as download URLs, are skipped:
			// leaving one out only ever allows less. The setup loader explains
			// them to the user.
			logDebug("skipping unusable persisted firewall entry", "entry", raw, "error", validateErr)
			continue
		}
		nameSet[name] = struct{}{}
	}
	names = make([]string, 0, len(nameSet))
	for name := range nameSet {
		names = append(names, name)
	}
	sort.Strings(names)

	ipData, err := readProtectedHostPolicyFile(store.Path, "firewall-ips")
	if err != nil {
		return nil, 0, nil, err
	}
	addresses, err := parseProtectedHostFirewallIPs(ipData)
	if err != nil {
		return nil, 0, nil, err
	}
	ipGrants = make([]netip.Addr, 0, len(addresses))
	for _, raw := range addresses {
		address, parseErr := netip.ParseAddr(raw)
		if parseErr != nil || !address.Is4() {
			return nil, 0, nil, fmt.Errorf("invalid persisted exact IPv4 firewall grant %q", raw)
		}
		ipGrants = append(ipGrants, address)
	}
	// Runtime generations are per-launch and begin at one. Live changes advance
	// the generation through the supervisor before replacing any host policy.
	return names, 1, ipGrants, nil
}

// validateProtectedSSHPrivateKey verifies the two host-owned private keys
// used by VM administration. It opens only the exact trusted files under
// ~/.zaigr; it never searches workspace or agent-state content for keys.
func validateProtectedSSHPrivateKey(path string) error {
	root := zaigDir()
	canonicalRoot, err := canonicalPathWithMissingSuffix(root)
	if err != nil {
		return err
	}
	if filepath.Clean(root) != canonicalRoot || filepath.Clean(filepath.Dir(path)) != filepath.Clean(root) {
		return fmt.Errorf("SSH private key must be directly inside the canonical protected ~/.zaigr directory")
	}
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open protected SSH key directory: %w", err)
	}
	defer unix.Close(rootFD)
	rootStat := &unix.Stat_t{}
	if err := unix.Fstat(rootFD, rootStat); err != nil {
		return err
	}
	resolvedRoot, err := filepath.EvalSymlinks(fmt.Sprintf("/proc/self/fd/%d", rootFD))
	if err != nil || filepath.Clean(resolvedRoot) != canonicalRoot {
		return fmt.Errorf("protected SSH key directory %q changed identity while opening", root)
	}
	if rootStat.Mode&unix.S_IFMT != unix.S_IFDIR || rootStat.Uid != uint32(os.Getuid()) || rootStat.Mode&0022 != 0 {
		return sshKeyDirectoryOwnershipError(root, rootStat.Uid, rootStat.Mode)
	}
	name := filepath.Base(path)
	if name != filepath.Base(rootSSHKeyPath()) && name != filepath.Base(userSSHKeyPath()) {
		return errors.New("unrecognized protected SSH private key path")
	}
	fd, err := unix.Openat(rootFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("open protected SSH private key %q without following symlinks: %w", path, err)
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 || stat.Mode&0077 != 0 || stat.Mode&0400 == 0 {
		return fmt.Errorf("SSH private key %q is unsafe: found uid=%d mode=%04o links=%d; expected uid=%d, a single-link regular file, owner read access, and no group/other permissions", path, stat.Uid, stat.Mode&07777, stat.Nlink, os.Getuid())
	}
	return nil
}

func readProtectedHostPolicyFile(root, name string) ([]byte, error) {
	if !filepath.IsAbs(root) || (name != "firewall" && name != "firewall-domains" && name != "firewall-ips") {
		return nil, errors.New("host network policy: invalid protected policy path")
	}
	canonical, err := canonicalPathWithMissingSuffix(root)
	if err != nil {
		return nil, err
	}
	// Do not let an alias under a mutable workspace or guest-visible tree
	// select a different policy root. The stored paths themselves must be the
	// canonical protected paths before we open any leaf.
	if filepath.Clean(root) != canonical {
		return nil, errors.New("host network policy directory must not be a symlink or path alias")
	}
	rootFD, err := unix.Open(canonical, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open protected policy directory: %w", err)
	}
	rootFile := os.NewFile(uintptr(rootFD), "zaigr-host-policy-root")
	defer rootFile.Close()
	rootInfo, err := rootFile.Stat()
	if err != nil {
		return nil, err
	}
	rootStat, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok || !rootInfo.IsDir() || int(rootStat.Uid) != os.Getuid() || rootInfo.Mode().Perm()&0022 != 0 {
		return nil, errors.New("host network policy directory must be a current-user-owned non-writable-by-others directory")
	}
	resolvedRoot, err := filepath.EvalSymlinks(fmt.Sprintf("/proc/self/fd/%d", rootFD))
	if err != nil || filepath.Clean(resolvedRoot) != canonical {
		return nil, errors.New("host network policy directory changed while opening")
	}
	fd, err := unix.Openat(rootFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open protected %s policy: %w", name, err)
	}
	file := os.NewFile(uintptr(fd), "zaigr-host-policy-leaf")
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || int(stat.Uid) != os.Getuid() || stat.Nlink != 1 || info.Mode().Perm()&0022 != 0 || info.Size() > 1<<20 {
		return nil, fmt.Errorf("protected %s policy must be a current-user-owned regular single-link file no larger than 1 MiB with no group/other write access", name)
	}
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 1<<20 {
		return nil, fmt.Errorf("protected %s policy exceeds 1 MiB", name)
	}
	return data, nil
}

func parseHostPolicyNames(data []byte) []string {
	seen := make(map[string]struct{})
	var names []string
	for _, line := range strings.Split(string(data), "\n") {
		entry := strings.TrimSpace(line)
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		if _, ok := seen[entry]; ok {
			continue
		}
		seen[entry] = struct{}{}
		names = append(names, entry)
	}
	sort.Strings(names)
	return names
}

func parseProtectedHostFirewallIPs(data []byte) ([]string, error) {
	if len(data) == 0 {
		return nil, nil
	}
	if data[len(data)-1] != '\n' {
		return nil, errors.New("invalid project firewall IP metadata: nonempty file must end with a newline")
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	addresses := make([]string, 0, len(lines))
	previous := ""
	for _, line := range lines {
		address, err := validateProjectFirewallIPv4(line)
		if err != nil {
			return nil, fmt.Errorf("invalid project firewall IP metadata: %w", err)
		}
		if previous != "" && address <= previous {
			return nil, errors.New("invalid project firewall IP metadata: entries must be sorted and unique")
		}
		addresses = append(addresses, address)
		previous = address
	}
	return addresses, nil
}

func validateHostDNSPolicyName(raw string) (string, error) {
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if name == "" || !isValidFirewallDomain(name) {
		return "", errors.New("only exact multi-label DNS names are supported")
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return "", errors.New("IP literals belong in the exact IPv4 address policy")
	}
	return name, nil
}

// startHostDNSBroker creates the trusted per-launch host broker. The caller
// must pass the same policy snapshot used to create hostnet.Runtime and must
// start/authorize the capless frontend before allowing the VM to boot.
func startHostDNSBroker(ctx context.Context, runtime hostnet.Runtime, runtimeDir string, names []string, generation uint64, excludedPrefixes []netip.Prefix) (*hostdns.Server, error) {
	if runtime == nil {
		return nil, errors.New("host DNS: host network runtime is required")
	}
	if generation != runtime.Generation() {
		return nil, fmt.Errorf("host DNS: policy generation %d differs from network runtime generation %d", generation, runtime.Generation())
	}
	if !filepath.IsAbs(runtimeDir) {
		return nil, errors.New("host DNS: runtime directory must be an absolute host path")
	}
	info, err := os.Stat(runtimeDir)
	if err != nil {
		return nil, fmt.Errorf("host DNS: inspect private runtime directory: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("host DNS: runtime directory must be a private 0700 directory")
	}
	resolverServers, err := loadTrustedHostResolvers()
	if err != nil {
		return nil, err
	}
	return hostdns.StartBroker(ctx, hostdns.Config{
		LaunchID: runtime.LaunchID(), IPCPath: filepath.Join(runtimeDir, "dns.sock"),
		Names: names, Generation: generation, ResolverConfigPath: "/etc/resolv.conf", ResolverServers: resolverServers,
		FrontendUID: os.Getuid(), ExcludedPrefixes: excludedPrefixes,
	}, runtime)
}

func hostDNSExcludedPrefixes() ([]netip.Prefix, error) {
	// This inventory is a startup snapshot. The current development backend
	// requires stopping/restarting VMs after host interface or route changes;
	// production must monitor/revalidate and withdraw leases on inventory change.
	set := make(map[netip.Prefix]struct{})
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("host DNS: enumerate host interfaces: %w", err)
	}
	for _, iface := range interfaces {
		addresses, addrErr := iface.Addrs()
		if addrErr != nil {
			return nil, fmt.Errorf("host DNS: enumerate addresses on %s: %w", iface.Name, addrErr)
		}
		for _, address := range addresses {
			ipNet, ok := address.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipNet.IP)
			if !ok || !ip.Unmap().Is4() {
				continue
			}
			bits, totalBits := ipNet.Mask.Size()
			set[netip.PrefixFrom(ip.Unmap(), 32)] = struct{}{}
			if len(set) > 65536 {
				return nil, errors.New("host DNS: host exclusion inventory exceeds 65536 prefixes")
			}
			if totalBits != 32 || bits == 0 {
				continue
			}
			set[netip.PrefixFrom(ip.Unmap(), bits).Masked()] = struct{}{}
			if len(set) > 65536 {
				return nil, errors.New("host DNS: host exclusion inventory exceeds 65536 prefixes")
			}
		}
	}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, fmt.Errorf("host DNS: enumerate host IPv4 routes across routing tables: %w", err)
	}
	for _, route := range routes {
		if route.Dst == nil {
			continue // The default 0/0 route is not an exclusion.
		}
		ip, ok := netip.AddrFromSlice(route.Dst.IP)
		if !ok || !ip.Unmap().Is4() {
			continue
		}
		bits, totalBits := route.Dst.Mask.Size()
		if totalBits != 32 {
			return nil, fmt.Errorf("host DNS: malformed IPv4 route prefix %v", route.Dst)
		}
		if bits == 0 {
			continue
		}
		set[netip.PrefixFrom(ip.Unmap(), bits).Masked()] = struct{}{}
		if len(set) > 65536 {
			return nil, errors.New("host DNS: host exclusion inventory exceeds 65536 prefixes")
		}
	}
	prefixes := make([]netip.Prefix, 0, len(set))
	for prefix := range set {
		prefixes = append(prefixes, prefix)
	}
	sort.Slice(prefixes, func(i, j int) bool {
		if prefixes[i].Addr() == prefixes[j].Addr() {
			return prefixes[i].Bits() < prefixes[j].Bits()
		}
		return prefixes[i].Addr().Less(prefixes[j].Addr())
	})
	return prefixes, nil
}

// loadTrustedHostResolvers reads an optional host-only resolver override. The
// file is deliberately outside project/workspace exports and cannot be
// symlinked to a guest-controlled path. Absence preserves the host resolver.
func loadTrustedHostResolvers() ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return nil, errors.New("host DNS: cannot determine host home directory")
	}
	home = filepath.Clean(home)
	if resolved, resolveErr := filepath.EvalSymlinks(home); resolveErr != nil || filepath.Clean(resolved) != home {
		return nil, errors.New("host DNS: host home directory must not be a symlink")
	}
	root := zaigDir()
	rootFD, err := syscall.Open(root, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, syscall.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("host DNS: inspect trusted resolver directory: %w", err)
	}
	rootFile := os.NewFile(uintptr(rootFD), "zaigr-hostdns-config-dir")
	defer rootFile.Close()
	rootInfo, err := rootFile.Stat()
	if err != nil {
		return nil, fmt.Errorf("host DNS: stat trusted resolver directory: %w", err)
	}
	if !rootInfo.IsDir() || rootInfo.Mode().Perm()&0022 != 0 {
		return nil, errors.New("host DNS: ~/.zaigr must be a non-writable-by-others real directory")
	}
	if stat, ok := rootInfo.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Getuid() {
		return nil, errors.New("host DNS: ~/.zaigr must be owned by the current host user")
	}
	fileFD, err := syscall.Openat(rootFD, "host-network-resolvers", syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, syscall.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("host DNS: inspect trusted resolver file: %w", err)
	}
	resolverFile := os.NewFile(uintptr(fileFD), "zaigr-hostdns-resolvers")
	defer resolverFile.Close()
	fileInfo, err := resolverFile.Stat()
	if err != nil {
		return nil, fmt.Errorf("host DNS: stat trusted resolver file: %w", err)
	}
	if !fileInfo.Mode().IsRegular() || fileInfo.Size() > 4096 || fileInfo.Mode().Perm() != 0600 {
		return nil, errors.New("host DNS: resolver override must be a regular mode-0600 file of at most 4096 bytes")
	}
	if stat, ok := fileInfo.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Getuid() || stat.Nlink != 1 {
		return nil, errors.New("host DNS: resolver override must be owned by the current host user")
	}
	data, err := io.ReadAll(io.LimitReader(resolverFile, 4097))
	if err != nil {
		return nil, fmt.Errorf("host DNS: read trusted resolver file: %w", err)
	}
	if len(data) > 4096 {
		return nil, errors.New("host DNS: resolver override exceeds 4096 bytes")
	}
	servers := make([]string, 0, 4)
	for lineNo, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		host, port, splitErr := net.SplitHostPort(line)
		ip, parseErr := netip.ParseAddr(host)
		portNumber, portErr := strconv.ParseUint(port, 10, 16)
		if splitErr != nil || parseErr != nil || ip.Zone() != "" || portErr != nil || portNumber == 0 {
			return nil, fmt.Errorf("host DNS: invalid resolver on line %d; expected an IP:port literal", lineNo+1)
		}
		servers = append(servers, net.JoinHostPort(ip.String(), strconv.FormatUint(portNumber, 10)))
		if len(servers) > 16 {
			return nil, errors.New("host DNS: resolver override supports at most 16 servers")
		}
	}
	if len(servers) == 0 {
		return nil, errors.New("host DNS: present resolver override must contain at least one IP:port line")
	}
	return servers, nil
}

// buildCaplessHostDNSFrontend configures an unstarted frontend child. Its
// caller starts the command, closes readyWrite, then waits on readyRead and
// calls awaitCaplessHostDNSFrontend before allowing QEMU to boot.
func buildCaplessHostDNSFrontend(ctx context.Context, executable, ipcPath string, udp, tcp *os.File) (*exec.Cmd, *os.File, *os.File, error) {
	if udp == nil || tcp == nil {
		return nil, nil, nil, errors.New("host DNS: bound UDP/TCP sockets are required")
	}
	if executable == "" {
		return nil, nil, nil, errors.New("host DNS: executable path is required")
	}
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("host DNS: create frontend readiness pipe: %w", err)
	}
	cmd := exec.CommandContext(ctx, executable,
		"__host-dns-frontend", "--bootstrap-privileges", "--ipc", ipcPath,
		"--udp-fd", "3", "--tcp-fd", "4", "--ready-fd", "5")
	cmd.ExtraFiles = []*os.File{udp, tcp, readyWrite}
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = hostnet.RootlessUserNamespaceSysProcAttr(false)
	cmd.SysProcAttr.Setpgid = true
	cmd.SysProcAttr.Pdeathsig = syscall.SIGKILL
	return cmd, readyRead, readyWrite, nil
}

func awaitCaplessHostDNSFrontend(ctx context.Context, server *hostdns.Server, cmd *exec.Cmd, ready *os.File) error {
	if server == nil {
		return errors.New("host DNS: broker and started frontend process are required")
	}
	if cmd == nil || cmd.Process == nil || ready == nil {
		return errors.New("host DNS: started frontend command and readiness pipe are required")
	}
	defer ready.Close()
	readyResult := make(chan error, 1)
	go func() {
		var one [1]byte
		_, err := ready.Read(one[:])
		if err == nil && one[0] != 1 {
			err = errors.New("host DNS: frontend sent an invalid readiness marker")
		}
		readyResult <- err
	}()
	select {
	case err := <-readyResult:
		if err != nil {
			return fmt.Errorf("host DNS: frontend failed before readiness: %w", err)
		}
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(5 * time.Second):
		return errors.New("host DNS: frontend readiness deadline exceeded")
	}
	identity, err := inspectFrontendIdentity(cmd.Process.Pid)
	if err != nil {
		return err
	}
	return server.AuthorizeFrontend(cmd.Process.Pid, identity.startTime)
}

type frontendIdentity struct {
	startTime uint64
}

func inspectFrontendIdentity(pid int) (frontendIdentity, error) {
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return frontendIdentity{}, fmt.Errorf("host DNS: inspect frontend capability state: %w", err)
	}
	values := make(map[string]string)
	for _, line := range strings.Split(string(status), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok {
			values[key] = strings.TrimSpace(value)
		}
	}
	for _, field := range []string{"CapEff", "CapPrm", "CapInh", "CapBnd", "CapAmb"} {
		value, ok := values[field]
		if !ok {
			return frontendIdentity{}, fmt.Errorf("host DNS: frontend status lacks %s", field)
		}
		caps, parseErr := strconv.ParseUint(value, 16, 64)
		if parseErr != nil || caps != 0 {
			return frontendIdentity{}, fmt.Errorf("host DNS: frontend has nonempty %s capability set", field)
		}
	}
	if values["NoNewPrivs"] != "1" {
		return frontendIdentity{}, errors.New("host DNS: frontend no_new_privs is not set")
	}
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return frontendIdentity{}, fmt.Errorf("host DNS: inspect frontend identity: %w", err)
	}
	closeParen := strings.LastIndexByte(string(stat), ')')
	if closeParen < 0 || closeParen+1 >= len(stat) {
		return frontendIdentity{}, errors.New("host DNS: malformed frontend process stat")
	}
	fields := strings.Fields(string(stat[closeParen+1:]))
	if len(fields) <= 19 {
		return frontendIdentity{}, errors.New("host DNS: frontend process stat lacks starttime")
	}
	startTime, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || startTime == 0 {
		return frontendIdentity{}, errors.New("host DNS: malformed frontend process starttime")
	}
	return frontendIdentity{startTime: startTime}, nil
}
