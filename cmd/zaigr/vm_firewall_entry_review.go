package main

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// Setup firewall files written for older zaigr versions may contain lines the
// host firewall cannot use, such as download URLs. They are explained and
// skipped instead of stopping the VM: skipping a line only ever allows less.

// reviewedFirewallLines remembers each decision so a setup loaded several
// times in one command asks only once.
var reviewedFirewallLines = map[string]string{}

// firewallLineHost returns the host part of a firewall line: without scheme,
// path, query, port or a leading "*.".
func firewallLineHost(line string) string {
	s := strings.ToLower(strings.TrimSpace(line))
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	return strings.TrimPrefix(s, "*.")
}

// suggestFirewallDomain returns the domain an unusable line most likely meant,
// or "" when there is none.
func suggestFirewallDomain(line string) string {
	name, err := validateHostDNSPolicyName(firewallLineHost(line))
	if err != nil {
		return ""
	}
	return name
}

// reviewSetupFirewallContent returns setup firewall content without unusable
// lines. When stdin is a terminal it offers to fix the file itself; the
// returned bool reports whether the file was rewritten.
func reviewSetupFirewallContent(setup, path string, data []byte) ([]byte, bool) {
	lines := strings.Split(string(data), "\n")
	cleaned := make([]string, 0, len(lines))
	fixed := make([]string, 0, len(lines))
	rewrite := false
	for _, line := range lines {
		entry := strings.TrimSpace(line)
		if entry == "" || strings.HasPrefix(entry, "#") {
			cleaned = append(cleaned, line)
			fixed = append(fixed, line)
			continue
		}
		if _, err := validateHostDNSPolicyName(entry); err == nil {
			cleaned = append(cleaned, line)
			fixed = append(fixed, line)
			continue
		}
		replacement, accepted := reviewFirewallLine(setup, path, entry)
		if replacement != "" {
			cleaned = append(cleaned, replacement)
		}
		if accepted {
			rewrite = true
			if replacement != "" {
				fixed = append(fixed, replacement)
			}
		} else {
			fixed = append(fixed, line)
		}
	}
	if !rewrite {
		return []byte(strings.Join(cleaned, "\n")), false
	}
	content := []byte(strings.Join(fixed, "\n"))
	mode := os.FileMode(0644)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	if err := writeFileAtomically(path, content, mode); err != nil {
		fmt.Fprintf(os.Stderr, "   Could not update %s: %v\n", path, err)
		return []byte(strings.Join(cleaned, "\n")), false
	}
	fmt.Fprintf(os.Stderr, "   Updated %s.\n", path)
	return content, true
}

// reviewFirewallLine explains one unusable line and returns the entry to use
// instead ("" to skip it) and whether the user agreed to fix the file.
func reviewFirewallLine(setup, path, entry string) (string, bool) {
	key := path + "\x00" + entry
	if replacement, ok := reviewedFirewallLines[key]; ok {
		return replacement, false
	}
	suggestion := suggestFirewallDomain(entry)
	fmt.Fprintf(os.Stderr, ":: Setup %s has a firewall line zaigr can't use:\n", setup)
	fmt.Fprintf(os.Stderr, "     %s\n", entry)
	fmt.Fprintln(os.Stderr, "   Firewall lines must be plain domain names, like github.com.")
	fmt.Fprintf(os.Stderr, "   File: %s\n", path)
	if addr, err := netip.ParseAddr(firewallLineHost(entry)); err == nil && addr.Is4() {
		fmt.Fprintln(os.Stderr, "   This is an IP address. To allow it, run:")
		fmt.Fprintf(os.Stderr, "     zaigr project firewall allow %s\n", addr)
	}
	if suggestion != "" && strings.HasPrefix(strings.TrimSpace(entry), "*.") {
		fmt.Fprintf(os.Stderr, "   Only %s itself will be allowed, not its subdomains.\n", suggestion)
		fmt.Fprintln(os.Stderr, "   Add each subdomain you need as its own line.")
	}
	question := "Remove it from that file?"
	if suggestion != "" {
		question = fmt.Sprintf("Replace it with %s in that file?", suggestion)
	}
	if !stdinIsTerminal() {
		if suggestion != "" {
			fmt.Fprintf(os.Stderr, "   Suggested line: %s\n", suggestion)
		}
		fmt.Fprintln(os.Stderr, "   Skipped for now. Fix the file to stop this message.")
		reviewedFirewallLines[key] = ""
		return "", false
	}
	fmt.Fprintf(os.Stderr, "%s [Y/n] ", question)
	answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	answer = strings.ToLower(strings.TrimSpace(answer))
	if answer != "" && answer != "y" && answer != "yes" {
		fmt.Fprintln(os.Stderr, "   Skipped. It stays blocked until the file is fixed.")
		reviewedFirewallLines[key] = ""
		return "", false
	}
	reviewedFirewallLines[key] = suggestion
	return suggestion, true
}

func stdinIsTerminal() bool {
	_, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TCGETS)
	return err == nil
}
