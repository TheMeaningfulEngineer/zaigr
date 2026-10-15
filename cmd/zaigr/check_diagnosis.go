package main

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type checkHost struct {
	name, id, like, kernel string
	policy                 map[string]string
	container              bool
}

func detectCheckHost() checkHost {
	h := checkHost{name: "Linux (distribution unknown)", kernel: "unknown", policy: make(map[string]string)}
	for _, path := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			value = strings.Trim(strings.TrimSpace(value), "\"'")
			switch key {
			case "PRETTY_NAME":
				h.name = value
			case "ID":
				h.id = value
			case "ID_LIKE":
				h.like = value
			}
		}
		break
	}
	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		h.kernel = strings.TrimSpace(string(data))
	}
	for label, path := range map[string]string{
		"AppArmor enabled":                    "/sys/module/apparmor/parameters/enabled",
		"AppArmor user-namespace restriction": "/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
		"Unprivileged user namespaces":        "/proc/sys/kernel/unprivileged_userns_clone",
		"User namespace limit":                "/proc/sys/user/max_user_namespaces",
		"SELinux enforcing":                   "/sys/fs/selinux/enforce",
		"Security profile":                    "/proc/self/attr/current",
		"Caller UID map":                      "/proc/self/uid_map",
		"Caller GID map":                      "/proc/self/gid_map",
	} {
		if data, err := os.ReadFile(path); err == nil {
			h.policy[label] = strings.TrimSpace(string(data))
		}
	}
	if data, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			key, value, _ := strings.Cut(line, ":")
			if key == "CapEff" || key == "NoNewPrivs" || key == "Seccomp" || key == "NSpid" {
				h.policy[key] = strings.TrimSpace(value)
			}
		}
	}
	for _, path := range []string{"/run/.containerenv", "/.dockerenv"} {
		if _, err := os.Stat(path); err == nil {
			h.container = true
		}
	}
	return h
}

func (h checkHost) family(id string) bool {
	return h.id == id || strings.Contains(" "+h.like+" ", " "+id+" ")
}

func (h checkHost) context() string {
	lines := []string{fmt.Sprintf("Caller: uid=%d gid=%d", os.Geteuid(), os.Getegid()), "OS: " + h.name, "Kernel: " + h.kernel}
	for _, label := range []string{
		"AppArmor enabled", "AppArmor user-namespace restriction", "Unprivileged user namespaces",
		"User namespace limit", "SELinux enforcing", "Security profile", "Caller UID map", "Caller GID map",
		"CapEff", "NoNewPrivs", "Seccomp",
	} {
		if value, ok := h.policy[label]; ok {
			lines = append(lines, label+": "+value)
		}
	}
	if h.container {
		lines = append(lines, "Container environment: detected")
	}
	return strings.Join(lines, "\n")
}

type probeKernelAudit struct {
	apparmor, selinux bool
	detail            string
}

func readProbeKernelAudit(host checkHost, probe virtiofsProbe) probeKernelAudit {
	result := probeKernelAudit{}
	// Bound the time window and attribute denials to observed probe PIDs. A
	// denial for a different virtiofsd instance must not confirm this diagnosis.
	pidPattern := regexp.MustCompile(`(?:^|\s)pid=(\d+)(?:\s|$)`)
	// Kernel records use the initial PID namespace. A container's /proc can
	// expose different numbers, so a numerical match alone is not evidence.
	canMatchPIDs := !host.container && len(strings.Fields(host.policy["NSpid"])) <= 1
	var attempts []string
	for _, command := range []struct {
		name string
		args []string
	}{
		{"journalctl", []string{"-k", "-b", "--no-pager", "-o", "cat", "-n", "200", "--since", fmt.Sprintf("@%d", probe.started.Unix()), "--until", fmt.Sprintf("@%d", probe.ended.Unix()+1)}},
		{"dmesg", []string{"--since", probe.started.Format("2006-01-02 15:04:05"), "--until", probe.ended.Add(time.Second).Format("2006-01-02 15:04:05")}},
	} {
		out, err := checkCommandOutput(command.name, command.args...)
		var denials []string
		for _, line := range strings.Split(string(out), "\n") {
			pidMatch := pidPattern.FindStringSubmatch(line)
			if len(pidMatch) != 2 {
				continue
			}
			pid, _ := strconv.Atoi(pidMatch[1])
			if !canMatchPIDs || !probe.pids[pid] {
				continue
			}
			apparmor := strings.Contains(line, `apparmor="DENIED"`)
			selinux := strings.Contains(line, "avc:") && strings.Contains(line, "denied") && !strings.Contains(line, "permissive=1")
			if !apparmor && !selinux {
				continue
			}
			result.apparmor = result.apparmor || apparmor
			result.selinux = result.selinux || selinux
			if len(denials) < 5 {
				denials = append(denials, line)
			}
		}
		if len(denials) > 0 {
			result.detail = "Kernel audit: matching probe denials from " + command.name + "\n" + strings.Join(denials, "\n")
			return result
		}
		status := "no matching probe denial visible"
		if !canMatchPIDs {
			status = "cannot safely attribute host kernel PIDs from this container or nested PID namespace"
		}
		lower := strings.ToLower(string(out))
		if err != nil && (strings.Contains(lower, "permission") || strings.Contains(lower, "not permitted")) {
			status = "kernel log access restricted for this account"
		} else if err != nil {
			status = fmt.Sprintf("unavailable (%v)", err)
		}
		attempts = append(attempts, command.name+": "+status)
	}
	result.detail = "Kernel audit: " + strings.Join(attempts, "; ") + ". Fast-exiting sandbox children may escape PID observation. Diagnosis uses the probe failure and readable host settings."
	return result
}

func diagnoseVirtiofs(host checkHost, daemonLog string, audit probeKernelAudit) string {
	permission := strings.Contains(daemonLog, "Permission denied") || strings.Contains(daemonLog, "Operation not permitted")
	operation := "starting the filesystem sandbox"
	if strings.Contains(daemonLog, "CleanMount") {
		operation = "configuring mounts inside the filesystem sandbox"
	} else if strings.Contains(daemonLog, "Unshare") {
		operation = "creating the filesystem sandbox namespaces"
	}
	var diagnosis, remedy string
	switch {
	case audit.apparmor:
		diagnosis = "AppArmor denied an operation in the sandbox probe (confirmed by kernel audit)."
		remedy = "Required host change: an AppArmor policy allowing the daemon below to create user namespaces and perform sandbox operations; the matching denial identifies the blocked permission."
	case audit.selinux:
		diagnosis = "SELinux denied an operation in the sandbox probe (confirmed by kernel audit)."
		remedy = "Required host change: a SELinux policy allowing the daemon below to perform the sandbox operations identified in the matching denial."
	case permission && strings.Contains(daemonLog, "Unshare") && os.Geteuid() != 0 && host.policy["Unprivileged user namespaces"] == "0":
		diagnosis = "the host disables unprivileged user namespaces."
		remedy = "Required host change: permit user namespaces for the account running zaigr."
	case strings.Contains(daemonLog, "Unshare") && strings.Contains(daemonLog, "No space left on device") && os.Geteuid() != 0 && host.policy["User namespace limit"] == "0":
		diagnosis = "the host user namespace limit is zero."
		remedy = "Required host change: a nonzero user.max_user_namespaces limit."
	case permission && strings.Contains(daemonLog, "CleanMount") && host.policy["AppArmor enabled"] == "Y" && host.policy["AppArmor user-namespace restriction"] == "1" && host.policy["Security profile"] == "unconfined" && os.Geteuid() != 0:
		diagnosis = "likely AppArmor user-namespace restriction"
		if host.family("ubuntu") {
			diagnosis = "likely Ubuntu AppArmor user-namespace restriction"
		}
		diagnosis += ". The enabled restriction and sandbox mount denial match this failure; audit confirmation is unavailable."
		remedy = "Ubuntu's user-namespace policy can allow namespace creation but deny capabilities needed for sandbox mounts, even for an unconfined process."
		if !host.family("ubuntu") {
			remedy = "AppArmor can deny capabilities needed inside a user namespace even when namespace creation succeeds."
		}
		remedy += "\nRequired host change: a dedicated AppArmor profile granting userns permission to the daemon path below."
	case permission && host.container:
		diagnosis = "likely container restrictions on sandbox namespaces or mounts."
		remedy = "Required host change: the container runtime must permit user, mount, PID and network namespaces and mounts inside the sandbox. Its seccomp, capabilities and security policy can restrict these operations."
	default:
		diagnosis = "sandbox startup failed; available evidence does not identify the blocking host policy."
		remedy = "Zaigr requires user, mount, PID and network namespaces, and permission to configure mounts inside the sandbox."
	}
	return "Diagnosis: " + diagnosis + "\nFailed operation: " + operation + ".\n" + remedy
}
