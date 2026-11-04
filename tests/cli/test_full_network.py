"""Public CLI acceptance for session-scoped maintenance network leases."""

import json
import re
import shlex
import signal
import socket
import time

import pexpect
import pytest

from ..conftest import err_msg, spawn_interactive
from ..conftest import run as _run
from .host_access_endpoints import wait_text
from .host_network_fixture.processes import signal_recorded_process
from .host_network_fixture.public_site import public_address

USER_PROMPT = r"user@[^:]+:.*[$] "
FULL_NETWORK_WARNING = (
    r"WARNING: --full-network gives this root shell and its child processes broad IPv4 TCP/UDP "
    r"access, including private network destinations\. Other VM processes stay on their ordinary "
    r"network policy\. Access ends when the host session expires or shell exits\."
)
SETUP_LEASE_WARNING = r"WARNING: Setup execution .*broad IPv4 TCP/UDP access.*"
CAPTURE_LEASE_WARNING = r"WARNING: Setup capture .*broad IPv4 TCP/UDP access.*"
ROOT_PROMPT = r"root@[^:]+:.*# "
ROOT_DIRTY_PROMPT = r"Accessing this VM as root automatically marks the project image dirty\."
ROOT_DIRTY_CONFIRM_PROMPT = r"Continue with root shell\? \[y/N\]"


def assert_full_network_sessions(output, expected, full_network=None, maintenance=None):
    """Check public firewall status counts for total, broad, and scoped sessions."""
    assert f"active sessions: {expected}" in output.lower(), output
    if full_network is not None:
        assert f"full-network sessions: {full_network}" in output.lower(), output
    if maintenance is not None:
        assert f"maintenance sessions: {maintenance}" in output.lower(), output


def checked_run(command, **kwargs):
    """Record a visible CLI command and return successful stdout."""
    stdout, stderr, code = _run(command, **kwargs)
    assert code == 0, err_msg(stdout, stderr)
    return stdout


def run_in_shell(shell, command):
    """Send a visible command to the interactive shell and return its output."""
    shell.sendline(command)
    shell.expect(getattr(shell, "zaigr_prompt", USER_PROMPT))
    output = re.sub(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|[@-_])", "", shell.before)
    return output.replace("\r\n", "\n").replace("\r", "\n")


def assert_probe_marker(output, marker):
    """Require an emitted result line rather than matching the echoed command."""
    assert re.search(rf"(?m)^PROBE_RESULT={re.escape(marker)}\r?$", output), output


def open_shell(command, project, request, full_network=False, root=False):
    """Open the explicit public CLI shell command and wait for its prompt."""
    shell = spawn_interactive(
        command,
        cwd=project.cwd,
        env=project.env,
        timeout=45,
    )
    request.addfinalizer(lambda: shell.close(force=True) if shell.isalive() else None)
    root = root or full_network
    if root:
        shell.expect(ROOT_DIRTY_PROMPT)
        shell.expect(ROOT_DIRTY_CONFIRM_PROMPT)
        shell.sendline("y")
    if full_network:
        shell.expect(FULL_NETWORK_WARNING)
    shell.zaigr_prompt = ROOT_PROMPT if root else USER_PROMPT
    shell.expect(shell.zaigr_prompt)
    return shell


def exit_shell(shell):
    """Close a CLI shell through its normal exit path."""
    shell.sendline("exit")
    shell.expect(pexpect.EOF)
    shell.close()


@pytest.fixture(autouse=True)
def small_vm(monkeypatch):
    """Keep independent acceptance VMs economical."""
    monkeypatch.setenv("ZAIGR_VM_RAM", "512")
    monkeypatch.setenv("ZAIGR_VM_CPU", "1")
    monkeypatch.setenv("ZAIGR_DISK_SIZE", "8G")


@pytest.mark.parametrize(
    ("shell_flags", "expected_error"),
    [
        (["--full-network"], "--root"),
        (["--root", "--full-network", "--preset", "docker"], "--preset"),
    ],
)
def test_full_network_requires_an_explicit_compatible_root_shell(project, shell_flags, expected_error):
    """Broad temporary networking is available only through the explicit root shell."""
    stdout, stderr, code = _run(
        [project.zaigr_bin, "shell", *shell_flags],
        cwd=project.cwd,
        env=project.env,
        timeout=30,
    )
    combined = (stdout + stderr).lower()
    assert code != 0, combined
    assert expected_error in combined, combined


@pytest.mark.timeout(360)
def test_full_network_is_private_to_root_maintenance_session_and_revoked(
    project, host_network_endpoints, request
):
    """Only one root maintenance shell and its children gain broad network access."""
    zaigr = project.zaigr_bin
    endpoint = host_network_endpoints
    host_url = f"http://10.0.2.2:{endpoint['tcp_port']}/"
    if endpoint["private_ip"] is None:
        pytest.fail("BLOCKED: host has no active private IPv4 interface outside guest uplink routes")
    authorized_url = (
        f"http://{endpoint['private_ip']}:{endpoint['private_tcp_port']}/"
    )
    checked_run([zaigr, "project", "vm", "start"], cwd=project.cwd, env=project.env,
                input="y\n", timeout=180)
    normal = open_shell(shlex.quote(str(zaigr)) + " shell", project, request)
    normal_uid = run_in_shell(normal, "printf 'UID=%s\\n' \"$(id -u)\"")
    assert re.search(r"(?m)^UID=[1-9][0-9]*\r?$", normal_uid), normal_uid
    denied = run_in_shell(
        normal,
        f"if curl --noproxy '*' -4fsS --connect-timeout 2 --max-time 4 {host_url}; "
        "then printf 'PROBE_RESULT=ALLOWED\\n'; else printf 'PROBE_RESULT=DENIED\\n'; fi",
    )
    assert_probe_marker(denied, "DENIED")
    assert endpoint["token"] not in denied
    udp_probe = project.cwd / "maintenance-udp-probe"
    stdout, stderr, code = _run(
        ["gcc", "-static", "-O2", "-Wall", "-Wextra", "-Werror", "-o", udp_probe,
         "tests/cli/host_network_fixture/udp_probe.c"],
    )
    assert code == 0, err_msg(stdout, stderr)
    udp_denied = run_in_shell(normal, f"./maintenance-udp-probe 10.0.2.2 {endpoint['udp_port']}")
    assert_probe_marker(udp_denied, "DENIED")

    root_without_network = open_shell(
        shlex.quote(str(zaigr)) + " shell --root", project, request, root=True
    )
    root_denied = run_in_shell(
        root_without_network,
        f"if curl --noproxy '*' -4fsS --connect-timeout 2 --max-time 4 {host_url}; "
        "then printf 'PROBE_RESULT=ALLOWED\\n'; else printf 'PROBE_RESULT=DENIED\\n'; fi",
    )
    assert_probe_marker(root_denied, "DENIED")
    assert endpoint["token"] not in root_denied
    exit_shell(root_without_network)

    first_full = open_shell(
        shlex.quote(str(zaigr)) + " shell --root --full-network", project, request,
        full_network=True, root=True,
    )
    assert re.search(r"(?m)^0\r?$", run_in_shell(first_full, "id -u"))
    assert endpoint["token"] in run_in_shell(
        first_full, f"curl --noproxy '*' -4fsS --max-time 4 {host_url}"
    )
    # The controlled endpoint above proves the maintenance tunnel is usable.
    # Probe the former credential-gateway address from that same namespace.
    # The management gateway address is excluded from maintenance networking;
    # the separate host-side listener probe verifies no gateway is listening.
    gateway_probe = run_in_shell(
        first_full,
        "curl --noproxy '*' -4fsS --connect-timeout 2 --max-time 3 "
        "http://10.0.2.3:9443/ 2>&1; printf 'GATEWAY_CURL_STATUS=%s\\n' \"$?\"",
    )
    assert "Connection timed out" in gateway_probe, gateway_probe
    assert "GATEWAY_CURL_STATUS=28" in gateway_probe, gateway_probe
    udp_output = run_in_shell(
        first_full,
        f"cd /home/user/workspace && ./maintenance-udp-probe 10.0.2.2 {endpoint['udp_port']}",
    )
    assert re.search(
        rf"(?m)^PROBE_RESULT={re.escape(endpoint['token'] + ':udp')}\r?$", udp_output
    ), udp_output

    ordinary_during_maintenance = run_in_shell(
        normal,
        f"if curl --noproxy '*' -4fsS --connect-timeout 2 --max-time 4 {host_url}; "
        "then printf 'PROBE_RESULT=ALLOWED\\n'; else printf 'PROBE_RESULT=DENIED\\n'; fi",
    )
    assert_probe_marker(ordinary_during_maintenance, "DENIED")
    assert endpoint["token"] not in ordinary_during_maintenance
    udp_denied_during_maintenance = run_in_shell(
        normal, f"./maintenance-udp-probe 10.0.2.2 {endpoint['udp_port']}"
    )
    assert_probe_marker(udp_denied_during_maintenance, "DENIED")
    vm_exec_denied = checked_run(
        [zaigr, "project", "vm", "exec", "--", "bash", "-c",
         (f"if curl --noproxy '*' -4fsS --connect-timeout 2 --max-time 4 {host_url}; "
          "then echo UNEXPECTED_ACCESS; else echo VM_EXEC_DENIED; fi")],
        cwd=project.cwd, env=project.env, timeout=20,
    )
    assert "VM_EXEC_DENIED" in vm_exec_denied and "UNEXPECTED_ACCESS" not in vm_exec_denied

    checked_run([zaigr, "project", "firewall", "allow", endpoint["private_ip"]],
                cwd=project.cwd, env=project.env, timeout=20)
    authorized_stream = project.cwd / "full-network-authorized-stream.log"
    checked_run(
        [zaigr, "project", "vm", "exec", "--", "bash", "-c",
         (f"nohup curl --noproxy '*' -4fsSN --max-time 120 {authorized_url}stream "
          f"> {authorized_stream.name} 2>&1 < /dev/null &")],
        cwd=project.cwd, env=project.env, timeout=20,
    )
    wait_text(authorized_stream, endpoint["token"])

    # Root maintenance shares the VM filesystem with the ordinary shell.
    run_in_shell(
        first_full,
        "printf '#!/bin/sh\\nprintf maintenance-file-survives\\n\\n' "
        "> /usr/local/bin/maintenance-tool && chmod 755 /usr/local/bin/maintenance-tool",
    )
    run_in_shell(first_full, f"nohup curl --noproxy '*' -4fsSN --max-time 120 {host_url}stream "
                f"> /home/user/workspace/full-network-root-stream.log 2>&1 < /dev/null &")
    root_stream = project.cwd / "full-network-root-stream.log"
    wait_text(root_stream, endpoint["token"])

    assert_full_network_sessions(
        checked_run([zaigr, "project", "firewall", "show"], cwd=project.cwd, env=project.env),
        1, full_network=0, maintenance=1,
    )
    time.sleep(11)
    renewed_status = checked_run(
        [zaigr, "project", "firewall", "show"], cwd=project.cwd, env=project.env
    )
    assert_full_network_sessions(renewed_status, 1, full_network=0, maintenance=1)
    assert "status: running" in checked_run(
        [zaigr, "project", "status"], cwd=project.cwd, env=project.env
    ).lower()
    assert len(root_stream.read_bytes()) > 0
    assert endpoint["token"] in run_in_shell(
        first_full, f"curl --noproxy '*' -4fsS --max-time 4 {host_url}"
    )

    # Closing the maintenance shell releases its network session and cuts off
    # its existing tunnel flow, while a separately granted exact host rule lives on.
    exit_shell(first_full)
    assert_full_network_sessions(
        checked_run([zaigr, "project", "firewall", "show"], cwd=project.cwd, env=project.env),
        0, full_network=0, maintenance=0,
    )
    time.sleep(0.5)
    frozen_stream_length = len(root_stream.read_bytes())
    time.sleep(0.5)
    assert len(root_stream.read_bytes()) == frozen_stream_length

    revoked = run_in_shell(
        normal,
        f"if curl --noproxy '*' -4fsS --connect-timeout 2 --max-time 4 {host_url}; "
        "then printf 'PROBE_RESULT=ALLOWED\\n'; else printf 'PROBE_RESULT=DENIED\\n'; fi",
    )
    assert_probe_marker(revoked, "DENIED")
    assert endpoint["token"] not in revoked
    authorized_before = len(authorized_stream.read_bytes())
    time.sleep(0.5)
    assert len(authorized_stream.read_bytes()) > authorized_before
    checked_run([zaigr, "project", "firewall", "remove", endpoint["private_ip"]],
                cwd=project.cwd, env=project.env, timeout=20)
    time.sleep(0.5)
    authorized_stopped = len(authorized_stream.read_bytes())
    time.sleep(0.5)
    assert len(authorized_stream.read_bytes()) == authorized_stopped
    normal_uid_after = run_in_shell(normal, "printf 'UID=%s\\n' \"$(id -u)\"")
    assert re.search(r"(?m)^UID=[1-9][0-9]*\r?$", normal_uid_after), normal_uid_after
    assert "maintenance-file-survives" in run_in_shell(normal, "/usr/local/bin/maintenance-tool")
    exit_shell(normal)


@pytest.mark.timeout(240)
def test_full_network_sessions_share_one_maintenance_lease(
    project, host_network_endpoints, host_network_dns, dns_probe_binary, request
):
    """An ended shell retains access only while another shared-lease shell remains open."""
    zaigr = project.zaigr_bin
    endpoint = host_network_endpoints
    resolver = host_network_dns["resolver"]
    assert dns_probe_binary.is_file()
    host_url = f"http://10.0.2.2:{endpoint['tcp_port']}/"
    checked_run([zaigr, "project", "vm", "start"], cwd=project.cwd, env=project.env,
                input="y\n", timeout=180)

    first = open_shell(
        shlex.quote(str(zaigr)) + " shell --root --full-network", project, request,
        full_network=True, root=True,
    )
    assert "project-image-dirty: yes (root-shell," in checked_run(
        [zaigr, "project", "status"], cwd=project.cwd, env=project.env
    )
    second = open_shell(
        shlex.quote(str(zaigr)) + " shell --root --full-network", project, request,
        full_network=True, root=True,
    )
    assert endpoint["token"] in run_in_shell(first, f"curl --noproxy '*' -4fsS {host_url}")
    assert endpoint["token"] in run_in_shell(second, f"curl --noproxy '*' -4fsS {host_url}")
    first_public_dns = run_in_shell(first, "cd /home/user/workspace && ./dns_probe udp arbitrary.test")
    first_private_dns = run_in_shell(first, "cd /home/user/workspace && ./dns_probe udp private.test")
    assert "rcode=0" in first_public_dns and "a=93.184.216.34" in first_public_dns, first_public_dns
    assert "rcode=0" in first_private_dns and "a=192.168.1.12" in first_private_dns, first_private_dns
    assert_full_network_sessions(
        checked_run([zaigr, "project", "firewall", "show"], cwd=project.cwd, env=project.env),
        2, full_network=0, maintenance=2,
    )

    # The guest maintenance NIC and namespace are shared by all sessions.
    # A background process outlives its shell but keeps the shared lease.
    shared_stream = project.cwd / "full-network-shared-namespace-stream.log"
    run_in_shell(
        first,
        f"nohup curl --noproxy '*' -4fsSN --max-time 120 {host_url}stream "
        f"> /home/user/workspace/{shared_stream.name} 2>&1 < /dev/null &",
    )
    wait_text(shared_stream, endpoint["token"])
    exit_shell(first)
    assert_full_network_sessions(
        checked_run([zaigr, "project", "firewall", "show"], cwd=project.cwd, env=project.env),
        1, full_network=0, maintenance=1,
    )
    shared_length = len(shared_stream.read_bytes())
    time.sleep(0.5)
    assert len(shared_stream.read_bytes()) > shared_length, (
        "an ended shell's background process lost maintenance access while another shell remained"
    )
    assert endpoint["token"] in run_in_shell(second, f"curl --noproxy '*' -4fsS {host_url}")
    shared_public_dns = run_in_shell(
        second, "cd /home/user/workspace && ./dns_probe udp arbitrary.test"
    )
    shared_private_dns = run_in_shell(
        second, "cd /home/user/workspace && ./dns_probe udp private.test"
    )
    assert "rcode=0" in shared_public_dns and "a=93.184.216.34" in shared_public_dns, shared_public_dns
    assert "rcode=0" in shared_private_dns and "a=192.168.1.12" in shared_private_dns, shared_private_dns
    ordinary = checked_run(
        [zaigr, "project", "vm", "exec", "--", "bash", "-c",
         (f"if curl --noproxy '*' -4fsS --connect-timeout 2 --max-time 4 {host_url}; "
          "then echo UNEXPECTED_ACCESS; else echo VM_EXEC_DENIED; fi")],
        cwd=project.cwd, env=project.env, timeout=20,
    )
    assert "VM_EXEC_DENIED" in ordinary and "UNEXPECTED_ACCESS" not in ordinary

    exit_shell(second)
    assert_full_network_sessions(
        checked_run([zaigr, "project", "firewall", "show"], cwd=project.cwd, env=project.env),
        0, full_network=0, maintenance=0,
    )
    denied_after_last_session = _run(
        [zaigr, "project", "vm", "exec", "--", "curl", "--noproxy", "*", "-4fsS",
         "--connect-timeout", "2", "--max-time", "4", host_url],
        cwd=project.cwd, env=project.env, timeout=20,
    )
    assert denied_after_last_session[2] != 0, err_msg(
        denied_after_last_session[0], denied_after_last_session[1]
    )
    assert endpoint["token"] not in denied_after_last_session[0] + denied_after_last_session[1]
    assert resolver.count("arbitrary.test") >= 2 and resolver.count("private.test") >= 2


@pytest.mark.timeout(240)
def test_full_network_exposes_host_private_ipv4_data(project, host_network_endpoints, request):
    """Only the root maintenance namespace reaches a controlled private host service."""
    endpoint = host_network_endpoints
    if endpoint["private_ip"] is None:
        pytest.fail("BLOCKED: host has no private IPv4 interface outside guest uplink routes")

    zaigr = project.zaigr_bin
    checked_run([zaigr, "project", "vm", "start"], cwd=project.cwd, env=project.env,
                input="y\n", timeout=180)
    normal = open_shell(shlex.quote(str(zaigr)) + " shell", project, request)
    private_url = f"http://{endpoint['private_ip']}:{endpoint['private_tcp_port']}/"
    host_response = checked_run(
        ["curl", "--noproxy", "*", "-4fsS", "--max-time", "4", private_url], timeout=10
    )
    assert host_response == endpoint["token"]
    assert endpoint["request_counts"]()["tcp"] > 0
    denied = run_in_shell(
        normal,
        f"if curl --noproxy '*' -4fsS --connect-timeout 2 --max-time 4 {private_url}; "
        "then printf 'PROBE_RESULT=ALLOWED\\n'; else printf 'PROBE_RESULT=DENIED\\n'; fi",
    )
    assert_probe_marker(denied, "DENIED")
    assert endpoint["token"] not in denied
    shell = open_shell(
        shlex.quote(str(zaigr)) + " shell --root --full-network", project, request,
        full_network=True, root=True,
    )
    routes = run_in_shell(shell, "ip -4 route")
    output = run_in_shell(
        shell,
        f"curl --noproxy '*' -4vfsS --connect-timeout 3 --max-time 6 {private_url}",
    )
    assert endpoint["token"] in output, (
        f"{output}\nGuest IPv4 routes:\n{routes}\n"
        f"Host listener: {endpoint['private_ip']}:{endpoint['private_tcp_port']}\n"
        f"Endpoint requests: {endpoint['request_counts']()}"
    )
    denied = run_in_shell(
        normal,
        f"if curl --noproxy '*' -4fsS --connect-timeout 2 --max-time 4 {private_url}; "
        "then printf 'PROBE_RESULT=ALLOWED\\n'; else printf 'PROBE_RESULT=DENIED\\n'; fi",
    )
    assert_probe_marker(denied, "DENIED")
    assert endpoint["token"] not in denied
    exit_shell(shell)
    exit_shell(normal)


def reachable_public_https_ip():
    """Return a public PyPI address reachable directly from the host, if any."""
    for result in socket.getaddrinfo("pypi.org", 443, socket.AF_INET, socket.SOCK_STREAM):
        candidate = result[4][0]
        stdout, _stderr, code = _run([
            "curl", "--noproxy", "*", "--connect-timeout", "3", "--max-time", "8",
            "--resolve", f"pypi.org:443:{candidate}", "--output", "/dev/null",
            "--write-out", "%{http_code}", "https://pypi.org/",
        ], timeout=10)
        if code == 0 and stdout.strip().isdigit() and stdout.strip() != "000":
            return candidate
    return None


@pytest.mark.live_network
@pytest.mark.timeout(240)
def test_full_network_reaches_public_ipv4_without_dns_policy_changes(project, request):
    """Use a pre-resolved public address so this probe tests IPv4 scope only."""
    public_ip = reachable_public_https_ip()
    if public_ip is None:
        pytest.fail("BLOCKED: no direct reachable public IPv4 HTTPS endpoint for mandatory acceptance")

    zaigr = project.zaigr_bin
    checked_run([zaigr, "project", "vm", "start"], cwd=project.cwd, env=project.env,
                input="y\n", timeout=180)
    shell = open_shell(
        shlex.quote(str(zaigr)) + " shell --root --full-network", project, request,
        full_network=True, root=True,
    )
    output = run_in_shell(
        shell,
        f"curl --noproxy '*' -4sS --connect-timeout 4 --max-time 12 "
        f"--resolve pypi.org:443:{public_ip} --output /dev/null --write-out '%{{http_code}}' "
        "https://pypi.org/",
    )
    assert any(code in output for code in ("200", "301", "302")), output
    exit_shell(shell)


@pytest.mark.timeout(300)
def test_full_network_temporarily_allows_arbitrary_and_private_dns(
    project, host_network_dns, dns_probe_binary, setup_factory, request
):
    """Permit broad DNS during the lease without changing a restricted grant."""
    zaigr = project.zaigr_bin
    dns = host_network_dns
    assert dns_probe_binary.is_file()
    dns["resolver"].set_answer("pinned.test", "93.184.216.34", 2)
    dns["resolver"].set_answer("permanent.test", "192.168.1.14", 30)
    setup_factory(
        "pinned-dns", "true",
        firewall=[
            "pinned.test", "permanent.test", "alias.test", "linked-target.test", "zero-ttl.test",
        ],
    )
    checked_run([zaigr, "project", "vm", "start"], cwd=project.cwd, env=project.env,
                input="y\n", timeout=180)
    checked_run([zaigr, "project", "setup", "run", "pinned-dns"],
                cwd=project.cwd, env=project.env, timeout=180)

    normal = open_shell(shlex.quote(str(zaigr)) + " shell", project, request)
    pinned_public = run_in_shell(normal, "./dns_probe udp pinned.test")
    assert "rcode=0" in pinned_public and "a=93.184.216.34" in pinned_public, pinned_public
    pinned_queries = dns["resolver"].count("pinned.test")
    time.sleep(3)
    pinned_refreshed = run_in_shell(normal, "./dns_probe udp pinned.test")
    assert "rcode=0" in pinned_refreshed and "a=93.184.216.34" in pinned_refreshed
    assert dns["resolver"].count("pinned.test") > pinned_queries
    alias = run_in_shell(normal, "./dns_probe udp alias.test")
    assert "rcode=0" in alias and "answers=2" in alias, alias
    assert dns["resolver"].count("alias.test") > 0
    unsafe = run_in_shell(normal, "./dns_probe udp unsafe.test")
    malformed = run_in_shell(normal, "./dns_probe udp malformed.test")
    assert "rcode=0" not in unsafe, unsafe
    assert "rcode=0" not in malformed, malformed
    dns["resolver"].set_answer("pinned.test", "192.168.1.13", 30)
    full = open_shell(
        shlex.quote(str(zaigr)) + " shell --root --full-network", project, request, full_network=True
    )
    public = run_in_shell(full, "cd /home/user/workspace && ./dns_probe udp arbitrary.test")
    assert "rcode=0" in public and "a=93.184.216.34" in public, public
    private = run_in_shell(full, "cd /home/user/workspace && ./dns_probe udp private.test")
    assert "rcode=0" in private and "a=192.168.1.12" in private, private
    permanent_private = run_in_shell(full, "cd /home/user/workspace && ./dns_probe udp permanent.test")
    assert "rcode=0" in permanent_private and "a=192.168.1.14" in permanent_private
    pinned_private = run_in_shell(full, "cd /home/user/workspace && ./dns_probe udp pinned.test")
    assert "rcode=0" in pinned_private and "a=192.168.1.13" in pinned_private, pinned_private
    unsafe_in_full = run_in_shell(full, "cd /home/user/workspace && ./dns_probe udp unsafe.test")
    assert "rcode=0" not in unsafe_in_full, unsafe_in_full
    malformed_in_full = run_in_shell(full, "cd /home/user/workspace && ./dns_probe udp malformed.test")
    assert "rcode=0" not in malformed_in_full, malformed_in_full
    public_refused_during_maintenance = run_in_shell(
        normal, "./dns_probe udp arbitrary.test"
    )
    private_refused_during_maintenance = run_in_shell(
        normal, "./dns_probe udp private.test"
    )
    pinned_private_refused_during_maintenance = run_in_shell(
        normal, "./dns_probe udp pinned.test"
    )
    assert "rcode=5" in public_refused_during_maintenance, public_refused_during_maintenance
    assert "rcode=5" in private_refused_during_maintenance, private_refused_during_maintenance
    assert "rcode=0" not in pinned_private_refused_during_maintenance, pinned_private_refused_during_maintenance
    assert dns["resolver"].count("arbitrary.test") > 0
    assert dns["resolver"].count("private.test") > 0
    exit_shell(full)

    public_refused = run_in_shell(normal, "./dns_probe udp arbitrary.test")
    private_refused = run_in_shell(normal, "./dns_probe udp private.test")
    pinned_private_refused = run_in_shell(normal, "./dns_probe udp pinned.test")
    assert "rcode=5" in public_refused, public_refused
    assert "rcode=5" in private_refused, private_refused
    dns["resolver"].set_answer("permanent.test", "93.184.216.35", 30)
    permanent_public = run_in_shell(normal, "./dns_probe udp permanent.test")
    assert "rcode=0" in permanent_public and "a=93.184.216.35" in permanent_public
    assert "rcode=0" not in pinned_private_refused, pinned_private_refused
    unsafe_refused = run_in_shell(normal, "./dns_probe udp unsafe.test")
    malformed_refused = run_in_shell(normal, "./dns_probe udp malformed.test")
    assert "rcode=0" not in unsafe_refused, unsafe_refused
    assert "rcode=0" not in malformed_refused, malformed_refused
    assert dns["resolver"].count("arbitrary.test") == 1
    assert dns["resolver"].count("private.test") == 1
    assert dns_probe_binary.is_file()
    dns["resolver"].set_answer("pinned.test", "93.184.216.34", 30)
    pinned_allowed_again = run_in_shell(normal, "./dns_probe udp pinned.test")
    assert "rcode=0" in pinned_allowed_again and "a=93.184.216.34" in pinned_allowed_again, pinned_allowed_again
    exit_shell(normal)


@pytest.mark.skip(reason=(
    "holds one deb.debian.org address for minutes; when the site moves to another "
    "address, a zaigr firewall around the test machine blocks it"
))
@pytest.mark.parametrize("manual_ip_reference", [False, True])
@pytest.mark.timeout(360)
def test_exact_dns_grants_share_and_release_live_ip_references(
    project, host_network_dns, public_http_stream_client, manual_ip_reference, request
):
    """Keep a public HTTP flow through shared DNS grants until its final reference is removed."""
    zaigr = project.zaigr_bin
    dns = host_network_dns
    public_ip = public_address("deb.debian.org")
    debian_url = "http://deb.debian.org/debian/dists/trixie/main/binary-amd64/Packages.xz"
    host_control = checked_run(
        ["curl", "--noproxy", "*", "-4fsSI", "--connect-timeout", "4", "--max-time", "12",
         "--resolve", f"deb.debian.org:80:{public_ip}", debian_url], timeout=15
    )
    content_length = next(
        int(line.split(":", 1)[1])
        for line in host_control.splitlines()
        if line.lower().startswith("content-length:")
    )
    assert "200 OK" in host_control and content_length > 5_000_000, host_control
    dns["resolver"].set_answer("lease-a.test", public_ip, 8)
    dns["resolver"].set_answer("lease-b.test", public_ip, 8)

    checked_run([zaigr, "project", "vm", "start"], cwd=project.cwd, env=project.env,
                input="y\n", timeout=180)
    checked_run([zaigr, "project", "firewall", "allow", "lease-a.test"],
                cwd=project.cwd, env=project.env, timeout=20)
    checked_run([zaigr, "project", "firewall", "allow", "lease-b.test"],
                cwd=project.cwd, env=project.env, timeout=20)
    if manual_ip_reference:
        checked_run([zaigr, "project", "firewall", "allow", public_ip],
                    cwd=project.cwd, env=project.env, timeout=20)

    normal = open_shell(shlex.quote(str(zaigr)) + " shell", project, request)
    stream_a = project.cwd / "lease-a-stream.log"
    try:
        a_answer = checked_run(
            [zaigr, "project", "vm", "exec", "--", "getent", "ahostsv4", "lease-a.test"],
            cwd=project.cwd, env=project.env, timeout=20,
        )
        b_answer = checked_run(
            [zaigr, "project", "vm", "exec", "--", "getent", "ahostsv4", "lease-b.test"],
            cwd=project.cwd, env=project.env, timeout=20,
        )
        assert public_ip in a_answer and public_ip in b_answer
        checked_run(
            [zaigr, "project", "vm", "exec", "--", "bash", "-c",
             (f"nohup timeout 240 ./{public_http_stream_client.name} {public_ip} 80 "
              "/debian/dists/trixie/main/binary-amd64/Packages.xz "
              f"> {stream_a.name} 2>&1 < /dev/null &")],
            cwd=project.cwd, env=project.env, timeout=20,
        )
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if stream_a.exists() and len(stream_a.read_bytes()) >= 1024:
                break
            time.sleep(0.05)
        assert stream_a.exists() and len(stream_a.read_bytes()) >= 1024, (
            stream_a.read_text() if stream_a.exists() else "stream never started"
        )
        assert stream_a.read_bytes().startswith(b"HTTP/1.1 200 OK"), stream_a.read_bytes()[:128]
        initial_queries = (
            dns["resolver"].count("lease-a.test"),
            dns["resolver"].count("lease-b.test"),
        )
        # Renewal must happen without guest DNS lookups after the initial grants.
        before_refresh_window = len(stream_a.read_bytes())
        time.sleep(18)
        assert dns["resolver"].count("lease-a.test") > initial_queries[0]
        assert dns["resolver"].count("lease-b.test") > initial_queries[1]
        assert len(stream_a.read_bytes()) > before_refresh_window, (
            "authorized public transfer stopped across automatic TTL refresh"
        )
        checked_run(
            [zaigr, "project", "vm", "exec", "--", "curl", "--noproxy", "*", "-4fsS",
             "--connect-timeout", "4", "--max-time", "12", "--resolve",
             f"lease-a.test:80:{public_ip}", "-H", "Host: deb.debian.org",
             "--output", "/dev/null",
             "http://lease-a.test/debian/dists/trixie/main/binary-amd64/Packages.xz"],
            cwd=project.cwd, env=project.env, timeout=20,
        )
        checked_run([zaigr, "project", "firewall", "remove", "lease-a.test"],
                    cwd=project.cwd, env=project.env, timeout=20)
        time.sleep(0.5)
        before_remove_a = len(stream_a.read_bytes())
        growth_deadline = time.monotonic() + 5
        while time.monotonic() < growth_deadline and len(stream_a.read_bytes()) <= before_remove_a:
            time.sleep(0.1)
        assert len(stream_a.read_bytes()) > before_remove_a, (
            "removing lease-a.test dropped an IP flow still referenced by lease-b.test"
        )
        assert "lease-b.test" in checked_run(
            [zaigr, "project", "firewall", "show"],
            cwd=project.cwd, env=project.env,
        )

        checked_run([zaigr, "project", "firewall", "remove", "lease-b.test"],
                    cwd=project.cwd, env=project.env, timeout=20)
        if manual_ip_reference:
            direct_ip_access = checked_run(
                [zaigr, "project", "vm", "exec", "--", "curl", "--noproxy", "*", "-4fsS",
                 "--connect-timeout", "4", "--max-time", "12", "--resolve",
                 f"lease-b.test:80:{public_ip}", "-H", "Host: deb.debian.org",
                 "--output", "/dev/null",
                 "http://lease-b.test/debian/dists/trixie/main/binary-amd64/Packages.xz"],
                cwd=project.cwd, env=project.env, timeout=20,
            )
            assert direct_ip_access == "", direct_ip_access
            time.sleep(0.5)
            before_static_remove = len(stream_a.read_bytes())
            growth_deadline = time.monotonic() + 5
            while time.monotonic() < growth_deadline and len(stream_a.read_bytes()) <= before_static_remove:
                time.sleep(0.1)
            assert len(stream_a.read_bytes()) > before_static_remove, (
                "removing DNS references dropped a flow still authorized by the exact IP grant"
            )
            checked_run([zaigr, "project", "firewall", "remove", public_ip],
                        cwd=project.cwd, env=project.env, timeout=20)
        else:
            denied = checked_run(
                [zaigr, "project", "vm", "exec", "--", "bash", "-c",
                 (f"if curl --noproxy '*' -4fsS --connect-timeout 4 --max-time 12 "
                  f"--resolve lease-b.test:80:{public_ip} -H 'Host: deb.debian.org' "
                  "http://lease-b.test/debian/dists/trixie/main/binary-amd64/Packages.xz; "
                  "then echo UNEXPECTED_ACCESS; "
                  "else echo DNS_REVOKED; fi")],
                cwd=project.cwd, env=project.env, timeout=20,
            )
            assert "DNS_REVOKED" in denied and "UNEXPECTED_ACCESS" not in denied, denied
        # Let bytes already buffered in the guest TCP receive queue drain before
        # deciding that revocation stopped this flow.
        time.sleep(0.5)
        previous_length = len(stream_a.read_bytes())
        quiet_since = time.monotonic()
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            time.sleep(0.25)
            current_length = len(stream_a.read_bytes())
            if current_length != previous_length:
                previous_length = current_length
                quiet_since = time.monotonic()
            elif time.monotonic() - quiet_since >= 2:
                break
        assert time.monotonic() - quiet_since >= 2, "revoked stream did not become quiet"

        checked_run([zaigr, "project", "firewall", "allow", "lease-b.test"],
                    cwd=project.cwd, env=project.env, timeout=20)
        assert public_ip in checked_run(
            [zaigr, "project", "vm", "exec", "--", "getent", "ahostsv4", "lease-b.test"],
            cwd=project.cwd, env=project.env, timeout=20,
        )
        checked_run(
            [zaigr, "project", "vm", "exec", "--", "curl", "--noproxy", "*", "-4fsS",
             "--connect-timeout", "4", "--max-time", "12", "--resolve",
             f"lease-b.test:80:{public_ip}", "-H", "Host: deb.debian.org",
             "--output", "/dev/null",
             "http://lease-b.test/debian/dists/trixie/main/binary-amd64/Packages.xz"],
            cwd=project.cwd, env=project.env, timeout=20,
        )
        time.sleep(1)
        assert len(stream_a.read_bytes()) == previous_length, (
            "regranting a DNS name resumed the old TCP stream"
        )
    finally:
        exit_shell(normal)


def stream_grows(path, seconds):
    """Return whether a guest stream log grows within the window."""
    before = len(path.read_bytes())
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if len(path.read_bytes()) > before:
            return True
        time.sleep(0.1)
    return False


def stream_goes_quiet(path, seconds):
    """Return whether a guest stream stops growing for two seconds within the window."""
    # Bytes already buffered in the guest receive queue may drain first.
    previous_length = len(path.read_bytes())
    quiet_since = time.monotonic()
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        time.sleep(0.25)
        current_length = len(path.read_bytes())
        if current_length != previous_length:
            previous_length = current_length
            quiet_since = time.monotonic()
        elif time.monotonic() - quiet_since >= 2:
            return True
    return False


@pytest.mark.skip(reason=(
    "holds one deb.debian.org address for minutes; when the site moves to another "
    "address, a zaigr firewall around the test machine blocks it"
))
@pytest.mark.timeout(360)
def test_dns_answer_change_keeps_established_flow_until_domain_removed(
    project, host_network_dns, public_http_stream_client, request
):
    """A CDN moving an allowed name to new IPs must not cut connections already open."""
    zaigr = project.zaigr_bin
    dns = host_network_dns
    public_ip = public_address("deb.debian.org")
    # Any other public address: the name's answer moves away from public_ip.
    rotated_ip = "151.101.2.132"
    assert rotated_ip != public_ip
    dns["resolver"].set_answer("cdn.test", public_ip, 5)

    checked_run([zaigr, "project", "vm", "start"], cwd=project.cwd, env=project.env,
                input="y\n", timeout=180)
    checked_run([zaigr, "project", "firewall", "allow", "cdn.test"],
                cwd=project.cwd, env=project.env, timeout=20)
    normal = open_shell(shlex.quote(str(zaigr)) + " shell", project, request)
    stream = project.cwd / "cdn-rotation-stream.log"
    try:
        assert public_ip in checked_run(
            [zaigr, "project", "vm", "exec", "--", "getent", "ahostsv4", "cdn.test"],
            cwd=project.cwd, env=project.env, timeout=20,
        )
        checked_run(
            [zaigr, "project", "vm", "exec", "--", "bash", "-c",
             (f"nohup timeout 300 ./{public_http_stream_client.name} {public_ip} 80 "
              "/debian/dists/trixie/main/binary-amd64/Packages.xz "
              f"> {stream.name} 2>&1 < /dev/null &")],
            cwd=project.cwd, env=project.env, timeout=20,
        )
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and not (stream.exists() and len(stream.read_bytes()) >= 1024):
            time.sleep(0.05)
        assert stream.exists() and stream.read_bytes().startswith(b"HTTP/1.1 200 OK"), (
            stream.read_bytes()[:128] if stream.exists() else "stream never started"
        )

        queries = dns["resolver"].count("cdn.test")
        dns["resolver"].set_answer("cdn.test", rotated_ip, 5)
        # Wait well past several TTLs so the host has refreshed the name.
        for _ in range(6):
            time.sleep(5)
            assert stream_grows(stream, 4), (
                "an established connection stopped after the allowed name's DNS answer moved to another IP"
            )
        assert dns["resolver"].count("cdn.test") > queries, "the host never refreshed the changed answer"
        assert rotated_ip in checked_run(
            [zaigr, "project", "vm", "exec", "--", "getent", "ahostsv4", "cdn.test"],
            cwd=project.cwd, env=project.env, timeout=20,
        )

        # The old address is no longer an answer for any allowed name, so new
        # connections to it stay blocked even while the old flow continues.
        denied = checked_run(
            [zaigr, "project", "vm", "exec", "--", "bash", "-c",
             (f"if curl --noproxy '*' -4fsS --connect-timeout 4 --max-time 8 -o /dev/null "
              f"--resolve cdn.test:80:{public_ip} -H 'Host: deb.debian.org' "
              "http://cdn.test/debian/dists/trixie/Release; "
              "then echo UNEXPECTED_ACCESS; else echo NEW_FLOW_BLOCKED; fi")],
            cwd=project.cwd, env=project.env, timeout=20,
        )
        assert "NEW_FLOW_BLOCKED" in denied and "UNEXPECTED_ACCESS" not in denied, denied
        assert stream_grows(stream, 4), "a blocked new connection disturbed the established flow"

        # Removing the domain is the explicit revocation: it ends the old flow too.
        checked_run([zaigr, "project", "firewall", "remove", "cdn.test"],
                    cwd=project.cwd, env=project.env, timeout=20)
        assert stream_goes_quiet(stream, 8), (
            "removing the domain left a connection opened under its earlier answer running"
        )
    finally:
        exit_shell(normal)


@pytest.mark.timeout(180)
def test_delayed_dns_answer_cannot_restore_removed_grant(
    project, host_network_dns, dns_probe_binary, request
):
    """A late DNS response cannot recreate an exact grant removed in flight."""
    zaigr = project.zaigr_bin
    resolver = host_network_dns["resolver"]
    assert dns_probe_binary.is_file()
    public_ip = public_address("deb.debian.org")
    debian_url = "http://deb.debian.org/debian/dists/trixie/main/binary-amd64/Packages.xz"
    host_control = checked_run(
        ["curl", "--noproxy", "*", "-4fsSI", "--connect-timeout", "4", "--max-time", "12",
         "--resolve", f"deb.debian.org:80:{public_ip}", debian_url], timeout=15,
    )
    assert "200 OK" in host_control, host_control
    resolver.set_answer("delayed.test", public_ip, 30)
    checked_run([zaigr, "project", "vm", "start"], cwd=project.cwd, env=project.env,
                input="y\n", timeout=180)
    checked_run([zaigr, "project", "firewall", "allow", "delayed.test"],
                cwd=project.cwd, env=project.env, timeout=20)
    normal = open_shell(shlex.quote(str(zaigr)) + " shell", project, request)
    try:
        normal.sendline("./dns_probe udp delayed.test")
        assert resolver.delayed_seen.wait(8), "guest did not issue delayed DNS query"
        checked_run([zaigr, "project", "firewall", "remove", "delayed.test"],
                    cwd=project.cwd, env=project.env, timeout=20)
        resolver.release_delayed.set()
        normal.expect(USER_PROMPT, timeout=12)
        assert "rcode=0" not in normal.before, normal.before
        denied = checked_run(
            [zaigr, "project", "vm", "exec", "--", "bash", "-c",
             (f"if curl --noproxy '*' -4fsS --connect-timeout 2 --max-time 4 "
              f"--resolve delayed.test:80:{public_ip} -H 'Host: deb.debian.org' "
              "http://delayed.test/debian/dists/trixie/main/binary-amd64/Packages.xz; "
              "then echo UNEXPECTED_ACCESS; else echo DENIED; fi")],
            cwd=project.cwd, env=project.env, timeout=15,
        )
        assert "DENIED" in denied, denied
    finally:
        resolver.release_delayed.set()
        exit_shell(normal)


@pytest.mark.timeout(300)
def test_full_network_lease_expires_when_owner_supervisor_is_stopped(
    project, host_network_endpoints, request
):
    """A stopped renewer loses the temporary broad lease within ten seconds."""
    zaigr = project.zaigr_bin
    endpoint = host_network_endpoints
    host_url = f"http://10.0.2.2:{endpoint['tcp_port']}/"
    checked_run([zaigr, "project", "vm", "start"], cwd=project.cwd, env=project.env,
                input="y\n", timeout=180)
    shell = open_shell(
        shlex.quote(str(zaigr)) + " shell --root --full-network", project, request, full_network=True
    )
    assert endpoint["token"] in run_in_shell(
        shell,
        f"curl --noproxy '*' -4fsS --max-time 4 {host_url}",
    )
    owner_stream = project.cwd / "full-network-supervisor-stop-stream.log"
    run_in_shell(
        shell,
        f"nohup curl --noproxy '*' -4fsSN --max-time 120 {host_url}stream "
        f"> /home/user/workspace/{owner_stream.name} 2>&1 < /dev/null &",
    )
    wait_text(owner_stream, endpoint["token"])

    record_path = project.store_dir / "vm-supervisor.json"
    record = json.loads(record_path.read_text())
    assert record["supervisor"]["pid"] > 1, record
    signal_recorded_process(record, "supervisor", signal.SIGSTOP)
    try:
        # The guest session remains available while the host lease expires.
        time.sleep(11)
        expired = run_in_shell(
            shell,
            f"if curl --noproxy '*' -4fsS --connect-timeout 2 --max-time 4 {host_url}; "
            "then printf 'PROBE_RESULT=ALLOWED\\n'; else printf 'PROBE_RESULT=DENIED\\n'; fi",
        )
        assert_probe_marker(expired, "DENIED")
        assert endpoint["token"] not in expired
        frozen_length = len(owner_stream.read_bytes())
        time.sleep(0.5)
        assert len(owner_stream.read_bytes()) == frozen_length
    finally:
        signal_recorded_process(record, "supervisor", signal.SIGCONT)
        exit_shell(shell)

    # Resuming the supervisor must not resurrect the expired lease ID after
    # its owning CLI has exited.
    denied = _run(
        [zaigr, "project", "vm", "exec", "--", "curl", "--noproxy", "*", "-4fsS",
         "--connect-timeout", "2", "--max-time", "4", host_url],
        cwd=project.cwd, env=project.env, timeout=20,
    )
    assert denied[2] != 0, err_msg(denied[0], denied[1])
    assert endpoint["token"] not in denied[0] + denied[1]


def host_maintenance_nft(project, record, *arguments):
    """Run nft in the host helper's private network namespace."""
    helper_pid = record["network_processes"]["hostnet-helper"]["pid"]
    command = [
        "nsenter", "--target", str(helper_pid), "--user", "--net",
        "--preserve-credentials", "/usr/sbin/nft", *arguments,
    ]
    stdout, stderr, code = _run(command, cwd=project.cwd, env=project.env, timeout=15)
    assert code == 0, err_msg(stdout, stderr)
    return stdout


def maintenance_gate_counters(project, record):
    """Read the four shared named counter objects used by the production gate."""
    expected = (
        "maintenance_gate_accept_to_uplink",
        "maintenance_gate_accept_from_uplink",
        "maintenance_gate_drop_to_uplink",
        "maintenance_gate_drop_from_uplink",
    )
    # These IDs and attributes follow linux/netfilter/nf_tables.h. GETOBJ reads
    # one named object without asking nft userspace to decode the whole table.
    helper = r'''import json, socket, struct, sys
TABLE = "zaigr"
NFNL_SUBSYS_NFTABLES = 10
NFT_MSG_GETOBJ = 19
NFT_MSG_NEWOBJ = 18
NFT_MSG_GETGEN = 16
NFT_MSG_NEWGEN = 15
NFTA_OBJ_TABLE = 1
NFTA_OBJ_NAME = 2
NFTA_OBJ_TYPE = 3
NFTA_OBJ_DATA = 4
NFT_OBJECT_COUNTER = 1
NFTA_COUNTER_BYTES = 1
NFTA_COUNTER_PACKETS = 2
NLMSG_ERROR = 2
NLMSG_DONE = 3
NLM_F_REQUEST = 1
NFPROTO_INET = 1

def attr(kind, value):
    data = struct.pack("=HH", 4 + len(value), kind) + value
    return data + b"\0" * ((-len(data)) % 4)

def attributes(data):
    while len(data) >= 4:
        length, kind = struct.unpack_from("=HH", data)
        if length < 4 or length > len(data):
            raise RuntimeError("invalid netlink attribute length")
        yield kind & 0x3fff, data[4:length]
        data = data[(length + 3) & ~3:]

def current_res_id(sock):
    message_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETGEN
    payload = struct.pack("!BBH", 0, 0, 0)
    header = struct.pack("=IHHII", 20, message_type, NLM_F_REQUEST, 1, 0)
    sock.send(header + payload)
    while True:
        response = sock.recv(65536)
        offset = 0
        while offset + 16 <= len(response):
            length, kind, flags, sequence, pid = struct.unpack_from("=IHHII", response, offset)
            message = response[offset + 16:offset + length]
            offset += (length + 3) & ~3
            if sequence != 1:
                continue
            if kind == NLMSG_ERROR:
                error = struct.unpack_from("=i", message)[0]
                if error:
                    raise OSError(-error, "nftables GETGEN failed")
                continue
            response_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWGEN
            if kind == response_type and len(message) >= 4:
                return struct.unpack_from("!H", message, 2)[0]

def counter(sock, sequence, name, res_id):
    payload = struct.pack("!BBH", NFPROTO_INET, 0, res_id)
    payload += attr(NFTA_OBJ_TABLE, TABLE.encode() + b"\0")
    payload += attr(NFTA_OBJ_NAME, name.encode() + b"\0")
    payload += attr(NFTA_OBJ_TYPE, struct.pack("!I", NFT_OBJECT_COUNTER))
    message_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETOBJ
    header = struct.pack("=IHHII", 16 + len(payload), message_type, NLM_F_REQUEST, sequence, 0)
    sock.send(header + payload)
    while True:
        response = sock.recv(65536)
        offset = 0
        while offset + 16 <= len(response):
            length, kind, flags, seq, pid = struct.unpack_from("=IHHII", response, offset)
            message = response[offset + 16:offset + length]
            offset += (length + 3) & ~3
            if seq != sequence:
                continue
            if kind == NLMSG_ERROR:
                error = struct.unpack_from("=i", message)[0]
                if error:
                    raise OSError(-error, "nftables GETOBJ failed for " + name)
                continue
            if kind == NLMSG_DONE:
                raise RuntimeError("nftables GETOBJ returned no object for " + name)
            response_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWOBJ
            if kind != response_type or len(message) < 4:
                continue
            if message[0] != NFPROTO_INET:
                raise RuntimeError("nftables GETOBJ returned the wrong family for " + name)
            object_fields = {}
            counter_data = None
            for outer_kind, value in attributes(message[4:]):
                if outer_kind in (NFTA_OBJ_TABLE, NFTA_OBJ_NAME):
                    object_fields[outer_kind] = value.rstrip(b"\0").decode()
                elif outer_kind == NFTA_OBJ_TYPE:
                    object_fields[outer_kind] = struct.unpack("!I", value[:4])[0]
                elif outer_kind == NFTA_OBJ_DATA:
                    counter_data = value
            if object_fields.get(NFTA_OBJ_TABLE) != TABLE:
                raise RuntimeError("nftables GETOBJ returned the wrong table for " + name)
            if object_fields.get(NFTA_OBJ_NAME) != name:
                raise RuntimeError("nftables GETOBJ returned the wrong object name for " + name)
            if object_fields.get(NFTA_OBJ_TYPE) != NFT_OBJECT_COUNTER:
                raise RuntimeError("nftables GETOBJ returned the wrong object type for " + name)
            if counter_data is None:
                raise RuntimeError("nftables GETOBJ response lacks counter data for " + name)
            result = {}
            for inner_kind, inner_value in attributes(counter_data):
                if inner_kind in (NFTA_COUNTER_BYTES, NFTA_COUNTER_PACKETS):
                    # nftables emits these NLA_U64 counter values in BE.
                    result[inner_kind] = struct.unpack("!Q", inner_value[:8])[0]
            if NFTA_COUNTER_PACKETS not in result or NFTA_COUNTER_BYTES not in result:
                raise RuntimeError("counter response lacks packet/byte totals for " + name)
            return {"packets": result[NFTA_COUNTER_PACKETS], "bytes": result[NFTA_COUNTER_BYTES]}

sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 12)
sock.bind((0, 0))
res_id = current_res_id(sock)
result = {}
for sequence, name in enumerate(sys.argv[1:], 1):
    result[name] = counter(sock, sequence + 1, name, res_id)
print(json.dumps(result, sort_keys=True))
'''
    helper_pid = record["network_processes"]["hostnet-helper"]["pid"]
    command = [
        "nsenter", "--target", str(helper_pid), "--user", "--net",
        "--preserve-credentials", "/usr/bin/python3", "-c", helper, *expected,
    ]
    stdout, stderr, code = _run(command, cwd=project.cwd, env=project.env, timeout=15)
    assert code == 0, err_msg(stdout, stderr)
    counts = json.loads(stdout)
    assert set(counts) == set(expected), counts
    return {name: int(counts[name]["packets"]) for name in expected}


def guest_udp_counts(path):
    """Return the latest send and receive totals written by the guest UDP probe."""
    if not path.exists():
        return 0, 0
    rows = re.findall(
        r"(?m)^GUEST_SENT=(\d+) GUEST_RECEIVED=(\d+)\r?$",
        path.read_text(errors="replace"),
    )
    return tuple(map(int, rows[-1])) if rows else (0, 0)


@pytest.mark.timeout(300)
def test_maintenance_nic_lease_expires_with_bidirectional_udp_accounting(
    project, host_network_endpoints, request
):
    """Every datagram admitted by tap-maint before expiry is the full residual."""
    zaigr = project.zaigr_bin
    endpoint = host_network_endpoints
    source = "tests/cli/host_network_fixture/udp_lease_stream.c"
    probe = project.cwd / "maintenance-udp-lease-stream"
    stdout, stderr, code = _run(
        ["gcc", "-static", "-O2", "-Wall", "-Wextra", "-Werror", "-o", probe, source],
        timeout=30,
    )
    assert code == 0, err_msg(stdout, stderr)

    checked_run(
        [zaigr, "project", "vm", "start"], cwd=project.cwd, env=project.env,
        input="y\n", timeout=180,
    )
    control = open_shell(shlex.quote(str(zaigr)) + " shell", project, request)
    maintenance = open_shell(
        shlex.quote(str(zaigr)) + " shell --root --full-network", project, request,
        full_network=True, root=True,
    )
    udp_log = project.cwd / "maintenance-udp-lease-stream.log"
    record = json.loads((project.store_dir / "vm-supervisor.json").read_text())
    assert record["supervisor"]["pid"] > 1, record
    assert "hostnet-helper" in record["network_processes"], record
    set_before = host_maintenance_nft(
        project, record, "list", "set", "inet", "zaigr", "maintenance_network"
    )
    assert re.search(r"(?<!\d)10\.0\.4\.2(?!\d)", set_before), set_before
    command_output = run_in_shell(
        maintenance,
        f"nohup /home/user/workspace/{probe.name} 10.0.2.2 {endpoint['udp_port']} "
        f"45123 > /home/user/workspace/{udp_log.name} 2>&1 < /dev/null & "
        "printf 'UDP_STREAM_PID=%s\\n' \"$!\"",
    )
    pid_match = re.search(r"(?m)^UDP_STREAM_PID=(\d+)\r?$", command_output)
    assert pid_match, command_output
    stream_pid = pid_match.group(1)
    endpoint["start_udp_peer"]()

    positive_deadline = time.monotonic() + 12
    positive = maintenance_gate_counters(project, record)
    while time.monotonic() < positive_deadline:
        guest_sent, guest_received = guest_udp_counts(udp_log)
        host_counts = endpoint["request_counts"]()
        positive = maintenance_gate_counters(project, record)
        if guest_sent > 10 and guest_received > 10 and host_counts["udp"] > 10:
            break
        time.sleep(0.2)
    guest_sent, guest_received = guest_udp_counts(udp_log)
    host_counts = endpoint["request_counts"]()
    assert guest_sent > 10 and guest_received > 10, udp_log.read_text()
    assert host_counts["udp"] > 10 and host_counts["udp_peer_sent"] > 10, host_counts
    assert positive["maintenance_gate_accept_to_uplink"] > 0, positive
    assert positive["maintenance_gate_accept_from_uplink"] > 0, positive
    assert "CONTROL_POSITIVE" in run_in_shell(control, "printf CONTROL_POSITIVE")

    supervisor_stopped = False
    helper_stopped = False
    try:
        signal_recorded_process(record, "supervisor", signal.SIGSTOP)
        supervisor_stopped = True
        signal_recorded_process(
            record, "hostnet-helper", signal.SIGSTOP, network_process=True
        )
        helper_stopped = True
        assert "CONTROL_HELD" in run_in_shell(control, "printf CONTROL_HELD")

        expiry_deadline = time.monotonic() + 18
        set_at_expiry = set_before
        while time.monotonic() < expiry_deadline:
            set_at_expiry = host_maintenance_nft(
                project, record, "list", "set", "inet", "zaigr", "maintenance_network"
            )
            if not re.search(r"(?<!\d)10\.0\.4\.2(?!\d)", set_at_expiry):
                break
            time.sleep(0.2)
        assert not re.search(r"(?<!\d)10\.0\.4\.2(?!\d)", set_at_expiry), set_at_expiry
        accepted_at_expiry = maintenance_gate_counters(project, record)
        assert accepted_at_expiry["maintenance_gate_accept_to_uplink"] > 0, accepted_at_expiry
        assert accepted_at_expiry["maintenance_gate_accept_from_uplink"] > 0, accepted_at_expiry
        counts_at_expiry = endpoint["request_counts"]()
        guest_at_expiry = guest_udp_counts(udp_log)
        assert "CONTROL_EXPIRED" in run_in_shell(control, "printf CONTROL_EXPIRED")
        new_connection = run_in_shell(
            maintenance,
            f"if curl --noproxy '*' -4fsS --connect-timeout 2 --max-time 4 "
            f"http://10.0.2.2:{endpoint['tcp_port']}/; then "
            "printf 'PROBE_RESULT=ALLOWED\\n'; else printf 'PROBE_RESULT=DENIED\\n'; fi",
        )
        assert_probe_marker(new_connection, "DENIED")
        assert endpoint["token"] not in new_connection
        signal_recorded_process(
            record, "hostnet-helper", signal.SIGCONT, network_process=True
        )
        helper_stopped = False
        signal_recorded_process(record, "supervisor", signal.SIGCONT)
        supervisor_stopped = False

        assert "CONTROL_RELEASED" in run_in_shell(control, "printf CONTROL_RELEASED")
        assert "CONTROL_RELEASED" in run_in_shell(maintenance, "printf CONTROL_RELEASED")
        live_deadline = time.monotonic() + 8
        network_live = ""
        while time.monotonic() < live_deadline:
            network_live = host_maintenance_nft(
                project, record, "list", "set", "inet", "zaigr", "network_live"
            )
            if re.search(r"elements\s*=\s*\{\s*0(?:\s|[,}])", network_live):
                break
            time.sleep(0.2)
        assert re.search(r"elements\s*=\s*\{\s*0(?:\s|[,}])", network_live), network_live
        release_deadline = time.monotonic() + 8
        set_after_release = set_at_expiry
        while time.monotonic() < release_deadline:
            set_after_release = host_maintenance_nft(
                project, record, "list", "set", "inet", "zaigr", "maintenance_network"
            )
            if not re.search(r"(?<!\d)10\.0\.4\.2(?!\d)", set_after_release):
                break
            time.sleep(0.2)
        assert not re.search(r"(?<!\d)10\.0\.4\.2(?!\d)", set_after_release), set_after_release
        counters_after_release = maintenance_gate_counters(project, record)
        time.sleep(1.2)
        counters_later = maintenance_gate_counters(project, record)
        assert counters_later["maintenance_gate_accept_to_uplink"] == accepted_at_expiry[
            "maintenance_gate_accept_to_uplink"
        ], (accepted_at_expiry, counters_later)
        assert counters_later["maintenance_gate_accept_from_uplink"] == accepted_at_expiry[
            "maintenance_gate_accept_from_uplink"
        ], (accepted_at_expiry, counters_later)
        drops_after_release = (
            counters_after_release["maintenance_gate_drop_to_uplink"],
            counters_after_release["maintenance_gate_drop_from_uplink"],
        )
        drops_later = (
            counters_later["maintenance_gate_drop_to_uplink"],
            counters_later["maintenance_gate_drop_from_uplink"],
        )
        assert drops_later[0] > drops_after_release[0], (drops_after_release, drops_later)
        assert drops_later[1] > drops_after_release[1], (drops_after_release, drops_later)
        assert endpoint["request_counts"]()["udp_peer_sent"] > counts_at_expiry["udp_peer_sent"]
        guest_after_release = guest_udp_counts(udp_log)
        assert guest_after_release[0] > guest_at_expiry[0], (
            "guest UDP sender stopped while the host gate was denying its packets"
        )
        endpoint["stop_udp_peer"]()
        run_in_shell(maintenance, f"kill -USR1 {stream_pid}")
        drain_deadline = time.monotonic() + 6
        while time.monotonic() < drain_deadline and "GUEST_STREAM_DRAINED=1" not in udp_log.read_text():
            time.sleep(0.2)
        assert "GUEST_STREAM_DRAINED=1" in udp_log.read_text(), udp_log.read_text()
        final_guest_counts = guest_udp_counts(udp_log)
        assert final_guest_counts[0] > 0, udp_log.read_text()
        assert endpoint["request_counts"]()["udp"] <= accepted_at_expiry[
            "maintenance_gate_accept_to_uplink"
        ], endpoint["request_counts"]()
        assert final_guest_counts[1] <= accepted_at_expiry[
            "maintenance_gate_accept_from_uplink"
        ], (final_guest_counts, accepted_at_expiry)
        assert "CONTROL_AFTER_EXPIRY" in run_in_shell(control, "printf CONTROL_AFTER_EXPIRY")
        request.node.user_properties.append((
            "maintenance_udp_gate",
            json.dumps({
                "accepted_at_expiry": accepted_at_expiry,
                "counters_later": counters_later,
                "final_guest_counts": {
                    "sent": final_guest_counts[0],
                    "received": final_guest_counts[1],
                },
                "host_request_counts": endpoint["request_counts"](),
            }, sort_keys=True),
        ))
    finally:
        if helper_stopped:
            signal_recorded_process(
                record, "hostnet-helper", signal.SIGCONT, network_process=True
            )
        if supervisor_stopped:
            signal_recorded_process(record, "supervisor", signal.SIGCONT)
        if maintenance.isalive():
            exit_shell(maintenance)
        if control.isalive():
            exit_shell(control)


@pytest.mark.timeout(300)
def test_full_network_lease_expires_when_owner_cli_dies(project, host_network_endpoints, request):
    """The kernel deadline revokes a lease when its renewing CLI is killed."""
    zaigr = project.zaigr_bin
    endpoint = host_network_endpoints
    host_url = f"http://10.0.2.2:{endpoint['tcp_port']}/"
    checked_run([zaigr, "project", "vm", "start"], cwd=project.cwd, env=project.env,
                input="y\n", timeout=180)
    normal = open_shell(shlex.quote(str(zaigr)) + " shell", project, request)
    full = open_shell(
        shlex.quote(str(zaigr)) + " shell --root --full-network", project, request,
        full_network=True, root=True,
    )
    normal_denied = run_in_shell(
        normal,
        f"if curl --noproxy '*' -4fsS --connect-timeout 2 --max-time 4 {host_url}; "
        "then printf 'PROBE_RESULT=ALLOWED\\n'; else printf 'PROBE_RESULT=DENIED\\n'; fi",
    )
    assert_probe_marker(normal_denied, "DENIED")
    assert endpoint["token"] not in normal_denied
    assert endpoint["token"] in run_in_shell(
        full, f"curl --noproxy '*' -4fsS --max-time 4 {host_url}"
    )
    owner_stream = project.cwd / "full-network-owner-crash-stream.log"
    run_in_shell(
        full,
        f"nohup curl --noproxy '*' -4fsSN --max-time 120 {host_url}stream "
        f"> /home/user/workspace/{owner_stream.name} 2>&1 < /dev/null &",
    )
    wait_text(owner_stream, endpoint["token"])

    # Kill the CLI process without using its orderly shell-exit cleanup path.
    full.kill(signal.SIGKILL)
    full.wait()
    time.sleep(11)
    denied = run_in_shell(
        normal,
        f"if curl --noproxy '*' -4fsS --connect-timeout 2 --max-time 4 {host_url}; "
        "then printf 'PROBE_RESULT=ALLOWED\\n'; else printf 'PROBE_RESULT=DENIED\\n'; fi",
    )
    assert_probe_marker(denied, "DENIED")
    assert endpoint["token"] not in denied
    assert "status: running" in checked_run(
        [zaigr, "project", "status"], cwd=project.cwd, env=project.env
    ).lower()
    frozen_length = len(owner_stream.read_bytes())
    time.sleep(0.5)
    assert len(owner_stream.read_bytes()) == frozen_length
    exit_shell(normal)


@pytest.mark.timeout(300)
def test_full_network_helper_failure_cuts_off_active_maintenance_stream(
    project, host_network_endpoints, request
):
    """A failed host network helper cuts off networking and may stop the VM."""
    zaigr = project.zaigr_bin
    endpoint = host_network_endpoints
    host_url = f"http://10.0.2.2:{endpoint['tcp_port']}/"
    checked_run([zaigr, "project", "vm", "start"], cwd=project.cwd, env=project.env,
                input="y\n", timeout=180)
    full = open_shell(
        shlex.quote(str(zaigr)) + " shell --root --full-network", project, request,
        full_network=True, root=True,
    )
    assert endpoint["token"] in run_in_shell(
        full, f"curl --noproxy '*' -4fsS --max-time 4 {host_url}"
    )
    helper_stream = project.cwd / "full-network-helper-freeze-stream.log"
    run_in_shell(
        full,
        f"nohup curl --noproxy '*' -4fsSN --max-time 120 {host_url}stream "
        f"> /home/user/workspace/{helper_stream.name} 2>&1 < /dev/null &",
    )
    wait_text(helper_stream, endpoint["token"])

    record = json.loads((project.store_dir / "vm-supervisor.json").read_text())
    assert "hostnet-helper" in record["network_processes"], record
    push_count_before_failure = endpoint["request_counts"]()["stream_pushes"]
    assert push_count_before_failure > 0, endpoint["request_counts"]()
    signal_recorded_process(
        record, "hostnet-helper", signal.SIGKILL, network_process=True
    )
    time.sleep(0.5)
    # Allow bytes already in flight to drain, then measure a fresh quiet
    # window while the independent host endpoint continues attempting writes.
    stream_length_after_drain = len(helper_stream.read_bytes())
    push_count_after_drain = endpoint["request_counts"]()["stream_pushes"]
    time.sleep(0.5)
    assert len(helper_stream.read_bytes()) == stream_length_after_drain
    assert endpoint["request_counts"]()["stream_pushes"] > push_count_after_drain
    status = ""
    stop_deadline = time.monotonic() + 20
    while time.monotonic() < stop_deadline:
        status = checked_run([zaigr, "project", "status"], cwd=project.cwd, env=project.env)
        if "status: not running" in status.lower():
            break
        time.sleep(0.5)
    if "status: running" in status.lower():
        denied = checked_run(
            [zaigr, "project", "vm", "exec", "--", "bash", "-c",
             (f"if curl --noproxy '*' -4fsS --connect-timeout 2 --max-time 4 {host_url}; "
              "then echo UNEXPECTED_ACCESS; else echo VM_EXEC_DENIED; fi")],
            cwd=project.cwd, env=project.env, timeout=25,
        )
        assert "VM_EXEC_DENIED" in denied and "UNEXPECTED_ACCESS" not in denied
    else:
        assert "status: not running" in status.lower(), status
    if full.isalive():
        full.close(force=True)


@pytest.mark.timeout(420)
def test_setup_and_capture_announce_leases_on_an_already_running_vm(
    project, setup_factory, host_network_endpoints, request
):
    """Setup and capture get bounded host access without a stop/start cycle."""
    zaigr = project.zaigr_bin
    endpoint = host_network_endpoints
    host_url = f"http://10.0.2.2:{endpoint['tcp_port']}/"
    setup_factory(
        "host-network-lease-probe",
        "#!/bin/bash\nset -eu\n"
        "printf 'READY\\n' > /home/user/workspace/.setup-lease-ready\n"
        f"curl --noproxy '*' -4fsS --max-time 5 {host_url} > /tmp/setup-lease-probe\n"
        "sleep 12\n",
        firewall=[],
    )
    checked_run([zaigr, "project", "vm", "start"], cwd=project.cwd, env=project.env,
                input="y\n", timeout=180)
    normal = open_shell(shlex.quote(str(zaigr)) + " shell", project, request)
    setup = spawn_interactive(
        shlex.quote(str(zaigr)) + " project setup run host-network-lease-probe",
        cwd=project.cwd,
        env=project.env,
        timeout=180,
    )
    request.addfinalizer(lambda: setup.close(force=True) if setup.isalive() else None)
    setup.expect(SETUP_LEASE_WARNING, timeout=60)
    wait_text(project.cwd / ".setup-lease-ready", "READY")
    assert_full_network_sessions(
        checked_run([zaigr, "project", "firewall", "show"], cwd=project.cwd, env=project.env),
        1, full_network=0, maintenance=1,
    )
    setup_window = run_in_shell(
        normal,
        f"if curl --noproxy '*' -4fsS --connect-timeout 2 --max-time 4 {host_url}; "
        "then printf 'PROBE_RESULT=ALLOWED\\n'; else printf 'PROBE_RESULT=DENIED\\n'; fi",
    )
    assert_probe_marker(setup_window, "DENIED")
    assert endpoint["token"] not in setup_window
    setup.expect(pexpect.EOF, timeout=180)
    setup.close()
    assert setup.exitstatus == 0
    assert checked_run(
        [zaigr, "project", "vm", "exec", "--", "cat", "/tmp/setup-lease-probe"],
        cwd=project.cwd,
        env=project.env,
    ).strip() == endpoint["token"]
    assert "status: running" in checked_run(
        [zaigr, "project", "status"], cwd=project.cwd, env=project.env
    ).lower()
    assert_full_network_sessions(
        checked_run([zaigr, "project", "firewall", "show"], cwd=project.cwd, env=project.env), 0
    )

    setup_revoked = run_in_shell(
        normal,
        f"if curl --noproxy '*' -4fsS --connect-timeout 2 --max-time 4 {host_url}; "
        "then printf 'PROBE_RESULT=ALLOWED\\n'; else printf 'PROBE_RESULT=DENIED\\n'; fi",
    )
    assert_probe_marker(setup_revoked, "DENIED")

    capture = spawn_interactive(
        shlex.quote(str(zaigr)) + " project setup capture start",
        cwd=project.cwd,
        env=project.env,
        timeout=180,
    )
    request.addfinalizer(lambda: capture.close(force=True) if capture.isalive() else None)
    try:
        capture.expect(r"A project VM is already running\.", timeout=60)
        capture.expect(r"Continue\? \[y/N\]")
        capture.sendline("y")
        capture.expect(CAPTURE_LEASE_WARNING, timeout=60)
        capture.expect(ROOT_PROMPT, timeout=180)
        capture.sendline(f"curl --noproxy '*' -4fsS --max-time 5 {host_url}")
        capture.expect(ROOT_PROMPT, timeout=30)
        assert endpoint["token"] in capture.before, capture.before
        capture_window = run_in_shell(
            normal,
            f"if curl --noproxy '*' -4fsS --connect-timeout 2 --max-time 4 {host_url}; "
            "then printf 'PROBE_RESULT=ALLOWED\\n'; else printf 'PROBE_RESULT=DENIED\\n'; fi",
        )
        assert_probe_marker(capture_window, "DENIED")
        assert endpoint["token"] not in capture_window

        review = checked_run(
            [zaigr, "project", "setup", "capture", "review"],
            cwd=project.cwd,
            env=project.env,
        )
        assert "curl" in review and str(endpoint["tcp_port"]) in review, review
        accepted = checked_run(
            [zaigr, "project", "setup", "capture", "accept"],
            cwd=project.cwd,
            env=project.env,
            timeout=180,
        )
        assert "accepted setup capture" in accepted.lower(), accepted
        capture.sendline("exit")
        capture.expect(pexpect.EOF, timeout=30)
        capture.close()
        assert capture.exitstatus == 0
    finally:
        if capture.isalive():
            capture.close(force=True)
    assert_full_network_sessions(
        checked_run([zaigr, "project", "firewall", "show"], cwd=project.cwd, env=project.env), 0
    )
    assert "status: running" in checked_run(
        [zaigr, "project", "status"], cwd=project.cwd, env=project.env
    ).lower()
    capture_revoked = run_in_shell(
        normal,
        f"if curl --noproxy '*' -4fsS --connect-timeout 2 --max-time 4 {host_url}; "
        "then printf 'PROBE_RESULT=ALLOWED\\n'; else printf 'PROBE_RESULT=DENIED\\n'; fi",
    )
    assert_probe_marker(capture_revoked, "DENIED")
    exit_shell(normal)
