"""Adversarial public workflows for persistent exact project IPv4 permissions."""

import os
import shlex
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from pathlib import Path

import pexpect
import pytest

from ..conftest import err_msg, spawn_interactive
from ..conftest import run as _run
from . import ip_access_endpoints
from .ip_access_endpoints import assert_host_services

ip_endpoints = ip_access_endpoints.ip_endpoints
ip_network = ip_access_endpoints.ip_network
zaigr_bin = ip_access_endpoints.zaigr_bin
host_endpoint = ip_access_endpoints.host_endpoint
USER_PROMPT = r"user@[^:]+:.*[$] "
ROOT_PROMPT = r"root@[^:]+:.*# "


@pytest.fixture(autouse=True)
def small_vm_resources(monkeypatch):
    """Keep independently owned test VMs within the parallel worker budget."""
    monkeypatch.setenv("ZAIGR_VM_RAM", "512")
    monkeypatch.setenv("ZAIGR_VM_CPU", "1")
    monkeypatch.setenv("ZAIGR_DISK_SIZE", "8G")


def _checked_run(cmd, **kwargs):
    """Record a visible command and return successful stdout."""
    stdout, stderr, rc = _run(cmd, **kwargs)
    assert rc == 0, err_msg(stdout, stderr)
    return stdout


def _assert_blocked(stdout, stderr, rc):
    """Require a real curl connection denial rather than a guest-command error."""
    assert rc in (7, 28), err_msg(stdout, stderr)
    assert "ip-endpoint-" not in stdout
    assert "connect" in stderr.lower() or "timed out" in stderr.lower(), stderr


def _assert_stream_stops(stream):
    """Allow ten seconds for revocation, then require two seconds of silence."""
    grace_deadline = time.monotonic() + 10
    while time.monotonic() < grace_deadline:
        try:
            stream.read_nonblocking(
                size=4096, timeout=min(1, grace_deadline - time.monotonic())
            )
        except pexpect.EOF:
            return
        except pexpect.TIMEOUT:
            continue

    quiet_deadline = time.monotonic() + 2
    while time.monotonic() < quiet_deadline:
        try:
            stream.read_nonblocking(
                size=4096, timeout=min(1, quiet_deadline - time.monotonic())
            )
        except pexpect.EOF:
            return
        except pexpect.TIMEOUT:
            continue
        pytest.fail("Revoked established connection delivered traffic after its grace period")


def _assert_file_stops(path):
    """Require a detached guest stream capture to stay unchanged for ten seconds."""
    size = path.stat().st_size
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        time.sleep(min(1, deadline - time.monotonic()))
        current_size = path.stat().st_size
        assert current_size == size, f"Revoked established traffic extended {path}"


@pytest.fixture()
def udp_client(project):
    """Build a real UDP client that can reuse one exact local socket tuple."""
    source = project.cwd / "ip-chaos-udp.c"
    source.write_text(r'''
#include <arpa/inet.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in local = { .sin_family = AF_INET,
        .sin_port = htons(40123), .sin_addr.s_addr = INADDR_ANY };
    struct sockaddr_in peer = { .sin_family = AF_INET,
        .sin_port = htons(atoi(argv[2])) };
    if (fd < 0 || inet_pton(AF_INET, argv[1], &peer.sin_addr) != 1 ||
        bind(fd, (struct sockaddr *)&local, sizeof(local)) ||
        connect(fd, (struct sockaddr *)&peer, sizeof(peer))) {
        perror("UDP socket setup"); return 3;
    }
    setbuf(stdout, NULL);
    puts("UDP_BOUND_40123");
    char request[256], reply[1024];
    while (fgets(request, sizeof(request), stdin)) {
        size_t length = 0;
        while (request[length]) ++length;
        if (send(fd, request, length, 0) < 0) {
            perror("UDP send"); return 4;
        }
        struct pollfd pending = { .fd = fd, .events = POLLIN };
        int ready = poll(&pending, 1, 2000);
        if (!ready) { puts("UDP_TIMEOUT"); continue; }
        ssize_t size = recv(fd, reply, sizeof(reply), 0);
        if (size < 0) { perror("UDP receive"); return 5; }
        fwrite(reply, 1, size, stdout);
    }
    close(fd);
    return 0;
}
''', encoding="utf-8")
    _checked_run(["gcc", "-static", "-Wall", "-Wextra", "-Werror", "-O2",
                  "-o", project.cwd / "ip-chaos-udp", source], timeout=30)
    return "/home/user/workspace/ip-chaos-udp"


@pytest.fixture()
def tcp_source_port_22_client(project):
    """Build a real HTTP client that binds guest source port 22."""
    source = project.cwd / "ip-chaos-tcp22.c"
    source.write_text(r'''
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int reuse = 1;
    struct sockaddr_in local = { .sin_family = AF_INET,
        .sin_port = htons(22) };
    struct sockaddr_in peer = { .sin_family = AF_INET,
        .sin_port = htons(atoi(argv[2])) };
    if (fd < 0 || setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) ||
        inet_pton(AF_INET, "10.0.2.15", &local.sin_addr) != 1 ||
        inet_pton(AF_INET, argv[1], &peer.sin_addr) != 1 ||
        bind(fd, (struct sockaddr *)&local, sizeof(local)) ||
        connect(fd, (struct sockaddr *)&peer, sizeof(peer))) {
        perror("TCP source-port-22 setup"); return 3;
    }
    socklen_t local_size = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &local_size)) {
        perror("getsockname"); return 4;
    }
    printf("SOURCE_PORT=%u\n", ntohs(local.sin_port));
    fflush(stdout);
    char request[256];
    int length = snprintf(request, sizeof(request),
        "GET /stream HTTP/1.0\r\nHost: %s\r\n\r\n", argv[1]);
    if (write(fd, request, length) != length) { perror("HTTP request"); return 5; }
    char buffer[4096];
    ssize_t count;
    while ((count = read(fd, buffer, sizeof(buffer))) > 0) {
        if (write(STDOUT_FILENO, buffer, count) != count) return 6;
    }
    if (count < 0) { perror("HTTP response"); return 7; }
    close(fd);
    return 0;
}
''', encoding="utf-8")
    _checked_run(["gcc", "-static", "-Wall", "-Wextra", "-Werror", "-O2",
                  "-o", project.cwd / "ip-chaos-tcp22", source], timeout=30)
    return "/home/user/workspace/ip-chaos-tcp22"


@pytest.mark.timeout(360)
def test_udp_reused_source_tuple_cannot_inherit_revoked_access(
    project, ip_endpoints, udp_client
):
    """A newly bound UDP socket cannot reuse a revoked conntrack permission."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    endpoint = ip_endpoints["first"]
    run(f"{zaigr} project vm start", input="y\n", timeout=180)
    run(f"{zaigr} project firewall allow {endpoint['ip']}")
    command = f"{zaigr} project vm exec -- {udp_client} {endpoint['ip']} 18082"
    session = spawn_interactive(command, cwd=project.cwd, env=project.env)
    try:
        session.expect_exact("UDP_BOUND_40123", timeout=10)
        nonce = uuid.uuid4().hex
        session.sendline(nonce)
        session.expect_exact(endpoint["token"] + ":" + nonce, timeout=5)
        run(f"{zaigr} project firewall remove {endpoint['ip']}")
        nonce = uuid.uuid4().hex
        session.sendline(nonce)
        assert session.expect_exact(
            [endpoint["token"] + ":" + nonce, pexpect.EOF, "UDP_TIMEOUT"], timeout=5,
        ) != 0
    finally:
        if session.isalive():
            session.close(force=True)
    assert_host_services(endpoint, ip_endpoints["key"])
    # This is a fresh socket with the same source port and destination tuple.
    stdout, stderr, rc = _run(
        command, cwd=project.cwd, env=project.env, input=uuid.uuid4().hex + "\n",
        timeout=10,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert "UDP_BOUND_40123" in stdout and "UDP_TIMEOUT" in stdout, stdout
    assert endpoint["token"] not in stdout
    run(f"{zaigr} project firewall allow {endpoint['ip']}")
    nonce = uuid.uuid4().hex
    output = run(command, input=nonce + "\n", timeout=10)
    assert endpoint["token"] + ":" + nonce in output


@pytest.mark.parametrize("destination", ["endpoint", "host-alias"])
@pytest.mark.parametrize("process_name", ["sshd-prefix", "forged-pid"])
@pytest.mark.timeout(360)
def test_outbound_source_port_22_named_sshd_is_revoked(
    project, ip_endpoints, host_endpoint, tcp_source_port_22_client,
    destination, process_name
):
    """An ordinary process named sshd cannot inherit the inbound control exemption."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    endpoint = ip_endpoints["first"]
    address, port, token = (
        (endpoint["ip"], 18080, endpoint["token"]) if destination == "endpoint"
        else ("10.0.2.2", host_endpoint["port"], host_endpoint["token"])
    )
    run(f"{zaigr} project vm start", input="y\n", timeout=180)
    run(f"{zaigr} project firewall allow {address}")
    # Use the VM's actual assigned source address. A spoofed .16 source is
    # rejected by the host tap before reaching this policy, so it cannot be a
    # positive control for the granted destination.
    previous = run(f"{zaigr} project vm exec -- cat /proc/sys/net/ipv4/ip_unprivileged_port_start").strip()
    sshd_pid = run(f"{zaigr} project vm exec -- pgrep -o -x sshd").strip()
    assert sshd_pid.isdecimal(), sshd_pid
    run(f"{zaigr} project vm exec --root -- sysctl -w net.ipv4.ip_unprivileged_port_start=0", input="y\n")
    if process_name == "sshd-prefix":
        executable = "/tmp/sshd-chaos"
    else:
        executable = f"/tmp/pid={sshd_pid}"
    run(f"{zaigr} project vm exec -- cp {tcp_source_port_22_client} {executable}")
    output_path = project.cwd / f"source-port-22-{uuid.uuid4().hex}.log"
    ready_path = project.cwd / f"source-port-22-{uuid.uuid4().hex}.ready"
    sshd_log_path = project.cwd / f"source-port-22-{uuid.uuid4().hex}-sshd.log"
    guest_output_path = f"/home/user/workspace/{output_path.name}"
    guest_ready_path = f"/home/user/workspace/{ready_path.name}"
    guest_ready_tmp_path = guest_ready_path + ".tmp"
    guest_sshd_log_path = f"/home/user/workspace/{sshd_log_path.name}"
    run(f"{zaigr} project vm exec -- rm -f {guest_output_path}")
    runner_path = f"/home/user/workspace/source-port-22-{uuid.uuid4().hex}.sh"
    runner = (
        "#!/bin/sh\n"
        "sleep 3\n"
        "pkill -x sshd || true\n"
        "sleep 1\n"
        f"timeout 30 su -s /bin/sh user -c {shlex.quote(f'{executable} {address} {port}')} "
        f"> {shlex.quote(guest_output_path)} 2>&1\n"
        "mkdir -p /run/sshd\n"
        f"/usr/sbin/sshd -D -e > {shlex.quote(guest_sshd_log_path)} 2>&1 </dev/null &\n"
        "sshd_pid=$!\n"
        "sleep 1\n"
        f"if kill -0 \"$sshd_pid\"; then echo ready > {shlex.quote(guest_ready_tmp_path)}; "
        f"else echo failed > {shlex.quote(guest_ready_tmp_path)}; fi\n"
        f"mv {shlex.quote(guest_ready_tmp_path)} {shlex.quote(guest_ready_path)}\n"
    )
    run(f"{zaigr} project vm exec --root -- tee {runner_path}", input="y\n" + runner)
    run(f"{zaigr} project vm exec --root -- rm -f {guest_ready_path} {guest_ready_tmp_path}", input="y\n")
    # A detached root coordinator closes every authenticated SSH channel before
    # an ordinary-UID fake sshd binds local source port 22. It later restores
    # sshd so public VM commands can verify the management path is usable.
    coordinator_started = time.monotonic()
    run(
        f"{zaigr} project vm exec --root -- sh -c "
        + shlex.quote(f"nohup sh {runner_path} </dev/null >/dev/null 2>&1 &"),
        input="y\n",
    )
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if output_path.exists() and "{0}:2".format(token) in output_path.read_text(errors="replace"):
            break
        time.sleep(0.2)
    else:
        pytest.fail(f"Source-port client did not establish its real stream: {output_path.read_text(errors='replace') if output_path.exists() else 'no output file'}")
    output = output_path.read_text(errors="replace")
    assert "SOURCE_PORT=22" in output, output
    assert token + ":2" in output, output
    run(f"{zaigr} project firewall remove {address}")
    # Revoke while the detached ordinary process streams to a shared workspace
    # file; the host can observe actual delivered body bytes after its SSH
    # channel has closed, without interpreting an expect buffer as a cutoff.
    _assert_file_stops(output_path)
    silence_observed_at = time.monotonic()
    assert silence_observed_at - coordinator_started < 28, (
        "The ten-second quiet window ended too close to the client's 30-second "
        "timeout, so natural client exit could explain the unchanged capture"
    )
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        if ready_path.exists() and ready_path.read_text(errors="replace").strip():
            break
        time.sleep(0.2)
    assert ready_path.exists() and ready_path.read_text(errors="replace").strip(), (
        "guest runner did not report SSH management service startup"
    )
    assert ready_path.read_text().strip() == "ready", sshd_log_path.read_text(errors="replace")
    assert run(f"{zaigr} project vm exec -- printf CONTROL_EXEC") == "CONTROL_EXEC"
    assert_host_services(endpoint, ip_endpoints["key"])
    _assert_blocked(*_run(
        f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS "
        f"--connect-timeout 2 --max-time 4 http://{address}:{port}/",
        cwd=project.cwd, env=project.env, timeout=15,
    ))
    run(f"{zaigr} project vm exec --root -- sysctl -w net.ipv4.ip_unprivileged_port_start={previous}", input="y\n")


@pytest.mark.timeout(240)
def test_partial_live_policy_withdrawal_survives_conntrack_failure(
    project, ip_endpoints, test_root
):
    """The nft grant is withdrawn even when host conntrack cleanup fails."""
    endpoint = ip_endpoints["first"]
    fail_marker = test_root / "conntrack-failure-enabled"
    fault_log = Path(str(fail_marker) + ".log")
    env = project.env
    env["ZAIGR_TEST_CONNTRACK_DELETE_FAILURE"] = str(fail_marker)
    run = partial(_checked_run, cwd=project.cwd, env=env)
    zaigr = project.zaigr_bin
    run(f"{zaigr} project vm start", input="y\n", timeout=180)
    run(f"{zaigr} project firewall allow {endpoint['ip']}")
    output = run(
        f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS "
        f"--connect-timeout 3 --max-time 6 http://{endpoint['ip']}:18080/"
    )
    assert output.strip() == endpoint["token"] + ":0"
    stream = spawn_interactive(
        f"{zaigr} project vm exec -- curl --noproxy '*' -4fsSN --max-time 120 "
        f"http://{endpoint['ip']}:18080/stream",
        cwd=project.cwd, env=env,
    )
    stream.expect_exact(endpoint["token"] + ":2", timeout=10)
    assert not fault_log.exists(), "conntrack fault fired before the failure was armed"
    fail_marker.write_text(endpoint["ip"] + "\n", encoding="ascii")
    try:
        stdout, stderr, rc = _run(
            f"{zaigr} project firewall remove {endpoint['ip']}",
            cwd=project.cwd, env=env, timeout=30,
        )
        diagnostic = stdout + stderr
        assert rc != 0, diagnostic
        assert "saved" in diagnostic and "could not be applied" in diagnostic, diagnostic
        # The daemon's periodic policy reconciliation can hit the injected
        # conntrack fault before this CLI request reaches the host helper. Keep
        # durable evidence of the actual failing boundary, while requiring the
        # public operation to report that its saved policy was not applied.
        fault_events = fault_log.read_text()
        assert "injected-host-conntrack-failure" in fault_events, fault_events
        assert f"deletion for {endpoint['ip']} attempted and failed" in fault_events, fault_events
        assert (
            "injected-host-conntrack-failure" in diagnostic
            or "host-network-control.sock" in diagnostic
        ), diagnostic
        shown, show_error, show_rc = _run(
            f"{zaigr} project firewall show",
            cwd=project.cwd, env=env, timeout=20,
        )
        assert show_rc == 0, err_msg(shown, show_error)
        assert "pending or unconfirmed" in shown
        _assert_stream_stops(stream)
        fail_marker.unlink()
        stop_stdout, stop_stderr, stop_rc = _run(
            f"{zaigr} project vm stop", cwd=project.cwd, env=env, timeout=60,
        )
        if stop_rc != 0:
            if "project VM is not running" not in stop_stderr:
                assert "project vm stop --abrupt" in stop_stderr, stop_stderr
                abrupt_stdout, abrupt_stderr, abrupt_rc = _run(
                    f"{zaigr} project vm stop --abrupt",
                    cwd=project.cwd, env=env, timeout=60,
                )
                assert abrupt_rc == 0 or "project VM is not running" in abrupt_stderr, (
                    abrupt_stdout, abrupt_stderr,
                )
        deadline = time.monotonic() + 10
        status = ""
        while time.monotonic() < deadline:
            status = run(f"{zaigr} project status")
            if "status: not running" in status.lower():
                break
            time.sleep(0.5)
        assert "status: not running" in status.lower(), status
        run(f"{zaigr} project vm start", timeout=180)
        _assert_blocked(*_run(
            f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS "
            f"--connect-timeout 2 --max-time 4 http://{endpoint['ip']}:18080/",
            cwd=project.cwd, env=env, timeout=15,
        ))
        run(f"{zaigr} project firewall allow {endpoint['ip']}")
        allowed = run(
            f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS "
            f"--connect-timeout 3 --max-time 6 http://{endpoint['ip']}:18080/"
        )
        assert allowed.strip() == endpoint["token"] + ":0"
        run(f"{zaigr} project firewall remove {endpoint['ip']}")
        _assert_blocked(*_run(
            f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS "
            f"--connect-timeout 2 --max-time 4 http://{endpoint['ip']}:18080/",
            cwd=project.cwd, env=env, timeout=15,
        ))
    finally:
        fail_marker.unlink(missing_ok=True)
        if stream.isalive():
            stream.close(force=True)


@pytest.mark.timeout(180)
def test_global_firewall_enumeration_failure_is_recoverable(project):
    """A real project-store permission failure is visible and can be reconciled."""
    if os.geteuid() == 0:
        pytest.fail("permission-boundary test requires the normal unprivileged test uid")
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    run(f"{zaigr} project vm start", input="y\n", timeout=180)
    store_root = project.home / ".zaigr" / "store"
    store_root.mkdir(parents=True, exist_ok=True)
    original_mode = store_root.stat().st_mode & 0o777
    store_root.chmod(0)
    try:
        stdout, stderr, rc = _run(
            f"{zaigr} global firewall allow enumeration-recovery.example",
            cwd=project.cwd, env=project.env, timeout=20,
        )
        diagnostic = stdout + stderr
        assert rc != 0, diagnostic
        assert "global firewall saved" in diagnostic
        assert "project stores could not be enumerated" in diagnostic
        assert "permission denied" in diagnostic.lower()
    finally:
        store_root.chmod(original_mode)
    assert "enumeration-recovery.example" in run(f"{zaigr} global firewall list")
    effective = run(f"{zaigr} project firewall show")
    assert "enumeration-recovery.example" in effective, effective
    assert "enumeration-recovery.example" in run(
        f"{zaigr} global firewall allow enumeration-recovery.example"
    )
    assert run(f"{zaigr} project vm exec -- printf LIVE_POLICY_RECONCILED") == "LIVE_POLICY_RECONCILED"
    removed = run(
        f"{zaigr} global firewall remove enumeration-recovery.example"
    )
    assert "removed enumeration-recovery.example" in removed
    assert "enumeration-recovery.example" not in run(f"{zaigr} project firewall show")
    assert run(f"{zaigr} project vm exec -- printf LIVE_POLICY_REMOVED") == "LIVE_POLICY_REMOVED"


@pytest.mark.timeout(360)
def test_running_corrupt_policy_refuses_new_entry_without_broadening_live_shell(
    project, ip_endpoints
):
    """Malformed policy fails closed, and the saved valid policy recovers on boot."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    first, second = ip_endpoints["first"], ip_endpoints["second"]
    run(f"{zaigr} project vm start", input="y\n", timeout=180)
    run(f"{zaigr} project firewall allow {second['ip']}")
    policy = project.store_dir / "firewall-ips"
    original = policy.read_bytes()
    shell = spawn_interactive(f"{zaigr} shell", cwd=project.cwd, env=project.env)
    stream = None
    try:
        shell.expect(USER_PROMPT, timeout=20)
        stream = spawn_interactive(
            f"{zaigr} project vm exec -- curl --noproxy '*' -4fsSN --max-time 120 "
            f"http://{second['ip']}:18080/stream",
            cwd=project.cwd, env=project.env,
        )
        stream.expect_exact(second["token"] + ":2", timeout=10)
        # A truncated administrator edit adds a valid new IP before invalid data.
        damaged = f"{first['ip']}\n192.0.2.0/24\n".encode()
        policy.write_bytes(damaged)
        stdout, stderr, rc = _run(
            f"{zaigr} project firewall allow {first['ip']}",
            cwd=project.cwd, env=project.env, timeout=30,
        )
        diagnostic = stdout + stderr
        assert rc != 0, diagnostic
        assert "firewall" in diagnostic.lower(), diagnostic
        assert policy.read_bytes() == damaged
        _assert_stream_stops(stream)
        with pytest.raises(pexpect.EOF):
            shell.expect(USER_PROMPT, timeout=20)
    finally:
        policy.write_bytes(original)
        if stream is not None and stream.isalive():
            stream.close(force=True)
        if shell.isalive():
            shell.close(force=True)
    deadline = time.monotonic() + 10
    status = ""
    while time.monotonic() < deadline:
        status = run(f"{zaigr} project status")
        if "status: not running" in status.lower():
            break
        time.sleep(0.5)
    assert "status: not running" in status.lower(), status
    run(f"{zaigr} project vm start", timeout=180)
    assert run(
        f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS "
        f"--max-time 4 http://{second['ip']}:18080/"
    ).strip() == second["token"] + ":0"
    _assert_blocked(*_run(
        f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS "
        f"--connect-timeout 2 --max-time 4 http://{first['ip']}:18080/",
        cwd=project.cwd, env=project.env, timeout=15,
    ))
    run(f"{zaigr} project firewall allow {first['ip']}")
    assert run(
        f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS "
        f"--max-time 4 http://{first['ip']}:18080/"
    ).strip() == first["token"] + ":0"


@pytest.mark.timeout(480)
def test_live_mutations_and_vm_reuse_never_restore_removed_permissions(project, ip_endpoints):
    """Concurrent reuse and independent changes agree with final real traffic."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    first, second = ip_endpoints["first"], ip_endpoints["second"]
    run(f"{zaigr} project vm start", input="y\n", timeout=180)
    boot = run(f"{zaigr} project vm exec -- cat /proc/sys/kernel/random/boot_id")
    for turn in range(3):
        run(f"{zaigr} project firewall allow {first['ip']}")
        run(f"{zaigr} project firewall remove {second['ip']}")
        commands = [
            f"{zaigr} project firewall remove {first['ip']}",
            f"{zaigr} project firewall allow {second['ip']}",
            f"{zaigr} project vm start",
            f"{zaigr} project vm exec -- printf RACE_{turn}",
            f"{zaigr} project vm exec -- cat /proc/sys/kernel/random/boot_id",
        ]
        with ThreadPoolExecutor(max_workers=len(commands)) as pool:
            futures = [pool.submit(
                _run, command, cwd=project.cwd, env=project.env, timeout=40,
            ) for command in commands]
            results = [future.result() for future in futures]
        for stdout, stderr, rc in results:
            if rc:
                assert "busy" in stdout + stderr or "another terminal" in stdout + stderr, err_msg(stdout, stderr)
        expected = {first["ip"]: results[0][2] != 0, second["ip"]: results[1][2] == 0}
        assert any(rc == 0 for _, _, rc in results), results
        shown = run(f"{zaigr} project firewall show")
        for endpoint in (first, second):
            assert (endpoint["ip"] in shown) == expected[endpoint["ip"]], shown
            assert_host_services(endpoint, ip_endpoints["key"])
            result = _run(
                f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS "
                f"--connect-timeout 2 --max-time 4 http://{endpoint['ip']}:18080/",
                cwd=project.cwd, env=project.env, timeout=15,
            )
            if expected[endpoint["ip"]]:
                assert result[2] == 0 and result[0].strip() == endpoint["token"] + ":0", result
            else:
                _assert_blocked(*result)
        assert run(f"{zaigr} project vm exec -- cat /proc/sys/kernel/random/boot_id") == boot


@pytest.mark.timeout(420)
def test_stop_race_preserves_every_successful_policy_change(project, ip_endpoints):
    """A stop racing policy changes either serializes them or refuses visibly."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    first, second = ip_endpoints["first"], ip_endpoints["second"]
    run(f"{zaigr} project vm start", input="y\n", timeout=180)
    run(f"{zaigr} project firewall allow {first['ip']}")
    commands = [
        f"{zaigr} project firewall remove {first['ip']}",
        f"{zaigr} project firewall allow {second['ip']}",
        f"{zaigr} project vm stop",
    ]
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(
            _run, command, cwd=project.cwd, env=project.env, timeout=60,
        ) for command in commands]
        results = [future.result() for future in futures]
    for stdout, stderr, rc in results:
        if rc:
            assert "busy" in stdout + stderr or "another terminal" in stdout + stderr, err_msg(stdout, stderr)
    expected = {first["ip"]: results[0][2] != 0, second["ip"]: results[1][2] == 0}
    # A refused stop is retried before the next start, exercising stopped sync.
    if results[2][2]:
        run(f"{zaigr} project vm stop", timeout=60)
    assert "status: not running" in run(f"{zaigr} project status")
    run(f"{zaigr} project vm start", timeout=180)
    shown = run(f"{zaigr} project firewall show")
    for endpoint in (first, second):
        assert (endpoint["ip"] in shown) == expected[endpoint["ip"]], shown
        assert_host_services(endpoint, ip_endpoints["key"])
        result = _run(
            f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS "
            f"--connect-timeout 2 --max-time 4 http://{endpoint['ip']}:18080/",
            cwd=project.cwd, env=project.env, timeout=15,
        )
        if expected[endpoint["ip"]]:
            assert result[2] == 0 and result[0].strip() == endpoint["token"] + ":0", result
        else:
            _assert_blocked(*result)


@pytest.mark.timeout(480)
def test_rebuild_conflicts_refuse_mutations_without_losing_grants(
    project, setup_factory, ip_endpoints
):
    """An active image replacement refuses conflicting policy and lifecycle commands."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    first, second = ip_endpoints["first"], ip_endpoints["second"]
    setup_factory("ip-rebuild-gate", "printf 'IP_REBUILD_GATE_READY\\n'\nsleep 15")
    run(f"{zaigr} project setup run ip-rebuild-gate", input="y\n", timeout=180)
    run(f"{zaigr} project firewall allow {first['ip']}")
    run(f"{zaigr} project vm stop", timeout=60)
    rebuild = spawn_interactive(
        f"{zaigr} project rebuild", cwd=project.cwd, env=project.env, timeout=180,
    )
    try:
        rebuild.expect_exact("IP_REBUILD_GATE_READY", timeout=120)
        for command in (
            f"{zaigr} project firewall allow {second['ip']}",
            f"{zaigr} project firewall remove {first['ip']}",
            f"{zaigr} project vm start",
            f"{zaigr} project vm stop",
        ):
            stdout, stderr, rc = _run(command, cwd=project.cwd, env=project.env, timeout=10)
            assert rc != 0, err_msg(stdout, stderr)
            assert "busy" in stdout + stderr or "another terminal" in stdout + stderr, err_msg(stdout, stderr)
            assert "rebuild" in stdout + stderr, err_msg(stdout, stderr)
        rebuild.expect(pexpect.EOF, timeout=120)
        rebuild.close()
        assert rebuild.exitstatus == 0, rebuild.before
    finally:
        if rebuild.isalive():
            rebuild.close(force=True)
    run(f"{zaigr} project vm start", timeout=180)
    shown = run(f"{zaigr} project firewall show")
    assert first["ip"] in shown and second["ip"] not in shown, shown
    assert_host_services(first, ip_endpoints["key"])
    assert run(
        f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS "
        f"--max-time 4 http://{first['ip']}:18080/"
    ).strip() == first["token"] + ":0"
    assert_host_services(second, ip_endpoints["key"])
    _assert_blocked(*_run(
        f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS "
        f"--connect-timeout 2 --max-time 4 http://{second['ip']}:18080/",
        cwd=project.cwd, env=project.env, timeout=15,
    ))


@pytest.mark.parametrize("operation", ["clean", "rebuild"])
@pytest.mark.timeout(600)
def test_legacy_replacement_failure_and_retry_preserve_explicit_grants(
    project, setup_factory, ip_endpoints, operation
):
    """Standalone legacy stores retain IP configuration through failed replacement."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    first, second = ip_endpoints["first"], ip_endpoints["second"]
    store = project.store_dir
    store.mkdir(parents=True)
    # Reproduce the recoverable standalone-image/committed-script legacy layout.
    (store / "project-path").write_text(str(project.cwd) + "\n", encoding="utf-8")
    (store / "config").write_text("disk=8G\n", encoding="utf-8")
    (store / "base-image-version").write_text("legacy-base\n", encoding="utf-8")
    (store / "committed").mkdir()
    (store / "committed/001-legacy-ip.sh").write_text("printf 'old setup\\n'\n", encoding="utf-8")
    policy = store / "firewall-ips"
    policy.write_text(first["ip"] + "\n", encoding="utf-8")
    state = store / "agent-state/legacy-client"
    state.mkdir(parents=True)
    (state / "session").write_text("legacy-session\n", encoding="utf-8")
    legacy_image = store / "image-legacy.qcow2"
    run(["qemu-img", "create", "-f", "qcow2", legacy_image, "1G"], timeout=30)
    original_image = legacy_image.read_bytes()
    setup_factory("legacy-ip", "printf 'REPLACEMENT_FAILURE\\n'\nexit 17")
    if operation == "clean":
        # Clean cannot discard this unreadable subtree. Restore its mode even
        # after an assertion failure so fixture cleanup remains fully usable.
        state.chmod(0o500)
    try:
        stdout, stderr, rc = _run(
            [zaigr, "project", operation], cwd=project.cwd, env=project.env, timeout=240,
        )
        assert rc != 0, err_msg(stdout, stderr)
        if operation == "rebuild":
            assert "REPLACEMENT_FAILURE" in stdout, err_msg(stdout, stderr)
        else:
            assert "cannot be safely discarded" in stdout + stderr, err_msg(stdout, stderr)
        assert policy.read_text(encoding="utf-8") == first["ip"] + "\n"
        assert legacy_image.read_bytes() == original_image
        assert (state / "session").read_text(encoding="utf-8") == "legacy-session\n"
    finally:
        state.chmod(0o755)
    setup_factory("legacy-ip", "printf 'rebuilt-with-ip\\n' > /etc/legacy-ip")
    run([zaigr, "project", operation], timeout=240)
    assert policy.read_text(encoding="utf-8") == first["ip"] + "\n"
    assert not legacy_image.exists()
    run(f"{zaigr} project vm start", timeout=180)
    if operation == "rebuild":
        assert run(f"{zaigr} project vm exec -- cat /etc/legacy-ip") == "rebuilt-with-ip\n"
        assert run(
            f"{zaigr} project vm exec -- cat /home/user/.zaigr-agent-state/legacy-client/session"
        ) == "legacy-session\n"
    assert_host_services(first, ip_endpoints["key"])
    assert run(
        f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS "
        f"--max-time 4 http://{first['ip']}:18080/"
    ).strip() == first["token"] + ":0"
    assert_host_services(second, ip_endpoints["key"])
    _assert_blocked(*_run(
        f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS "
        f"--connect-timeout 2 --max-time 4 http://{second['ip']}:18080/",
        cwd=project.cwd, env=project.env, timeout=15,
    ))


@pytest.mark.timeout(720)
def test_global_base_changes_never_export_or_drop_project_grants(
    project_factory, setup_factory, ip_endpoints, tmp_path
):
    """Custom-base publication, adoption, and reset keep grants owned by the project."""
    owner = project_factory("base-ip-owner")
    consumer = project_factory("base-ip-consumer")
    zaigr = owner.zaigr_bin
    run = partial(_checked_run, env=owner.env)
    endpoint = ip_endpoints["first"]
    run(f"{zaigr} project vm start", cwd=owner.cwd, input="y\n", timeout=180)
    run(f"{zaigr} project firewall allow {endpoint['ip']}", cwd=owner.cwd)
    run(f"{zaigr} project vm stop", cwd=owner.cwd, timeout=60)
    setup_factory("base-without-ip", "printf 'custom-base\\n' > /etc/ip-chaos-base")
    run(f"{zaigr} global base-image setup run base-without-ip", cwd=tmp_path, timeout=240)
    run(f"{zaigr} project clean", cwd=owner.cwd, timeout=180)
    run(f"{zaigr} project vm start", cwd=owner.cwd, timeout=180)
    assert run(f"{zaigr} project vm exec -- cat /etc/ip-chaos-base", cwd=owner.cwd) == "custom-base\n"
    assert run(
        f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS "
        f"--max-time 4 http://{endpoint['ip']}:18080/", cwd=owner.cwd,
    ).strip() == endpoint["token"] + ":0"
    run(f"{zaigr} project vm start", cwd=consumer.cwd, input="y\n", timeout=180)
    assert run(f"{zaigr} project vm exec -- cat /etc/ip-chaos-base", cwd=consumer.cwd) == "custom-base\n"
    assert_host_services(endpoint, ip_endpoints["key"])
    _assert_blocked(*_run(
        f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS "
        f"--connect-timeout 2 --max-time 4 http://{endpoint['ip']}:18080/",
        cwd=consumer.cwd, env=consumer.env, timeout=15,
    ))
    run(f"{zaigr} project vm stop", cwd=owner.cwd, timeout=60)
    run(f"{zaigr} global base-image reset", cwd=tmp_path, timeout=30)
    run(f"{zaigr} project clean", cwd=owner.cwd, timeout=180)
    run(f"{zaigr} project vm start", cwd=owner.cwd, timeout=180)
    run(f"{zaigr} project vm exec -- test ! -e /etc/ip-chaos-base", cwd=owner.cwd)
    assert run(
        f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS "
        f"--max-time 4 http://{endpoint['ip']}:18080/", cwd=owner.cwd,
    ).strip() == endpoint["token"] + ":0"
    assert endpoint["ip"] in run(f"{zaigr} project firewall show", cwd=owner.cwd)
    assert endpoint["ip"] not in run(f"{zaigr} project firewall show", cwd=consumer.cwd)
