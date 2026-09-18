"""Adversarial public workflows for persistent exact project IPv4 permissions."""

import shlex
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from functools import partial

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
    """Require revoked established traffic to become quiet within ten seconds."""
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            stream.read_nonblocking(size=4096, timeout=2)
        except (pexpect.EOF, pexpect.TIMEOUT):
            return
    pytest.fail("Revoked established connection still delivered traffic after ten seconds")


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
    project, ip_endpoints, host_endpoint, destination, process_name
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
    # A guest-only second address avoids the actual inbound listener's port.
    # All changes belong to this disposable VM and are restored before teardown.
    run(f"{zaigr} project vm exec -- tee /tmp/ip-chaos-sshd.conf",
        input="ListenAddress 10.0.2.15\n")
    run(f"{zaigr} project vm exec --root -- cp /tmp/ip-chaos-sshd.conf /etc/ssh/sshd_config.d/ip-chaos.conf", input="y\n")
    run(f"{zaigr} project vm exec --root -- systemctl restart ssh", input="y\n")
    run(f"{zaigr} project vm exec --root -- ip address add 10.0.2.16/24 dev eth0", input="y\n")
    previous = run(f"{zaigr} project vm exec -- cat /proc/sys/net/ipv4/ip_unprivileged_port_start").strip()
    run(f"{zaigr} project vm exec --root -- sysctl -w net.ipv4.ip_unprivileged_port_start=0", input="y\n")
    if process_name == "sshd-prefix":
        executable = "/tmp/sshd-chaos"
    else:
        # This is public guest process information, not product runtime metadata.
        # A comm containing pid= can resemble an owner field in ss text output.
        sshd_pid = run(f"{zaigr} project vm exec -- pgrep -o -x sshd").strip()
        assert sshd_pid.isdecimal(), sshd_pid
        executable = f"/tmp/pid={sshd_pid}"
    run(f"{zaigr} project vm exec -- cp /usr/bin/curl {executable}")
    shell = spawn_interactive(f"{zaigr} shell", cwd=project.cwd, env=project.env)
    shell.expect(USER_PROMPT, timeout=20)
    stream = spawn_interactive(
        f"{zaigr} project vm exec -- {executable} --noproxy '*' -4fsSN "
        "--interface 10.0.2.16 --local-port 22 --max-time 90 "
        f"http://{address}:{port}/stream",
        cwd=project.cwd, env=project.env,
    )
    try:
        stream.expect_exact(token + ":2", timeout=15)
        run(f"{zaigr} project firewall remove {address}")
        _assert_stream_stops(stream)
        shell.sendline("printf '\\nCONTROL_SURVIVED\\n'")
        shell.expect_exact("\r\nCONTROL_SURVIVED\r\n")
        shell.expect(USER_PROMPT)
        assert run(f"{zaigr} project vm exec -- printf CONTROL_EXEC") == "CONTROL_EXEC"
        assert_host_services(endpoint, ip_endpoints["key"])
        _assert_blocked(*_run(
            f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS "
            f"--connect-timeout 2 --max-time 4 http://{address}:{port}/",
            cwd=project.cwd, env=project.env, timeout=15,
        ))
    finally:
        for process in (stream, shell):
            if process.isalive():
                process.close(force=True)
        run(f"{zaigr} project vm exec --root -- sysctl -w net.ipv4.ip_unprivileged_port_start={previous}", input="y\n")
        run(f"{zaigr} project vm exec --root -- rm /etc/ssh/sshd_config.d/ip-chaos.conf", input="y\n")
        run(f"{zaigr} project vm exec --root -- systemctl restart ssh", input="y\n")
        run(f"{zaigr} project vm exec --root -- ip address del 10.0.2.16/24 dev eth0", input="y\n")


@pytest.mark.parametrize("recovery", ["remove-retry", "vm-reuse"])
@pytest.mark.timeout(480)
def test_partial_live_changes_retain_every_pending_revocation(
    project, ip_endpoints, host_endpoint, recovery
):
    """Repeated partial mutations recover all changed destinations and preserve control."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    first, second = ip_endpoints["first"], ip_endpoints["second"]
    run(f"{zaigr} project vm start", input="y\n", timeout=180)
    run(f"{zaigr} project firewall allow {first['ip']}")
    run(f"{zaigr} project firewall allow 10.0.2.2")
    root = spawn_interactive(f"{zaigr} shell --root", cwd=project.cwd, env=project.env)
    root.expect(r"\[y/N\]")
    root.sendline("y")
    root.expect(ROOT_PROMPT, timeout=30)
    shell = spawn_interactive(f"{zaigr} shell", cwd=project.cwd, env=project.env)
    streams = []
    udp_sessions = []
    fault_active = False
    try:
        shell.expect(USER_PROMPT, timeout=30)
        for address, port, token in (
            (first["ip"], 18080, first["token"]),
            ("10.0.2.2", host_endpoint["port"], host_endpoint["token"]),
        ):
            stream = spawn_interactive(
                f"{zaigr} project vm exec -- curl --noproxy '*' -4fsSN "
                f"--max-time 180 http://{address}:{port}/stream",
                cwd=project.cwd, env=project.env,
            )
            streams.append(stream)
            stream.expect_exact(token + ":2", timeout=10)
        udp = spawn_interactive(
            f"{zaigr} project vm exec -- timeout 180 bash -c " + shlex.quote(
                f"exec 3<>/dev/udp/{first['ip']}/18082; printf 'UDP_READY\\n'; "
                "while IFS= read -r request; do printf '%s\\n' \"$request\" >&3; "
                "head -n 1 <&3; done"
            ), cwd=project.cwd, env=project.env,
        )
        udp_sessions.append(udp)
        udp.expect_exact("UDP_READY", timeout=10)
        nonce = uuid.uuid4().hex
        udp.sendline(nonce)
        udp.expect_exact(first["token"] + ":" + nonce, timeout=5)
        # Recovery is available through this existing root shell. A 120-second
        # systemd timer also restores the real utility if the test is interrupted.
        root.sendline(
            "systemd-run --unit=ip-chaos-restore --on-active=120 "
            "/bin/mv /usr/bin/ss.ip-chaos-held /usr/bin/ss"
        )
        root.expect_exact("Running timer as unit: ip-chaos-restore.timer")
        root.expect(ROOT_PROMPT)
        root.sendline("mv /usr/bin/ss /usr/bin/ss.ip-chaos-held")
        root.expect(ROOT_PROMPT)
        fault_active = True
        stdout, stderr, rc = _run(
            f"{zaigr} project firewall remove {first['ip']}",
            cwd=project.cwd, env=project.env, timeout=30,
        )
        assert rc != 0 and "saved" in stdout + stderr, err_msg(stdout, stderr)
        assert "could not be applied" in stdout + stderr, err_msg(stdout, stderr)
        # The missing socket utility leaves a real established flow alive after
        # the policy publication; this proves a partial live side effect.
        marker = uuid.uuid4().hex
        _checked_run(first["host_command"] + [
            "curl", "--noproxy", "*", "-4fsS", "--max-time", "4",
            f"http://{first['ip']}:18080/mark/{marker}",
        ])
        streams[0].expect_exact(marker, timeout=5)
        nonce = uuid.uuid4().hex
        udp.sendline(nonce)
        udp.expect_exact(first["token"] + ":" + nonce, timeout=5)
        stdout, stderr, rc = _run(
            f"{zaigr} project firewall allow {second['ip']}",
            cwd=project.cwd, env=project.env, timeout=30,
        )
        assert rc != 0 and "saved" in stdout + stderr, err_msg(stdout, stderr)
        shell.sendline(
            "curl --noproxy '*' -4fsS --max-time 4 "
            f"http://{second['ip']}:18080/"
        )
        shell.expect_exact(second["token"] + ":0", timeout=10)
        shell.expect(USER_PROMPT)
        # This connection belongs to a grant that has never been recorded as
        # successfully applied. Its later revocation depends on pending history.
        shell.sendline(
            "curl --noproxy '*' -4fsSN --max-time 180 "
            f"http://{second['ip']}:18080/stream"
        )
        shell.expect_exact(second["token"] + ":2", timeout=10)
        # A new entry must not claim it has applied the pending policy.
        stdout, stderr, rc = _run(
            f"{zaigr} project vm exec -- printf SHOULD_NOT_ENTER",
            cwd=project.cwd, env=project.env, timeout=30,
        )
        assert rc != 0 and "SHOULD_NOT_ENTER" not in stdout, err_msg(stdout, stderr)
        for address in (second["ip"], first["ip"], second["ip"]):
            stdout, stderr, rc = _run(
                [zaigr, "project", "firewall", "remove", address],
                cwd=project.cwd, env=project.env, timeout=30,
            )
            assert rc != 0, err_msg(stdout, stderr)
            assert "saved" in stdout + stderr, err_msg(stdout, stderr)
        marker = uuid.uuid4().hex
        _checked_run(second["host_command"] + [
            "curl", "--noproxy", "*", "-4fsS", "--max-time", "4",
            f"http://{second['ip']}:18080/mark/{marker}",
        ])
        shell.expect_exact(marker, timeout=5)
        shown = run(f"{zaigr} project firewall show")
        assert "pending or unconfirmed" in shown, shown
        assert first["ip"] not in shown and second["ip"] not in shown, shown
        root.sendline("mv /usr/bin/ss.ip-chaos-held /usr/bin/ss")
        root.expect(ROOT_PROMPT)
        fault_active = False
        root.sendline("systemctl stop ip-chaos-restore.timer")
        root.expect(ROOT_PROMPT)
        if recovery == "remove-retry":
            output = run(f"{zaigr} project firewall remove {second['ip']}")
            assert "applied" in output, output
        else:
            assert run(f"{zaigr} project vm exec -- printf RECONCILED") == "RECONCILED"
        _assert_stream_stops(streams[0])
        _assert_stream_stops(shell)
        shell.sendcontrol("c")
        shell.expect(USER_PROMPT, timeout=10)
        nonce = uuid.uuid4().hex
        udp.sendline(nonce)
        assert udp.expect_exact(
            [first["token"] + ":" + nonce, pexpect.EOF, pexpect.TIMEOUT], timeout=3,
        ) != 0
        marker = uuid.uuid4().hex
        _checked_run(ip_endpoints["host_command"] + [
            "curl", "--noproxy", "*", "-4fsS", "--max-time", "4",
            f"http://127.0.0.1:{host_endpoint['port']}/mark/{marker}",
        ])
        streams[1].expect_exact(marker, timeout=5)
        for endpoint in (first, second):
            # Restore the server's normal sentinel after the stream markers.
            _checked_run(endpoint["host_command"] + [
                "curl", "--noproxy", "*", "-4fsS", "--max-time", "4",
                f"http://{endpoint['ip']}:18080/mark/",
            ])
            assert_host_services(endpoint, ip_endpoints["key"])
            _assert_blocked(*_run(
                f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS "
                f"--connect-timeout 2 --max-time 4 http://{endpoint['ip']}:18081/",
                cwd=project.cwd, env=project.env, timeout=15,
            ))
        shell.sendline("printf '\\nCONTROL_SURVIVED\\n'")
        shell.expect_exact("\r\nCONTROL_SURVIVED\r\n")
        shell.expect(USER_PROMPT)
        assert "status: applied" in run(f"{zaigr} project firewall show")
    finally:
        if fault_active:
            root.sendline("mv /usr/bin/ss.ip-chaos-held /usr/bin/ss")
            root.expect(ROOT_PROMPT, timeout=10)
            root.sendline("systemctl stop ip-chaos-restore.timer")
            root.expect(ROOT_PROMPT, timeout=10)
        for process in streams + udp_sessions + [shell, root]:
            if process.isalive():
                process.close(force=True)


@pytest.mark.timeout(360)
def test_live_rule_enumeration_failure_is_not_reported_as_applied(project, ip_endpoints):
    """Failure to enumerate existing policies must not silently retain a removed grant."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    endpoint = ip_endpoints["first"]
    run(f"{zaigr} project vm start", input="y\n", timeout=180)
    run(f"{zaigr} project firewall allow {endpoint['ip']}")
    root = spawn_interactive(f"{zaigr} shell --root", cwd=project.cwd, env=project.env)
    root.expect(r"\[y/N\]")
    root.sendline("y")
    root.expect(ROOT_PROMPT, timeout=30)
    shell = spawn_interactive(f"{zaigr} shell", cwd=project.cwd, env=project.env)
    fault_active = False
    try:
        shell.expect(USER_PROMPT, timeout=20)
        root.sendline(
            "systemd-run --unit=ip-chaos-find-restore --on-active=90 "
            "/bin/mv /usr/bin/find.ip-chaos-held /usr/bin/find"
        )
        root.expect_exact("Running timer as unit: ip-chaos-find-restore.timer")
        root.expect(ROOT_PROMPT)
        root.sendline("mv /usr/bin/find /usr/bin/find.ip-chaos-held")
        root.expect(ROOT_PROMPT)
        fault_active = True
        stdout, stderr, rc = _run(
            f"{zaigr} project firewall remove {endpoint['ip']}",
            cwd=project.cwd, env=project.env, timeout=30,
        )
        # Observe the existing shell before any new entry can reconcile policy.
        shell.sendline(
            "curl --noproxy '*' -4fsS --connect-timeout 2 --max-time 4 "
            f"http://{endpoint['ip']}:18080/"
        )
        shell.expect(USER_PROMPT, timeout=10)
        traffic = shell.before
        assert rc != 0, err_msg(stdout, stderr) + "\nExisting shell traffic:\n" + traffic
        assert "saved" in stdout + stderr, err_msg(stdout, stderr)
        assert "applied to the running" not in stdout, stdout
        root.sendline("mv /usr/bin/find.ip-chaos-held /usr/bin/find")
        root.expect(ROOT_PROMPT)
        fault_active = False
        root.sendline("systemctl stop ip-chaos-find-restore.timer")
        root.expect(ROOT_PROMPT)
        run(f"{zaigr} project firewall remove {endpoint['ip']}")
        assert_host_services(endpoint, ip_endpoints["key"])
        _assert_blocked(*_run(
            f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS "
            f"--connect-timeout 2 --max-time 4 http://{endpoint['ip']}:18081/",
            cwd=project.cwd, env=project.env, timeout=15,
        ))
    finally:
        if fault_active:
            root.sendline("mv /usr/bin/find.ip-chaos-held /usr/bin/find")
            root.expect(ROOT_PROMPT, timeout=10)
            root.sendline("systemctl stop ip-chaos-find-restore.timer")
            root.expect(ROOT_PROMPT, timeout=10)
        for process in (shell, root):
            if process.isalive():
                process.close(force=True)


@pytest.mark.timeout(360)
def test_running_corrupt_policy_refuses_new_entry_without_broadening_live_shell(
    project, ip_endpoints
):
    """Malformed documented metadata cannot partially grant its valid first line."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    first, second = ip_endpoints["first"], ip_endpoints["second"]
    run(f"{zaigr} project vm start", input="y\n", timeout=180)
    run(f"{zaigr} project firewall allow {second['ip']}")
    policy = project.store_dir / "firewall-ips"
    original = policy.read_bytes()
    shell = spawn_interactive(f"{zaigr} shell", cwd=project.cwd, env=project.env)
    try:
        shell.expect(USER_PROMPT, timeout=20)
        # A truncated administrator edit adds a valid new IP before invalid data.
        damaged = f"{first['ip']}\n192.0.2.0/24\n".encode()
        policy.write_bytes(damaged)
        for command in (
            f"{zaigr} project firewall show",
            f"{zaigr} project firewall allow {first['ip']}",
            f"{zaigr} project vm exec -- printf SHOULD_NOT_ENTER",
            f"{zaigr} project vm start",
        ):
            stdout, stderr, rc = _run(command, cwd=project.cwd, env=project.env, timeout=20)
            assert rc != 0, err_msg(stdout, stderr)
            assert "firewall" in stdout + stderr, err_msg(stdout, stderr)
            assert "SHOULD_NOT_ENTER" not in stdout
            assert policy.read_bytes() == damaged
        assert_host_services(first, ip_endpoints["key"])
        shell.sendline(
            "curl --noproxy '*' -4fsS --connect-timeout 2 --max-time 4 "
            f"http://{first['ip']}:18080/; printf 'PROBE_EXIT=%s\\n' \"$?\""
        )
        shell.expect(r"\r\nPROBE_EXIT=(7|28)\r\n", timeout=10)
        assert first["token"] not in shell.before
        shell.expect(USER_PROMPT)
        shell.sendline(
            "curl --noproxy '*' -4fsS --max-time 4 "
            f"http://{second['ip']}:18080/"
        )
        shell.expect_exact(second["token"] + ":0", timeout=10)
        shell.expect(USER_PROMPT)
    finally:
        policy.write_bytes(original)
        if shell.isalive():
            shell.close(force=True)
    assert run(f"{zaigr} project vm exec -- printf RECOVERED") == "RECOVERED"
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
