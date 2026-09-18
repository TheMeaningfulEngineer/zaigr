"""Public CLI acceptance tests for persistent exact IPv4 project permissions."""

import os
import re
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
from .ip_access_endpoints import assert_host_services, ssh_options, udp_probe

ip_endpoints = ip_access_endpoints.ip_endpoints
ip_network = ip_access_endpoints.ip_network
zaigr_bin = ip_access_endpoints.zaigr_bin
host_endpoint = ip_access_endpoints.host_endpoint
USER_PROMPT = r"user@[^:]+:.*[$] "


@pytest.fixture(autouse=True)
def small_vm_resources(monkeypatch):
    """Keep isolated project VMs economical under parallel execution."""
    monkeypatch.setenv("ZAIGR_VM_RAM", "512")
    monkeypatch.setenv("ZAIGR_VM_CPU", "1")
    monkeypatch.setenv("ZAIGR_DISK_SIZE", "8G")


def _checked_run(cmd, **kwargs):
    """Record a visible command and return its successful stdout."""
    stdout, stderr, rc = _run(cmd, **kwargs)
    assert rc == 0, err_msg(stdout, stderr)
    return stdout


def _assert_blocked(stdout, stderr, rc):
    """Accept network denial, while rejecting unrelated guest command failures."""
    assert rc in (7, 28), err_msg(stdout, stderr)
    assert "ip-endpoint-" not in stdout
    assert "connect" in stderr.lower() or "timed out" in stderr.lower(), stderr


def _assert_pending(output):
    """Check that a stopped mutation describes deferred application."""
    assert "saved" in output.lower(), output
    assert "next" in output.lower() and "start" in output.lower(), output


def _assert_stream_stops(stream):
    """Require established traffic to become quiet within ten seconds."""
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            stream.read_nonblocking(size=4096, timeout=2)
        except (pexpect.EOF, pexpect.TIMEOUT):
            return
    pytest.fail("Revoked connection still delivered traffic after ten seconds")


def test_firewall_help_explains_exact_project_permissions(project):
    """Discoverable help documents scope, persistence, all ports, and normal SSH."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    output = run(f"{zaigr} project firewall --help")
    assert re.search(r"\ballow\b", output), output
    assert re.search(r"\bremove\b", output), output
    assert re.search(r"\bshow\b", output), output
    output += run(f"{zaigr} project firewall allow --help")
    output += run(f"{zaigr} project firewall remove --help")
    lowered = output.lower()
    for term in ("ipv4", "exact", "project", "all ports", "ssh", "remove"):
        assert term in lowered, output
    assert "persist" in lowered or "until removed" in lowered, output
    assert "offline" in lowered or "reachable" in lowered, output
    for operation in ("allow", "show", "remove"):
        assert f"zaigr project firewall {operation}" in lowered, output
    assert re.search(r"ssh\s+\S+@(?:\d{1,3}\.){3}\d{1,3}", lowered), output


@pytest.mark.parametrize("operation", ["allow", "remove", "show"])
def test_ip_commands_require_an_initialized_project(project, operation):
    """An uninitialized directory gets the existing actionable project error."""
    command = [project.zaigr_bin, "project", "firewall", operation]
    if operation != "show":
        command.append("192.0.2.41")
    stdout, stderr, rc = _run(command, cwd=project.cwd, env=project.env)
    assert rc != 0, err_msg(stdout, stderr)
    assert "requires a project" in stdout + stderr
    assert "zaigr shell" in stdout + stderr


@pytest.mark.timeout(360)
def test_stopped_permissions_validate_and_preserve_configuration(project):
    """Offline mutations stay stopped, are idempotent, and reject ambiguous input."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    run(f"{zaigr} project vm start", input="y\n", timeout=180)
    run(f"{zaigr} project vm stop", timeout=60)
    _assert_pending(run(f"{zaigr} project firewall allow 192.0.2.41", timeout=10))
    duplicate = run(f"{zaigr} project firewall allow 192.0.2.41", timeout=10)
    assert "already" in duplicate.lower() and "allow" in duplicate.lower()
    for address in ("192.168.2.11", "169.254.44.2", "10.0.2.2"):
        _assert_pending(run([zaigr, "project", "firewall", "allow", address], timeout=10))
    before = run(f"{zaigr} project firewall show", timeout=180)
    assert before.count("192.0.2.41") == 1, before
    assert "IP" in before or "IPv4" in before, before
    assert "all ports" in before.lower(), before
    assert "project" in before.lower(), before
    assert "next" in before.lower() or "pending" in before.lower(), before
    invalid_arguments = [
        [], ["192.0.2.42", "192.0.2.43"], ["example.com"],
        ["http://192.0.2.42"], ["192.0.2.42:22"], ["192.0.2.0/24"],
        ["192.0.2.*"], ["192.0.2.1-10"], ["::1"], ["::ffff:192.0.2.42"],
        ["192.0.2.999"], ["192.0.2"], ["3232235777"], ["0xc000022a"],
        ["192.000.2.42"], ["192.0.2.42 "], [" 192.0.2.42"],
        ["192.0.2.42\n192.0.2.43"], ["0.0.0.0"], ["224.0.0.1"],
        ["239.255.255.255"], ["255.255.255.255"],
    ]
    for operation in ("allow", "remove"):
        for arguments in invalid_arguments:
            stdout, stderr, rc = _run(
                [zaigr, "project", "firewall", operation] + arguments,
                cwd=project.cwd, env=project.env, timeout=10,
            )
            assert rc != 0, err_msg(stdout, stderr)
            assert "unknown command" not in stdout + stderr, err_msg(stdout, stderr)
    assert run(f"{zaigr} project firewall show", timeout=180) == before
    stdout, stderr, rc = _run(
        f"{zaigr} project firewall remove 192.0.2.99",
        cwd=project.cwd, env=project.env, timeout=10,
    )
    absent = (stdout + stderr).lower()
    assert rc in (0, 1), err_msg(stdout, stderr)
    assert "not allowed" in absent or "not granted" in absent, absent
    assert run(f"{zaigr} project firewall show", timeout=180) == before
    _assert_pending(run(f"{zaigr} project firewall remove 192.0.2.41", timeout=10))
    after = run(f"{zaigr} project firewall show", timeout=180)
    assert "192.0.2.41" not in after
    for address in ("192.168.2.11", "169.254.44.2", "10.0.2.2"):
        assert address in after
    assert "status: not running" in run(f"{zaigr} project status")


@pytest.mark.timeout(360)
def test_controlled_destination_fixture_has_real_guest_routes(project, ip_endpoints):
    """Temporary root access proves both routes and all services before denial."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    run(f"{zaigr} project vm start", input="y\n", timeout=180)
    run(
        f"{zaigr} project vm exec -- tee /tmp/ip-endpoint-key",
        input=ip_endpoints["key"].read_text(encoding="utf-8"),
    )
    run(f"{zaigr} project vm exec -- chmod 600 /tmp/ip-endpoint-key")
    for endpoint in (ip_endpoints["first"], ip_endpoints["second"]):
        for port in (18080, 18081):
            output = run(
                f"{zaigr} project vm exec --root -- curl --noproxy '*' -4fsS "
                f"--max-time 4 http://{endpoint['ip']}:{port}/", input="y\n",
            )
            assert output.strip() == endpoint["token"] + ":0"
        output = run(
            [zaigr, "project", "vm", "exec", "--root", "--"] + udp_probe(endpoint["ip"]),
            input="y\n",
        )
        assert output.strip() == endpoint["token"] + ":probe"
        output = run(
            [zaigr, "project", "vm", "exec", "--root", "--"]
            + ssh_options("/tmp/ip-endpoint-key")
            + [f"root@{endpoint['ip']}", "printf", endpoint["token"]], input="y\n",
        )
        assert output.strip() == endpoint["token"]
        _assert_blocked(*_run(
            f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS "
            f"--connect-timeout 2 --max-time 4 http://{endpoint['ip']}:18080/",
            cwd=project.cwd, env=project.env, timeout=15,
        ))


@pytest.mark.timeout(420)
def test_live_exact_ip_access_and_revocation_preserve_other_connections(
    project, ip_endpoints, host_endpoint
):
    """Live grants allow TCP, UDP, and SSH; revocation affects only that address."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    first, second = ip_endpoints["first"], ip_endpoints["second"]
    run(f"{zaigr} project vm start", input="y\n", timeout=180)
    boot = run(f"{zaigr} project vm exec -- cat /proc/sys/kernel/random/boot_id")
    host_url = f"http://10.0.2.2:{host_endpoint['port']}/sentinel"
    assert run(
        f"{zaigr} project vm exec --root -- curl --noproxy '*' -4fsS "
        f"--max-time 4 {host_url}", input="y\n",
    ).strip() == host_endpoint["token"]
    for endpoint in (first, second):
        output = run(
            f"{zaigr} project vm exec --root -- curl --noproxy '*' -4fsS "
            f"--max-time 4 http://{endpoint['ip']}:18080/", input="y\n",
        )
        assert output.strip() == endpoint["token"] + ":0"
        _assert_blocked(*_run(
            f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS "
            f"--connect-timeout 2 --max-time 4 http://{endpoint['ip']}:18080/",
            cwd=project.cwd, env=project.env, timeout=15,
        ))
    shell = spawn_interactive(f"{zaigr} shell", cwd=project.cwd, env=project.env)
    streams = []
    udp_sessions = []
    try:
        shell.expect(USER_PROMPT, timeout=30)
        allowed = run(f"{zaigr} project firewall allow {first['ip']}", timeout=20)
        assert "applied" in allowed.lower(), allowed
        for port in (18080, 18081):
            output = run(
                f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS "
                f"--max-time 4 http://{first['ip']}:{port}/",
            )
            assert output.strip() == first["token"] + ":0"
        assert run(
            [zaigr, "project", "vm", "exec", "--"] + udp_probe(first["ip"])
        ).strip() == first["token"] + ":probe"
        run(
            f"{zaigr} project vm exec -- tee /tmp/ip-endpoint-key",
            input=ip_endpoints["key"].read_text(encoding="utf-8"),
        )
        run(f"{zaigr} project vm exec -- chmod 600 /tmp/ip-endpoint-key")
        assert run(
            [zaigr, "project", "vm", "exec", "--"] + ssh_options("/tmp/ip-endpoint-key")
            + [f"root@{first['ip']}", "printf", first["token"]]
        ) == first["token"]
        _assert_blocked(*_run(
            f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS "
            f"--connect-timeout 2 --max-time 4 http://{second['ip']}:18080/",
            cwd=project.cwd, env=project.env, timeout=15,
        ))
        run(f"{zaigr} project firewall allow {second['ip']}", timeout=20)
        for endpoint in (first, second):
            # One Bash process owns one connected UDP socket for both probes.
            session = spawn_interactive(
                f"{zaigr} project vm exec -- timeout 90 bash -c "
                + shlex.quote(
                    f"exec 3<>/dev/udp/{endpoint['ip']}/18082; "
                    "printf 'UDP_READY\\n'; "
                    "while IFS= read -r request; do "
                    "printf '%s\\n' \"$request\" >&3; head -n 1 <&3; done"
                ),
                cwd=project.cwd, env=project.env,
            )
            udp_sessions.append(session)
            session.expect_exact("UDP_READY", timeout=10)
            nonce = uuid.uuid4().hex
            session.sendline(nonce)
            session.expect_exact(endpoint["token"] + ":" + nonce, timeout=5)
        for endpoint in (first, second):
            stream = spawn_interactive(
                f"{zaigr} project vm exec -- curl --noproxy '*' -4fsSN "
                f"--max-time 90 http://{endpoint['ip']}:18080/stream",
                cwd=project.cwd, env=project.env,
            )
            streams.append(stream)
            stream.expect_exact(endpoint["token"] + ":2", timeout=10)
        removed = run(f"{zaigr} project firewall remove {first['ip']}", timeout=20)
        assert "applied" in removed.lower(), removed
        _assert_stream_stops(streams[0])
        nonce = uuid.uuid4().hex
        udp_sessions[0].sendline(nonce)
        denied = udp_sessions[0].expect_exact(
            [first["token"] + ":" + nonce, pexpect.EOF, pexpect.TIMEOUT], timeout=3,
        )
        assert denied != 0, "Revoked connected UDP socket still exchanged traffic"
        udp_sessions[1].sendline(nonce)
        udp_sessions[1].expect_exact(second["token"] + ":" + nonce, timeout=5)
        marker = uuid.uuid4().hex
        _checked_run(second["host_command"] + [
            "curl", "--noproxy", "*", "-4fsS", "--max-time", "4",
            f"http://{second['ip']}:18080/mark/{marker}",
        ])
        streams[1].expect_exact(marker, timeout=5)
        assert_host_services(first, ip_endpoints["key"])
        _assert_blocked(*_run(
            f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS "
            f"--connect-timeout 2 --max-time 4 http://{first['ip']}:18081/",
            cwd=project.cwd, env=project.env, timeout=15,
        ))
        assert run(
            f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS "
            f"--max-time 4 http://{second['ip']}:18081/"
        ).strip() == second["token"] + ":0"
        assert run(f"{zaigr} project vm exec -- cat /proc/sys/kernel/random/boot_id") == boot
        _assert_blocked(*_run(
            f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS "
            f"--connect-timeout 2 --max-time 4 {host_url}",
            cwd=project.cwd, env=project.env, timeout=15,
        ))
        run(f"{zaigr} project firewall allow 10.0.2.2", timeout=20)
        assert run(
            f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS --max-time 4 {host_url}"
        ) == host_endpoint["token"]
        run(f"{zaigr} project firewall remove 10.0.2.2", timeout=20)
        _assert_blocked(*_run(
            f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS "
            f"--connect-timeout 2 --max-time 4 {host_url}",
            cwd=project.cwd, env=project.env, timeout=15,
        ))
        assert run(f"{zaigr} project vm exec -- printf CONTROL_OK") == "CONTROL_OK"
        shell.sendline("printf 'LIVE_CONTROL_%s\\n' OK")
        shell.expect_exact("LIVE_CONTROL_OK", timeout=10)
        shell.expect(USER_PROMPT)
        shell.sendline("exit")
        shell.expect(pexpect.EOF)
    finally:
        for stream in streams + udp_sessions:
            stream.close(force=True)
        if shell.isalive():
            shell.close(force=True)


@pytest.mark.timeout(600)
def test_stopped_grants_survive_restart_rebuild_clean_without_resurrection(
    project, setup_factory, ip_endpoints
):
    """Saved grants survive image changes while removed grants stay revoked."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    first, second = ip_endpoints["first"], ip_endpoints["second"]
    setup_factory("ip-lifecycle", "printf 'installed\\n' > /etc/ip-lifecycle")
    run(f"{zaigr} project setup run ip-lifecycle", input="y\n", timeout=180)
    run(
        f"{zaigr} project vm exec -- tee /home/user/workspace/ip-workspace",
        input="workspace-survives\n",
    )
    run(f"{zaigr} project vm exec -- mkdir -p /home/user/.zaigr-agent-state/ip-test")
    run(
        f"{zaigr} project vm exec -- tee /home/user/.zaigr-agent-state/ip-test/credential",
        input="test-agent-state\n",
    )
    run(f"{zaigr} project vm stop", timeout=60)
    for endpoint in (first, second):
        _assert_pending(run(f"{zaigr} project firewall allow {endpoint['ip']}", timeout=10))
    assert "status: not running" in run(f"{zaigr} project status")
    run(f"{zaigr} project vm start", timeout=180)
    for endpoint in (first, second):
        assert run(
            f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS "
            f"--max-time 4 http://{endpoint['ip']}:18080/"
        ).strip() == endpoint["token"] + ":0"
    run(f"{zaigr} project vm stop", timeout=60)
    _assert_pending(run(f"{zaigr} project firewall remove {second['ip']}", timeout=10))
    run(f"{zaigr} project vm start", timeout=180)
    _assert_blocked(*_run(
        f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS "
        f"--connect-timeout 2 --max-time 4 http://{second['ip']}:18080/",
        cwd=project.cwd, env=project.env, timeout=15,
    ))
    run(f"{zaigr} project vm stop", timeout=60)
    run(f"{zaigr} project rebuild", timeout=180)
    run(f"{zaigr} project vm start", timeout=180)
    assert run(f"{zaigr} project vm exec -- cat /etc/ip-lifecycle") == "installed\n"
    assert run(
        f"{zaigr} project vm exec -- cat /home/user/.zaigr-agent-state/ip-test/credential"
    ) == "test-agent-state\n"
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
    run(f"{zaigr} project vm stop", timeout=60)
    run(f"{zaigr} project clean", timeout=180)
    run(f"{zaigr} project vm start", timeout=180)
    run(f"{zaigr} project vm exec -- test ! -e /etc/ip-lifecycle")
    assert run(
        f"{zaigr} project vm exec -- cat /home/user/workspace/ip-workspace"
    ) == "workspace-survives\n"
    assert run(
        f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS "
        f"--max-time 4 http://{first['ip']}:18081/"
    ).strip() == first["token"] + ":0"
    _assert_blocked(*_run(
        f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS "
        f"--connect-timeout 2 --max-time 4 http://{second['ip']}:18081/",
        cwd=project.cwd, env=project.env, timeout=15,
    ))


@pytest.mark.timeout(420)
def test_projects_own_grants_independently_in_one_home(project_factory, ip_endpoints):
    """A sibling never inherits another project's grant or removal."""
    first_project = project_factory("granted")
    sibling = project_factory("sibling")
    run = partial(_checked_run, env=first_project.env)
    zaigr = first_project.zaigr_bin
    endpoint = ip_endpoints["first"]
    run(f"{zaigr} project vm start", cwd=first_project.cwd, input="y\n", timeout=180)
    run(f"{zaigr} project firewall allow {endpoint['ip']}", cwd=first_project.cwd)
    run(f"{zaigr} project vm start", cwd=sibling.cwd, input="y\n", timeout=180)
    _assert_blocked(*_run(
        f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS "
        f"--connect-timeout 2 --max-time 4 http://{endpoint['ip']}:18080/",
        cwd=sibling.cwd, env=sibling.env, timeout=15,
    ))
    assert run(
        f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS "
        f"--max-time 4 http://{endpoint['ip']}:18080/", cwd=first_project.cwd,
    ).strip() == endpoint["token"] + ":0"
    run(f"{zaigr} project firewall allow {endpoint['ip']}", cwd=sibling.cwd)
    run(f"{zaigr} project firewall remove {endpoint['ip']}", cwd=first_project.cwd)
    assert_host_services(endpoint, ip_endpoints["key"])
    _assert_blocked(*_run(
        f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS "
        f"--connect-timeout 2 --max-time 4 http://{endpoint['ip']}:18080/",
        cwd=first_project.cwd, env=first_project.env, timeout=15,
    ))
    assert run(
        f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS "
        f"--max-time 4 http://{endpoint['ip']}:18080/", cwd=sibling.cwd,
    ).strip() == endpoint["token"] + ":0"


@pytest.mark.timeout(600)
def test_capture_keeps_project_grants_without_exporting_them(
    project_factory, ip_endpoints
):
    """A reusable captured setup preserves the owner grant without granting consumers."""
    project = project_factory("capture-owner")
    consumer = project_factory("capture-consumer")
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    endpoint = ip_endpoints["first"]
    run(f"{zaigr} project vm start", input="y\n", timeout=180)
    run(f"{zaigr} project firewall allow {endpoint['ip']}")
    run(f"{zaigr} project vm stop", timeout=60)
    capture = spawn_interactive(
        f"{zaigr} project setup capture start",
        cwd=project.cwd, env=project.env, timeout=180,
    )
    try:
        capture.expect(r"root@[^:]+:.*# ", timeout=180)
        capture.sendline("printf 'captured-ip-content\\n' > /etc/captured-ip-content")
        capture.expect(r"root@[^:]+:.*# ")
        review = run(f"{zaigr} project setup capture review")
        assert "captured-ip-content" in review
        for operation in ("allow", "remove"):
            stdout, stderr, rc = _run(
                [zaigr, "project", "firewall", operation, endpoint["ip"]],
                cwd=project.cwd, env=project.env, timeout=10,
            )
            assert rc != 0, err_msg(stdout, stderr)
            assert "project setup capture is active" in stdout + stderr
        accepted = run(f"{zaigr} project setup capture accept", timeout=180)
        capture.expect(pexpect.EOF, timeout=30)
        capture.close()
        assert capture.exitstatus == 0
    finally:
        if capture.isalive():
            capture.close(force=True)
    setup_path = Path(re.search(r"Updated setup definition: (.+)", accepted).group(1))
    run(f"{zaigr} project vm start", timeout=180)
    assert run(
        f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS "
        f"--max-time 4 http://{endpoint['ip']}:18080/"
    ).strip() == endpoint["token"] + ":0"
    # Captured setup files are public user-owned output, copied as a user would.
    destination = consumer.cwd / ".zaigr" / "setups"
    _checked_run(["mkdir", "-p", destination])
    _checked_run(["cp", "-r", setup_path, destination / setup_path.name])
    _checked_run(
        [zaigr, "project", "setup", "run", setup_path.name],
        cwd=consumer.cwd, env=consumer.env, input="y\n", timeout=180,
    )
    _checked_run(f"{zaigr} project vm start", cwd=consumer.cwd, env=consumer.env, timeout=180)
    assert _checked_run(
        f"{zaigr} project vm exec -- cat /etc/captured-ip-content",
        cwd=consumer.cwd, env=consumer.env,
    ) == "captured-ip-content\n"
    assert_host_services(endpoint, ip_endpoints["key"])
    _assert_blocked(*_run(
        f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS "
        f"--connect-timeout 2 --max-time 4 http://{endpoint['ip']}:18080/",
        cwd=consumer.cwd, env=consumer.env, timeout=15,
    ))


@pytest.mark.timeout(480)
def test_stopped_capture_token_expires_without_revoking_project_grants(
    project, ip_endpoints
):
    """Accepting an interrupted capture expires its token and retains project grants."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    first, second = ip_endpoints["first"], ip_endpoints["second"]
    run(f"{zaigr} project vm start", input="y\n", timeout=180)
    run(f"{zaigr} project firewall allow {second['ip']}")
    assert_host_services(first, ip_endpoints["key"])
    _assert_blocked(*_run(
        f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS "
        f"--connect-timeout 2 --max-time 4 http://{first['ip']}:18080/",
        cwd=project.cwd, env=project.env, timeout=15,
    ))
    run(f"{zaigr} project vm stop", timeout=60)
    capture = spawn_interactive(
        f"{zaigr} project setup capture start",
        cwd=project.cwd, env=project.env, timeout=180,
    )
    try:
        capture.expect(r"root@[^:]+:.*# ", timeout=180)
        capture.sendline("printf 'interrupted-capture\\n' > /etc/interrupted-capture")
        capture.expect(r"root@[^:]+:.*# ")
        # Deliberately export this test's disposable token to its shared workspace.
        capture.sendline(
            "printf '%s\\n' \"${ZAIGR_SETUP_CAPTURE_TOKEN:-}\" "
            "> /home/user/workspace/capture-test-token"
        )
        capture.expect(r"root@[^:]+:.*# ")
        token = _checked_run(["cat", project.cwd / "capture-test-token"]).strip()
        assert token, "The real capture shell did not supply a disposable token"
        capture.sendline(
            "runuser -u user -- env "
            'ZAIGR_SETUP_CAPTURE_TOKEN="${ZAIGR_SETUP_CAPTURE_TOKEN:-}" '
            "curl --noproxy '*' -4fsS --connect-timeout 2 --max-time 4 "
            f"http://{first['ip']}:18080/"
        )
        capture.expect_exact(first["token"] + ":0", timeout=15)
        capture.expect(r"root@[^:]+:.*# ")
        capture.sendline("sync")
        capture.expect(r"root@[^:]+:.*# ")
        # Simulate guest loss without reading product runtime metadata.
        run([
            "python3", ip_endpoints["qemu_cleanup"], "--interrupt",
            str(ip_endpoints["namespace_inode"]), str(ip_endpoints["host_uid"]),
        ], timeout=20)
        capture.expect(pexpect.EOF, timeout=30)
        capture.close()
        deadline = time.monotonic() + 30
        while True:
            review = run(f"{zaigr} project setup capture review", timeout=10)
            if "observed endpoints (stored):" in review:
                break
            assert time.monotonic() < deadline, review
            time.sleep(0.5)
        accepted = run(f"{zaigr} project setup capture accept", timeout=180)
        assert "Accepted setup capture" in accepted, accepted
        assert "Promoted capture overlay" in accepted, accepted
    finally:
        if capture.isalive():
            capture.close(force=True)
    run(f"{zaigr} project vm start", timeout=180)
    assert run(
        f"{zaigr} project vm exec -- cat /etc/interrupted-capture"
    ) == "interrupted-capture\n"
    assert_host_services(first, ip_endpoints["key"])
    _assert_blocked(*_run(
        [zaigr, "project", "vm", "exec", "--", "env",
         f"ZAIGR_SETUP_CAPTURE_TOKEN={token}", "curl", "--noproxy", "*", "-4fsS",
         "--connect-timeout", "2", "--max-time", "4", f"http://{first['ip']}:18080/"],
        cwd=project.cwd, env=project.env, timeout=15,
    ))
    assert_host_services(second, ip_endpoints["key"])
    assert run(
        f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS "
        f"--max-time 4 http://{second['ip']}:18080/"
    ).strip() == second["token"] + ":0"


@pytest.mark.timeout(360)
def test_concurrent_stopped_mutations_never_lose_successful_changes(project):
    """Concurrent adds and removes either persist or explicitly report busy."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    run(f"{zaigr} project vm start", input="y\n", timeout=180)
    run(f"{zaigr} project vm stop", timeout=60)
    existing = ["192.0.2.11", "192.0.2.12", "192.0.2.13", "192.0.2.14"]
    new = ["192.0.2.21", "192.0.2.22", "192.0.2.23", "192.0.2.24"]
    for address in existing:
        run([zaigr, "project", "firewall", "allow", address])
    changes = [("remove", address) for address in existing]
    changes += [("allow", address) for address in new]
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [
            pool.submit(
                _run, [zaigr, "project", "firewall", operation, address],
                cwd=project.cwd, env=project.env, timeout=30,
            )
            for operation, address in changes
        ]
        results = [future.result() for future in futures]
    expected = set(existing)
    successful = 0
    for (operation, address), (stdout, stderr, rc) in zip(changes, results):
        if rc == 0:
            successful += 1
            if operation == "allow":
                expected.add(address)
            else:
                expected.remove(address)
        else:
            assert "busy" in (stdout + stderr).lower() or "another terminal" in stdout + stderr
    assert successful, results
    shown = run(f"{zaigr} project firewall show", timeout=180)
    for address in existing + new:
        assert (address in shown) == (address in expected), shown
    assert "status: not running" in run(f"{zaigr} project status")


@pytest.mark.timeout(360)
def test_documented_ip_store_corruption_and_write_failure_recover(project):
    """Malformed metadata fails closed and a real write failure preserves policy."""
    assert os.geteuid() != 0, "This fault injection requires unprivileged host permissions"
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    run(f"{zaigr} project vm start", input="y\n", timeout=180)
    run(f"{zaigr} project vm stop", timeout=60)
    run(f"{zaigr} project firewall allow 192.0.2.41")
    run(f"{zaigr} project firewall allow 192.0.2.42")
    policy = project.store_dir / "firewall-ips"
    original = policy.read_bytes()
    assert original == b"192.0.2.41\n192.0.2.42\n"
    for damaged in (
        b"192.0.2.41\n192.0.2.0/24\n", b"192.0.2.41\nnot-an-ip\n",
        b"192.0.2.41\n::ffff:192.0.2.42\n", b"192.0.2.41\n\xff\n",
    ):
        try:
            policy.write_bytes(damaged)
            for command in (
                f"{zaigr} project firewall show",
                f"{zaigr} project firewall allow 192.0.2.43",
                f"{zaigr} project firewall remove 192.0.2.41",
                f"{zaigr} project vm start",
            ):
                stdout, stderr, rc = _run(
                    command, cwd=project.cwd, env=project.env, timeout=20,
                )
                assert rc != 0, err_msg(stdout, stderr)
                assert "firewall" in (stdout + stderr).lower(), err_msg(stdout, stderr)
                assert "panic" not in stdout + stderr
                assert policy.read_bytes() == damaged
            stdout, stderr, rc = _run(
                f"{zaigr} project vm exec -- printf SHOULD_NOT_START",
                cwd=project.cwd, env=project.env, timeout=10,
            )
            assert rc != 0 and "SHOULD_NOT_START" not in stdout, err_msg(stdout, stderr)
        finally:
            policy.write_bytes(original)
    mode = policy.parent.stat().st_mode & 0o777
    try:
        policy.parent.chmod(0o500)
        stdout, stderr, rc = _run(
            f"{zaigr} project firewall allow 192.0.2.43",
            cwd=project.cwd, env=project.env, timeout=20,
        )
        assert rc != 0, err_msg(stdout, stderr)
        assert "firewall" in (stdout + stderr).lower(), err_msg(stdout, stderr)
        assert policy.read_bytes() == original
    finally:
        policy.parent.chmod(mode)
    run(f"{zaigr} project firewall allow 192.0.2.43")
    assert policy.read_bytes() == original + b"192.0.2.43\n"
    run(f"{zaigr} project vm start", timeout=180)
    assert run(f"{zaigr} project vm exec -- printf RECOVERED") == "RECOVERED"


@pytest.mark.timeout(300)
def test_ip_mutations_preserve_existing_exact_domain_access(project, setup_factory):
    """Adding and removing IP permissions preserves a setup's actual domain access."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    setup_factory("domain-owner", "true", firewall=["pypi.org"])
    _checked_run(
        "curl --noproxy '*' -4fsS -o /dev/null --connect-timeout 5 --max-time 15 https://pypi.org",
        timeout=20,
    )
    run(f"{zaigr} project setup run domain-owner", input="y\n", timeout=180)
    run(f"{zaigr} project vm start", timeout=180)
    run(
        f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS -o /dev/null "
        "--connect-timeout 5 --max-time 15 https://pypi.org", timeout=20,
    )
    run(f"{zaigr} project firewall allow 192.0.2.41")
    run(f"{zaigr} project firewall remove 192.0.2.41")
    shown = run(f"{zaigr} project firewall show")
    assert "# project setups" in shown and "pypi.org" in shown
    assert "192.0.2.41" not in shown
    run(
        f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS -o /dev/null "
        "--connect-timeout 5 --max-time 15 https://pypi.org", timeout=20,
    )
