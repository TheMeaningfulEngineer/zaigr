"""Public CLI acceptance tests for persistent exact IPv4 project permissions."""

import os
import re
from concurrent.futures import ThreadPoolExecutor
from functools import partial

import pytest

from ..conftest import err_msg
from ..conftest import run as _run


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


def _assert_pending(output):
    """Check that a stopped mutation describes deferred application."""
    assert "saved" in output.lower(), output
    assert "next" in output.lower() and "start" in output.lower(), output


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
    _assert_pending(
        run([zaigr, "project", "firewall", "allow", "192.0.2.42", "192.0.2.43"], timeout=10)
    )
    before = run(f"{zaigr} project firewall show", timeout=180)
    assert before.count("192.0.2.41") == 1, before
    assert before.count("192.0.2.42") == 1, before
    assert before.count("192.0.2.43") == 1, before
    assert "IP" in before or "IPv4" in before, before
    assert "all ports" in before.lower(), before
    assert "project" in before.lower(), before
    assert "next" in before.lower() or "pending" in before.lower(), before
    exact_dns_lookalikes = [
        "192.0.2.1-10", "192.0.2.999", "192.0.2", "192.000.2.42",
    ]
    for name in exact_dns_lookalikes:
        stdout, stderr, rc = _run(
            [zaigr, "project", "firewall", "allow", name],
            cwd=project.cwd, env=project.env, timeout=10,
        )
        assert rc == 0, err_msg(stdout, stderr)
        shown = run(f"{zaigr} project firewall show", timeout=180)
        lines = shown.splitlines()
        ip_section = lines.index("# Project exact IPv4 permissions (all ports)")
        domain_section = lines.index("# Project manual domain permissions")
        setup_section = lines.index("# Project setup permissions")
        assert name not in lines[ip_section + 1:domain_section], shown
        assert name in lines[domain_section + 1:setup_section], shown
        stdout, stderr, rc = _run(
            [zaigr, "project", "firewall", "remove", name],
            cwd=project.cwd, env=project.env, timeout=10,
        )
        assert rc == 0, err_msg(stdout, stderr)
        assert run(f"{zaigr} project firewall show", timeout=180) == before
    invalid_arguments = [
        [],
        ["http://192.0.2.42"], ["192.0.2.42:22"], ["192.0.2.0/24"],
        ["192.0.2.*"], ["::1"], ["::ffff:192.0.2.42"],
        ["3232235777"], ["0xc000022a"],
        ["192.0.2.42 "], [" 192.0.2.42"],
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
    invalid_multi_arguments = [
        ("allow", ["192.0.2.44", "bad..example.com"]),
        ("remove", ["192.0.2.41", "bad..example.com"]),
    ]
    for operation, arguments in invalid_multi_arguments:
        stdout, stderr, rc = _run(
            [zaigr, "project", "firewall", operation, *arguments],
            cwd=project.cwd, env=project.env, timeout=10,
        )
        assert rc != 0, err_msg(stdout, stderr)
        assert "unknown command" not in stdout + stderr, err_msg(stdout, stderr)
        assert run(f"{zaigr} project firewall show", timeout=180) == before
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
    assert "# project setup permissions" in shown.lower() and "pypi.org" in shown
    assert "192.0.2.41" not in shown
    run(
        f"{zaigr} project vm exec -- curl --noproxy '*' -4fsS -o /dev/null "
        "--connect-timeout 5 --max-time 15 https://pypi.org", timeout=20,
    )
