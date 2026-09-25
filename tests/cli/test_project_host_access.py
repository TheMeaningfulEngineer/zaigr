"""Public workflows for project host ports and serial devices."""

import os
import shlex
import socket
import termios
from functools import partial
from pathlib import Path

import pexpect
import pytest

from ..conftest import err_msg, spawn_interactive
from ..conftest import run as _run
from . import host_access_endpoints
from .host_access_endpoints import http_body, receive_peer, unused_port, wait_text

endpoint_binary = host_access_endpoints.endpoint_binary
host_devices = host_access_endpoints.host_devices


def checked_run(command, **kwargs):
    """Record a visible command, require success, and return its output."""
    stdout, stderr, code = _run(command, **kwargs)
    assert code == 0, err_msg(stdout, stderr)
    return stdout


@pytest.fixture(autouse=True)
def small_vm(monkeypatch):
    """Use modest VM resources for these independent endpoint tests."""
    monkeypatch.setenv("ZAIGR_VM_RAM", "512")
    monkeypatch.setenv("ZAIGR_VM_CPU", "1")
    monkeypatch.setenv("ZAIGR_DISK_SIZE", "8G")


def test_host_access_help_and_completion(project):
    """Discover the interface, defaults, and completion through the CLI."""
    run = partial(checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    assert "host-access" in run([zaigr, "project", "--help"])
    help_text = run([zaigr, "project", "host-access", "--help"])
    help_text += run([zaigr, "project", "host-access", "allow", "--help"])
    help_text += run([zaigr, "project", "host-access", "remove", "--help"])
    for word in ("allow", "remove", "show", "--vm-port", "127.0.0.1", "TCP", "restart", "persist"):
        assert word in help_text
    assert "host-access" in run([zaigr, "__complete", "project", "host"])


@pytest.mark.parametrize("operation", ["allow", "remove", "show"])
def test_host_access_requires_a_project(project, operation):
    """Refuse grants and inspection outside an initialized project."""
    args = [project.zaigr_bin, "project", "host-access", operation]
    if operation != "show":
        args.append("8080")
    stdout, stderr, code = _run(args, cwd=project.cwd, env=project.env)
    assert code != 0
    assert "requires a project" in stdout + stderr
    assert "zaigr shell" in stdout + stderr


def test_stopped_grants_validation_and_idempotence(project):
    """Persist valid grants without booting or changing invalid requests."""
    run = partial(checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    run([zaigr, "project", "vm", "start"], input="y\n", timeout=180)
    run([zaigr, "project", "vm", "stop"], timeout=60)
    empty = run([zaigr, "project", "host-access", "show"])
    assert empty.count("(none)") == 2
    port = unused_port()
    assert "saved" in run([zaigr, "project", "host-access", "allow", port, "--vm-port", "3000"])
    assert "Already allowed" in run([zaigr, "project", "host-access", "allow", port, "--vm-port", "3000"])
    before = run([zaigr, "project", "host-access", "show"])
    assert before.count(f"localhost:{port}") == 1
    assert "VM stopped" in before
    for args in (["0"], ["65536"], ["-1"], ["+1"], ["1.2.3.4"], ["http://localhost"],
                 ["100-200"], ["relative/device"], [str(project.cwd)], ["8080", "8081"],
                 [str(port), "--vm-port", "3001"], ["8081", "--vm-port", "0"],
                 ["/dev/null"], ["/dev/null", "--vm-port", "3000"]):
        stdout, stderr, code = _run([zaigr, "project", "host-access", "allow", *args],
                                   cwd=project.cwd, env=project.env)
        assert code != 0, err_msg(stdout, stderr)
    assert run([zaigr, "project", "host-access", "show"]) == before
    assert "status: not running" in run([zaigr, "project", "status"])
    assert str(port) in run([zaigr, "__complete", "project", "host-access", "remove", ""])
    run([zaigr, "project", "host-access", "remove", port])
    assert "already absent" in run([zaigr, "project", "host-access", "remove", port])
    assert run([zaigr, "project", "host-access", "show"]) == empty


def test_live_ports_status_and_no_probes(project, endpoint_binary):
    """Apply and remove real forwards while observing without connection probes."""
    run = partial(checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    host, second = unused_port(), unused_port()
    assert host != second
    run([zaigr, "project", "vm", "start"], input="y\n", timeout=180)
    run([zaigr, "project", "host-access", "allow", host, "--vm-port", "43123"])
    assert "Available" in next(line for line in run([zaigr, "project", "host-access", "show"]).splitlines() if f"localhost:{host}" in line)
    run([zaigr, "project", "vm", "exec", "--root", "--", "bash", "-c",
         "nohup ./endpoint netwatch 43123 /tmp/netwatch.sync > netwatch.log 2>&1 < /dev/null &"], input="y\n")
    wait_text(project.cwd / "netwatch.log", "READY")
    for _ in range(3):
        run([zaigr, "project", "host-access", "show"])
    run([zaigr, "project", "vm", "exec", "--", "tee", "/tmp/netwatch.sync"], input="idle\n")
    assert wait_text(project.cwd / "netwatch.log", "SYNC 1").strip() == "READY\nSYNC 1"
    run([zaigr, "project", "vm", "exec", "--", "bash", "-c",
         "nohup ./endpoint server 0.0.0.0 43123 server-one > server.log 2>&1 < /dev/null & echo $! > server.pid"])
    wait_text(project.cwd / "server.log", "READY")
    for _ in range(3):
        output = run([zaigr, "project", "host-access", "show"])
        assert "Attached" in next(line for line in output.splitlines() if f"localhost:{host}" in line)
    assert (project.cwd / "server.log").read_text().strip() == "READY"
    run([zaigr, "project", "vm", "exec", "--", "tee", "/tmp/netwatch.sync"], input="listening\n")
    assert wait_text(project.cwd / "netwatch.log", "SYNC 2").strip() == "READY\nSYNC 1\nSYNC 2"
    assert http_body(host) == "server-one"
    wait_text(project.cwd / "netwatch.log", "SYN")
    wait_text(project.cwd / "server.log", "ACCEPTED")
    run([zaigr, "project", "host-access", "allow", second, "--vm-port", "43123"])
    assert http_body(second) == "server-one"
    run([zaigr, "project", "host-access", "remove", host])
    with pytest.raises(ConnectionRefusedError):
        socket.create_connection(("127.0.0.1", host), timeout=2)
    assert http_body(second) == "server-one"
    run([zaigr, "project", "vm", "exec", "--", "bash", "-c", 'kill -0 "$(cat server.pid)"'])
    run([zaigr, "project", "vm", "exec", "--", "bash", "-c", 'kill "$(cat server.pid)"'])
    output = run([zaigr, "project", "host-access", "show"])
    assert "Available" in next(line for line in output.splitlines() if f"localhost:{second}" in line)


@pytest.fixture
def serial_project(host_devices, request):
    """Order teardown so QEMU closes each serial peer before its host fixture."""
    # Set up the project factory after the PTYs so its VM teardown runs first.
    return request.getfixturevalue("project_factory")()


def test_serial_devices_bytes_status_and_restart(serial_project, host_devices, setup_factory):
    """Share independent serial streams with user, root, and preset consumers."""
    project = serial_project
    run = partial(checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    stdout, stderr, code = _run(["gcc", "-static", "-O2", "-Wall", "-Werror", "-o", project.cwd / "endpoint",
                                Path(__file__).with_name("host_access_fixture") / "endpoint.c"])
    assert code == 0, err_msg(stdout, stderr)
    run([zaigr, "project", "vm", "start"], input="y\n", timeout=180)
    for _, _, alias in host_devices:
        assert "Waiting for VM restart" in run([zaigr, "project", "host-access", "allow", alias])
    # A grant added after this boot is safe to remove immediately.
    run([zaigr, "project", "host-access", "remove", host_devices[1][2]])
    run([zaigr, "project", "host-access", "allow", host_devices[1][2]])
    output = run([zaigr, "project", "host-access", "show"])
    for _, _, alias in host_devices:
        assert "Waiting for VM restart" in next(line for line in output.splitlines() if str(alias) in line)
    run([zaigr, "project", "vm", "stop"], timeout=60)
    run([zaigr, "project", "vm", "start"], timeout=120)
    output = run([zaigr, "project", "host-access", "show"])
    for i, (_, _, alias) in enumerate(host_devices):
        assert "Available" in next(line for line in output.splitlines() if str(alias) in line)
        run([zaigr, "project", "vm", "exec", "--", "bash", "-c",
             f"nohup ./endpoint watch {shlex.quote(str(alias))} /tmp/watch-{i}.sync > watch-{i}.log 2>&1 < /dev/null &"])
        wait_text(project.cwd / f"watch-{i}.log", "READY")
    for _ in range(3):
        run([zaigr, "project", "host-access", "show"])
    for i in range(2):
        run([zaigr, "project", "vm", "exec", "--", "tee", f"/tmp/watch-{i}.sync"], input="drain\n")
        assert wait_text(project.cwd / f"watch-{i}.log", "SYNC 1").strip() == "READY\nSYNC 1"
    for i, (_, _, alias) in enumerate(host_devices):
        root = ["--root"] if i == 1 else []
        run([zaigr, "project", "vm", "exec", *root, "--", "bash", "-c",
             f"nohup ./endpoint device {shlex.quote(str(alias))} serial-{i} > serial-{i}.log 2>&1 < /dev/null &"], input="y\n")
        wait_text(project.cwd / f"serial-{i}.log", "READY")
        wait_text(project.cwd / f"watch-{i}.log", "OPEN")
    output = run([zaigr, "project", "host-access", "show"])
    for i, (master, slave, alias) in enumerate(host_devices):
        assert "Attached" in next(line for line in output.splitlines() if str(alias) in line)
        assert termios.tcgetattr(slave)[4:6] == [termios.B19200, termios.B19200]
        os.write(master, f"from-host-{i}\n".encode())
        receive_peer(master, f"serial-{i}\n".encode())
        assert wait_text(project.cwd / f"serial-{i}.received", f"from-host-{i}").strip() == f"from-host-{i}"
        assert (project.cwd / f"watch-{i}.log").read_text().count("OPEN") == 1
        run([zaigr, "project", "vm", "exec", "--", "touch", f"serial-{i}.release"])
        wait_text(project.cwd / f"serial-{i}.log", "CLOSED")
        wait_text(project.cwd / f"watch-{i}.log", "CLOSE")
    output = run([zaigr, "project", "host-access", "show"])
    for _, _, alias in host_devices:
        assert "Available" in next(line for line in output.splitlines() if str(alias) in line)
        stdout, stderr, code = _run([zaigr, "project", "host-access", "remove", alias], cwd=project.cwd, env=project.env)
        assert code != 0 and "stop" in stdout + stderr
    master, _, alias = host_devices[0]
    setup_factory.preset(name="serial-consumer", setups=[],
                         run=f"exec ./endpoint device {shlex.quote(str(alias))} preset-device")
    preset = spawn_interactive(f"{shlex.quote(str(zaigr))} shell --preset serial-consumer",
                               cwd=project.cwd, env=project.env, timeout=60)
    try:
        preset.expect_exact("READY")
        output = run([zaigr, "project", "host-access", "show"])
        assert "Attached" in next(line for line in output.splitlines() if str(alias) in line)
        os.write(master, b"preset-host\n")
        receive_peer(master, b"preset-device\n")
        run([zaigr, "project", "vm", "exec", "--", "touch", "preset-device.release"])
        preset.expect_exact("CLOSED")
        preset.expect(pexpect.EOF)
        preset.close()
        assert preset.exitstatus == 0
    finally:
        if preset.isalive():
            preset.close(force=True)
    run([zaigr, "project", "vm", "stop"], timeout=60)
    for _, _, alias in host_devices:
        run([zaigr, "project", "host-access", "remove", alias])
    run([zaigr, "project", "vm", "start"], timeout=120)
    for _, _, alias in host_devices:
        stdout, stderr, code = _run([zaigr, "project", "vm", "exec", "--", "test", "-e", alias], cwd=project.cwd, env=project.env)
        assert code != 0, err_msg(stdout, stderr)
