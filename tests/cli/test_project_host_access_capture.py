"""Capture VMs and reusable setups do not inherit host resource grants."""

import re
import shlex
import socket
from functools import partial
from pathlib import Path

import pexpect
import pytest

from ..conftest import err_msg, spawn_interactive
from ..conftest import run as _run
from . import (
    host_access_endpoints,
    test_project_host_access,
    test_project_host_access_lifecycle,
)
from .host_access_endpoints import unused_port
from .test_project_host_access import checked_run

host_devices = host_access_endpoints.host_devices
serial_projects = test_project_host_access_lifecycle.serial_projects
small_vm = test_project_host_access.small_vm


@pytest.mark.parametrize("attached", [False, True])
def test_capture_and_reusable_setup_isolate_host_grants(serial_projects, host_devices, attached):
    """Keep shares in their authorized runtime without granting setup consumers."""
    owner, consumer = serial_projects("owner"), serial_projects("consumer")
    run = partial(checked_run, cwd=owner.cwd, env=owner.env)
    zaigr = owner.zaigr_bin
    alias = host_devices[0][2]
    host = unused_port()
    run([zaigr, "project", "vm", "start"], input="y\n", timeout=180)
    run([zaigr, "project", "vm", "stop"], timeout=60)
    run([zaigr, "project", "host-access", "allow", alias])
    run([zaigr, "project", "host-access", "allow", host])
    if attached:
        run([zaigr, "project", "vm", "start"], timeout=120)
    capture = spawn_interactive(f"{shlex.quote(str(zaigr))} project setup capture start",
                                cwd=owner.cwd, env=owner.env, timeout=180)
    accepted = None
    try:
        if attached:
            capture.expect_exact("[y/N]")
            capture.sendline("y")
        capture.expect(r"root@[^:]+:.*# ")
        # This observes the active capture session; vm exec intentionally
        # refuses to run while capture is active.
        capture.sendline(f"if test -c {shlex.quote(str(alias))}; then printf 'device-present\\n'; else printf 'device-absent\\n'; fi")
        capture.expect_exact("\rdevice-present\r\n" if attached else "\rdevice-absent\r\n")
        capture.expect(r"root@[^:]+:.*# ")
        if not attached:
            with pytest.raises(ConnectionRefusedError):
                socket.create_connection(("127.0.0.1", host), timeout=2)
        capture.sendline("printf 'capture-content\\n' > /etc/host-access-capture-test")
        capture.expect(r"root@[^:]+:.*# ")
        capture.sendline("exit")
        capture.expect(pexpect.EOF, timeout=30)
        capture.close()
        assert capture.exitstatus == 0
        run([zaigr, "project", "setup", "capture", "review"])
        accepted = run([zaigr, "project", "setup", "capture", "accept"], timeout=180)
    finally:
        if accepted is None:
            _run([zaigr, "project", "setup", "capture", "discard"], cwd=owner.cwd,
                 env=owner.env, input="y\n", timeout=60)
        if capture.isalive():
            capture.close(force=True)
    setup_path = Path(re.search(r"Updated setup definition: (.+)", accepted).group(1))
    destination = consumer.cwd / ".zaigr/setups"
    run(["mkdir", "-p", destination])
    run(["cp", "-r", setup_path, destination / setup_path.name])
    consume = partial(checked_run, cwd=consumer.cwd, env=consumer.env)
    consume([zaigr, "project", "setup", "run", setup_path.name], input="y\n", timeout=180)
    consume([zaigr, "project", "vm", "start"], timeout=180)
    assert consume([zaigr, "project", "vm", "exec", "--", "cat", "/etc/host-access-capture-test"]) == "capture-content\n"
    assert consume([zaigr, "project", "host-access", "show"]).count("(none)") == 2
    stdout, stderr, code = _run([zaigr, "project", "vm", "exec", "--", "test", "-e", alias],
                               cwd=consumer.cwd, env=consumer.env)
    assert code == 1, err_msg(stdout, stderr)
    run([zaigr, "project", "vm", "start"], timeout=120)
    output = run([zaigr, "project", "host-access", "show"])
    assert f"localhost:{host}" in output and str(alias) in output
    assert "Available" in next(line for line in output.splitlines() if str(alias) in line)
