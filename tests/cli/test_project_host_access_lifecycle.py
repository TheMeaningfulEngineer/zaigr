"""Persistence, ownership, failures, and isolation through the public CLI."""

import fcntl
import json
import os
import shlex
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from pathlib import Path

import pytest

from ..conftest import err_msg
from ..conftest import run as _run
from . import host_access_endpoints, test_project_host_access
from .host_access_endpoints import http_body, receive_peer, unused_port, wait_text
from .test_project_host_access import checked_run

host_devices = host_access_endpoints.host_devices
endpoint_binary = host_access_endpoints.endpoint_binary
small_vm = test_project_host_access.small_vm


def test_port_conflict_retries_restart_and_observer_failure(project, endpoint_binary):
    """Recover saved forwards and distinguish listener and observer failures."""
    run = partial(checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    run([zaigr, "project", "vm", "start"], input="y\n", timeout=180)
    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", 0))
        occupied.listen()
        host = occupied.getsockname()[1]
        stdout, stderr, code = _run([zaigr, "project", "host-access", "allow", host, "--vm-port", "43123"],
                                   cwd=project.cwd, env=project.env)
        assert code != 0 and "remains saved" in stdout + stderr
        output = run([zaigr, "project", "host-access", "show"])
        assert "Unavailable" in next(line for line in output.splitlines() if f"localhost:{host}" in line)
        run([zaigr, "project", "vm", "stop"], timeout=60)
        run([zaigr, "project", "vm", "start"], timeout=120)
        assert run([zaigr, "project", "vm", "exec", "--", "printf", "vm-usable"]) == "vm-usable"
        output = run([zaigr, "project", "host-access", "show"])
        assert "Unavailable" in next(line for line in output.splitlines() if f"localhost:{host}" in line)
    run([zaigr, "project", "host-access", "allow", host, "--vm-port", "43123"])
    run([zaigr, "project", "vm", "exec", "--", "bash", "-c",
         "nohup ./endpoint server 127.0.0.1 43123 loopback > loopback.log 2>&1 < /dev/null & echo $! > loopback.pid"])
    wait_text(project.cwd / "loopback.log", "READY")
    output = run([zaigr, "project", "host-access", "show"])
    assert "Available" in next(line for line in output.splitlines() if f"localhost:{host}" in line)
    assert "bind to 0.0.0.0" in output
    run([zaigr, "project", "vm", "exec", "--", "bash", "-c", 'kill "$(cat loopback.pid)"'])
    run([zaigr, "project", "vm", "exec", "--", "bash", "-c",
         "nohup ./endpoint server 0.0.0.0 43123 recovered > recovered.log 2>&1 < /dev/null &"])
    wait_text(project.cwd / "recovered.log", "READY")
    assert http_body(host) == "recovered"
    dual = unused_port()
    run([zaigr, "project", "host-access", "allow", dual, "--vm-port", "43124"])
    run([zaigr, "project", "vm", "exec", "--", "bash", "-c",
         "nohup ./endpoint server :: 43124 dual-stack > dual.log 2>&1 < /dev/null &"])
    wait_text(project.cwd / "dual.log", "READY")
    output = run([zaigr, "project", "host-access", "show"])
    assert "Attached" in next(line for line in output.splitlines() if f"localhost:{dual}" in line)
    assert http_body(dual) == "dual-stack"
    run([zaigr, "project", "vm", "exec", "--root", "--", "mv",
         "/usr/local/lib/zaigr/host-access", "/usr/local/lib/zaigr/host-access.disabled"], input="y\n")
    stdout, stderr, code = _run([zaigr, "project", "host-access", "show"], cwd=project.cwd, env=project.env, timeout=20)
    assert code != 0 and "Unknown" in stdout and f"localhost:{host}" in stdout
    assert "helper" in stderr
    run([zaigr, "project", "vm", "exec", "--root", "--", "mv",
         "/usr/local/lib/zaigr/host-access.disabled", "/usr/local/lib/zaigr/host-access"], input="y\n")
    assert http_body(host) == "recovered"


@pytest.fixture
def serial_projects(host_devices, request):
    """Create related project fixtures that stop before their PTY peers close."""
    return request.getfixturevalue("project_factory")


def test_device_ownership_aliases_concurrency_and_deletion(serial_projects, host_devices):
    """Serialize alias claims and retain ownership until deletion succeeds."""
    first, second = serial_projects("owner"), serial_projects("sibling")
    zaigr = first.zaigr_bin
    runs = [partial(checked_run, cwd=p.cwd, env=p.env) for p in (first, second)]
    for run in runs:
        run([zaigr, "project", "vm", "start"], input="y\n", timeout=180)
        run([zaigr, "project", "vm", "stop"], timeout=60)
    _, slave, alias = host_devices[0]
    other_alias = alias.with_name("same-device")
    other_alias.symlink_to(os.ttyname(slave))
    barrier = threading.Barrier(2)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(lambda p=p, path=path: (
            barrier.wait(),
            _run([zaigr, "project", "host-access", "allow", path], cwd=p.cwd, env=p.env)
        )[1]) for p, path in ((first, alias), (second, other_alias))]
        results = [future.result(timeout=20) for future in futures]
    assert sorted(result[2] for result in results) == [0, 1]
    winner = 0 if results[0][2] == 0 else 1
    loser = 1 - winner
    projects, paths = [first, second], [alias, other_alias]
    assert str(projects[winner].cwd) in results[loser][0] + results[loser][1]
    assert "reserved by" in results[loser][0] + results[loser][1]
    paths[winner].unlink()
    stdout, stderr, code = _run([zaigr, "project", "host-access", "allow", paths[loser]],
                               cwd=projects[loser].cwd, env=projects[loser].env)
    assert code != 0 and "reserved by" in stdout + stderr
    runs[winner]([zaigr, "project", "host-access", "remove", paths[winner]])
    runs[loser]([zaigr, "project", "host-access", "allow", paths[loser]])
    # Exercise deletion failure and legacy transaction recovery. This is a
    # committed replacement whose old store survived interruption of cleanup.
    store = projects[loser].store_dir
    backup = store.with_name(store.name + ".legacy-clean-transaction-old")
    runs[loser](["cp", "-al", store, backup])
    protected = store / "protected"
    protected.mkdir()
    protected.chmod(0o500)
    try:
        stdout, stderr, code = _run([zaigr, "project", "delete", "--force"],
                                   cwd=projects[loser].cwd, env=projects[loser].env)
        assert code != 0, err_msg(stdout, stderr)
        paths[winner].symlink_to(os.ttyname(slave))
        stdout, stderr, code = _run([zaigr, "project", "host-access", "allow", paths[winner]],
                                   cwd=projects[winner].cwd, env=projects[winner].env)
        assert code != 0 and "reserved by" in stdout + stderr
    finally:
        protected.chmod(0o700)
    runs[loser]([zaigr, "project", "delete", "--force"])
    assert not backup.exists()
    runs[winner]([zaigr, "project", "host-access", "allow", paths[winner]])
    # Also recover interruption immediately after the old store was renamed,
    # before any replacement directory was published.
    store = projects[winner].store_dir
    backup = store.with_name(store.name + ".legacy-clean-transaction-old")
    store.rename(backup)
    runs[winner]([zaigr, "project", "delete", "--force"])
    assert not store.exists() and not backup.exists()


def test_grants_survive_clean_rebuild_and_device_loss(serial_projects, host_devices):
    """Retain working grants across replacement images and missing devices."""
    project = serial_projects()
    run = partial(checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    stdout, stderr, code = _run(["gcc", "-static", "-O2", "-o", project.cwd / "endpoint",
                                Path(__file__).with_name("host_access_fixture") / "endpoint.c"])
    assert code == 0, err_msg(stdout, stderr)
    master, _, alias = host_devices[0]
    host = unused_port()
    run([zaigr, "project", "vm", "start"], input="y\n", timeout=180)
    run([zaigr, "project", "vm", "stop"], timeout=60)
    run([zaigr, "project", "host-access", "allow", alias])
    run([zaigr, "project", "host-access", "allow", host, "--vm-port", "43123"])
    (project.cwd / "keep-me").write_text("persistent project file\n")
    for i, command in enumerate(([zaigr, "project", "clean"], [zaigr, "project", "rebuild", "--force"])):
        run(command, input="y\n", timeout=180)
        assert (project.cwd / "keep-me").read_text() == "persistent project file\n"
        output = run([zaigr, "project", "host-access", "show"])
        assert str(alias) in output and f"localhost:{host}" in output and "VM stopped" in output
        run([zaigr, "project", "vm", "start"], timeout=120)
        run([zaigr, "project", "vm", "exec", "--", "bash", "-c",
             f"nohup ./endpoint server 0.0.0.0 43123 cycle-{i} > cycle-{i}.log 2>&1 < /dev/null &"])
        wait_text(project.cwd / f"cycle-{i}.log", "READY")
        assert http_body(host) == f"cycle-{i}"
        run([zaigr, "project", "vm", "exec", "--", "bash", "-c",
             f"nohup ./endpoint device {shlex.quote(str(alias))} cycle-device-{i} > cycle-device-{i}.log 2>&1 < /dev/null &"])
        wait_text(project.cwd / f"cycle-device-{i}.log", "READY")
        os.write(master, f"host-cycle-{i}\n".encode())
        receive_peer(master, f"cycle-device-{i}\n".encode())
        run([zaigr, "project", "vm", "exec", "--", "touch", f"cycle-device-{i}.release"])
        wait_text(project.cwd / f"cycle-device-{i}.log", "CLOSED")
        run([zaigr, "project", "vm", "stop"], timeout=60)
    alias.unlink()
    run([zaigr, "project", "vm", "start"], timeout=120)
    output = run([zaigr, "project", "host-access", "show"])
    assert "Unavailable" in next(line for line in output.splitlines() if str(alias) in line)
    assert run([zaigr, "project", "vm", "exec", "--", "printf", "still-usable"]) == "still-usable"
    run([zaigr, "project", "vm", "stop"], timeout=60)
    alias.symlink_to(os.ttyname(host_devices[1][1]))
    run([zaigr, "project", "vm", "start"], timeout=120)
    output = run([zaigr, "project", "host-access", "show"])
    assert "identity changed" in output
    run([zaigr, "project", "vm", "stop"], timeout=60)
    alias.unlink()
    run([zaigr, "project", "host-access", "remove", alias])


def test_partial_metadata_is_not_treated_as_empty(project):
    """Surface invalid saved metadata instead of rendering an empty grant set."""
    run = partial(checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    run([zaigr, "project", "vm", "start"], input="y\n", timeout=180)
    run([zaigr, "project", "vm", "stop"], timeout=60)
    # Metadata handling is the subject here: simulate an interrupted/invalid
    # external write, not device identity or transport behavior.
    path = project.store_dir / "host-access.json"
    path.write_text(json.dumps({"version": 1, "ports": []}))
    stdout, stderr, code = _run([zaigr, "project", "host-access", "show"], cwd=project.cwd, env=project.env)
    assert code != 0 and "incomplete" in stderr
    assert "(none)" not in stdout


def test_runtime_corruption_and_lock_contention_preserve_claims(serial_projects, host_devices):
    """Keep management usable and device ownership conservative on failures."""
    project = serial_projects()
    run = partial(checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    alias = host_devices[0][2]
    host = unused_port()
    run([zaigr, "project", "vm", "start"], input="y\n", timeout=180)
    run([zaigr, "project", "vm", "stop"], timeout=60)
    run([zaigr, "project", "host-access", "allow", alias])
    run([zaigr, "project", "host-access", "allow", host])
    # Hold the documented account ownership lock to model a stalled mutation.
    owner_lock = Path(project.env["HOME"]) / ".zaigr/project-locks/.host-device-owners.lock"
    with owner_lock.open("r+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        run([zaigr, "project", "vm", "start"], timeout=120)
    output = run([zaigr, "project", "host-access", "show"])
    assert "Available" in next(line for line in output.splitlines() if f"localhost:{host}" in line)
    assert "ownership is busy" in next(line for line in output.splitlines() if str(alias) in line)
    assert run([zaigr, "project", "vm", "exec", "--", "printf", "usable"]) == "usable"
    run([zaigr, "project", "vm", "stop"], timeout=60)
    run([zaigr, "project", "vm", "start"], timeout=120)
    assert "Available" in next(line for line in run([zaigr, "project", "host-access", "show"]).splitlines() if str(alias) in line)
    # Corruption handling is the subject: lose or truncate runtime bookkeeping
    # while QEMU retains the exposed device. None is evidence of a pending grant.
    metadata = project.store_dir / "runtime/host-access.json"
    intact = metadata.read_bytes()
    run([zaigr, "project", "host-access", "allow", host_devices[1][2]])
    misassociated = json.loads(intact)
    misassociated["devices"][0]["path"] = str(host_devices[1][2])
    for broken in (None, {"version": 1, "devices": [{}]}, {"version": 1, "devices": []}, misassociated):
        if broken is None:
            metadata.unlink()
        else:
            metadata.write_text(json.dumps(broken))
        stdout, stderr, code = _run([zaigr, "project", "host-access", "remove", alias], cwd=project.cwd, env=project.env)
        assert code != 0 and "stop the VM" in stdout + stderr
        stdout, stderr, code = _run([zaigr, "project", "host-access", "show"], cwd=project.cwd, env=project.env)
        assert code != 0 and str(alias) in stdout and "Unknown" in stdout
    metadata.write_bytes(intact)
    run([zaigr, "project", "vm", "exec", "--root", "--", "tee", "/var/lib/zaigr/host-access-aliases"],
        input="y\nincomplete-journal-entry\n")
    run([zaigr, "project", "vm", "stop"], timeout=60)
    run([zaigr, "project", "vm", "start"], timeout=120)
    assert run([zaigr, "project", "vm", "exec", "--", "printf", "usable-after-corruption"]) == "usable-after-corruption"


def test_sibling_ports_keep_their_own_servers_and_report_owner(project_factory):
    """Keep loopback forwards scoped to their owning VM across conflicts."""
    first, second = project_factory("port-owner"), project_factory("port-sibling")
    zaigr = first.zaigr_bin
    shared, distinct = unused_port(), unused_port()
    for project, marker in ((first, "first"), (second, "second")):
        run = partial(checked_run, cwd=project.cwd, env=project.env)
        run(["gcc", "-static", "-O2", "-o", project.cwd / "endpoint",
             Path(__file__).with_name("host_access_fixture") / "endpoint.c"])
        run([zaigr, "project", "vm", "start"], input="y\n", timeout=180)
        run([zaigr, "project", "vm", "exec", "--", "bash", "-c",
             f"nohup ./endpoint server 0.0.0.0 {shared} {marker} > server.log 2>&1 < /dev/null &"])
        wait_text(project.cwd / "server.log", "READY")
    first_run = partial(checked_run, cwd=first.cwd, env=first.env)
    second_run = partial(checked_run, cwd=second.cwd, env=second.env)
    first_run([zaigr, "project", "host-access", "allow", shared])
    second_run([zaigr, "project", "host-access", "allow", distinct, "--vm-port", shared])
    assert http_body(shared) == "first" and http_body(distinct) == "second"
    sockets = first_run(["ss", "-H", "-lnt", f"sport = :{shared}"])
    assert [line.split()[3] for line in sockets.splitlines()] == [f"127.0.0.1:{shared}"]
    stdout, stderr, code = _run([zaigr, "project", "host-access", "allow", shared], cwd=second.cwd, env=second.env)
    assert code != 0 and str(first.cwd) in stdout + stderr
    assert http_body(shared) == "first"
    second_run([zaigr, "project", "host-access", "remove", shared])
    assert http_body(shared) == "first" and http_body(distinct) == "second"
    first_run([zaigr, "global", "projects", "kill", "port-owner", "port-sibling"], timeout=120)
    with pytest.raises(ConnectionRefusedError):
        socket.create_connection(("127.0.0.1", shared), timeout=2)
    first_run([zaigr, "project", "vm", "start"], timeout=120)
    output = first_run([zaigr, "project", "host-access", "show"])
    assert "Available" in next(line for line in output.splitlines() if f"localhost:{shared}" in line)
