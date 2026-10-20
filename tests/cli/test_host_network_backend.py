"""Public CLI acceptance for host-enforced VM networking."""

import json
import signal
import socket
import time
from functools import partial

import pytest

from ..conftest import err_msg
from ..conftest import run as _run
from .host_access_endpoints import http_body, unused_port, wait_text
from .host_network_fixture.processes import signal_recorded_process


def checked_run(command, **kwargs):
    """Record a visible CLI command and return successful stdout."""
    stdout, stderr, code = _run(command, **kwargs)
    assert code == 0, err_msg(stdout, stderr)
    return stdout


def blocked_result(command, **kwargs):
    """Require a real network failure and reject an endpoint response."""
    stdout, stderr, code = _run(command, **kwargs)
    assert code != 0, err_msg(stdout, stderr)
    assert "hostnet-endpoint-" not in stdout
    assert "hostnet-endpoint-" not in stderr
    diagnostic = (stdout + stderr).lower()
    assert any(term in diagnostic for term in (
        "timed out", "failed to connect", "connection refused", "no route to host", "network is unreachable",
    )), diagnostic
    return stdout + stderr


def wait_until(predicate, description, timeout=20):
    """Poll a visible user-facing status check until its predicate is true."""
    deadline = time.monotonic() + timeout
    observed = None
    while time.monotonic() < deadline:
        observed = predicate()
        if observed:
            return observed
        time.sleep(0.1)
    pytest.fail(f"timed out waiting for {description}; last status was {observed!r}")


@pytest.fixture(autouse=True)
def small_vm(monkeypatch):
    """Keep independent host-network acceptance VMs economical."""
    monkeypatch.setenv("ZAIGR_VM_RAM", "512")
    monkeypatch.setenv("ZAIGR_VM_CPU", "1")
    monkeypatch.setenv("ZAIGR_DISK_SIZE", "8G")



@pytest.mark.timeout(300)
def test_guest_resolves_localhost_to_loopback(project):
    """Programs that listen on "localhost" work although the guest has no /etc/hosts."""
    run = partial(checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    run([zaigr, "project", "vm", "start"], input="y\n", timeout=180)
    answers = run([
        zaigr, "project", "vm", "exec", "--", "bash", "-c",
        "getent ahostsv4 localhost; getent ahostsv6 localhost; getent ahostsv4 app.localhost",
    ], timeout=30)
    assert "127.0.0.1" in answers and "::1" in answers, answers
    assert answers.count("127.0.0.1") >= 2, answers


@pytest.mark.timeout(420)
def test_host_network_keeps_ssh_and_project_forwarding_available(project, endpoint_binary):
    """Use the normal VM SSH command path and a real loopback host forward."""
    run = partial(checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    host_port = unused_port()
    run([zaigr, "project", "vm", "start"],
        input="y\n", timeout=180)

    runtime_components = run([
        zaigr, "project", "vm", "exec", "--", "bash", "-c",
        ("if command -v opensnitchd >/dev/null 2>&1; then exit 1; fi; "
         "if command -v zaigr-inside >/dev/null 2>&1; then exit 1; fi; "
         "if systemctl list-unit-files --no-legend opensnitch.service "
         "| grep -q '^opensnitch.service'; then exit 1; fi; "
         "printf 'host-managed-runtime-only\\n'")
    ], timeout=30)
    assert runtime_components == "host-managed-runtime-only\n", runtime_components

    # vm exec uses the project's normal SSH management path after host networking starts.
    assert run([zaigr, "project", "vm", "exec", "--", "printf", "ssh-ready"], timeout=30) == "ssh-ready"
    run([zaigr, "project", "vm", "exec", "--", "bash", "-c",
         ("nohup ./endpoint server 0.0.0.0 43123 hostnet-forward "
          "> hostnet-forward.log 2>&1 < /dev/null &")], timeout=20)
    wait_text(project.cwd / "hostnet-forward.log", "READY")

    run([zaigr, "project", "host-access", "allow", str(host_port), "--vm-port", "43123"], timeout=30)
    assert http_body(host_port) == "hostnet-forward"

    # The persisted forward is rebuilt with the VM; it remains on loopback and
    # still reaches a guest listener after a normal stop/start.
    run([zaigr, "project", "vm", "stop"], timeout=60)
    run([zaigr, "project", "vm", "start"], timeout=180)
    run([zaigr, "project", "vm", "exec", "--", "bash", "-c",
         ("nohup ./endpoint server 0.0.0.0 43123 hostnet-forward "
          "> hostnet-forward.log 2>&1 < /dev/null &")], timeout=20)
    wait_text(project.cwd / "hostnet-forward.log", "READY")
    assert http_body(host_port) == "hostnet-forward"

    # Remove stops new connections, while an already established TCP flow may
    # finish. Wait until the guest accepted the connection before removing.
    peer = socket.create_connection(("127.0.0.1", host_port), timeout=3)
    peer.settimeout(3)
    wait_text(project.cwd / "hostnet-forward.log", "ACCEPTED")
    run([zaigr, "project", "host-access", "remove", str(host_port)], timeout=30)
    peer.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
    response = bytearray()
    while True:
        chunk = peer.recv(4096)
        if not chunk:
            break
        response.extend(chunk)
    peer.close()
    assert bytes(response).split(b"\r\n\r\n", 1)[1].decode() == "hostnet-forward"
    with pytest.raises(ConnectionRefusedError):
        http_body(host_port)


@pytest.mark.parametrize("process_name", ["hostnet-helper", "slirp4netns", "host-dns-frontend"])
@pytest.mark.timeout(300)
def test_host_network_stops_vm_when_owned_network_process_dies(project, host_network_endpoints, process_name):
    """Fail closed when an exact recorded helper, uplink, or DNS PID exits."""
    run = partial(checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    endpoint = host_network_endpoints
    stream_url = f"http://10.0.2.2:{endpoint['tcp_port']}/stream"
    stream_log = project.cwd / f"hostnet-{process_name}.log"

    run([zaigr, "project", "vm", "start"],
        input="y\n", timeout=180)
    run([zaigr, "project", "firewall", "allow", "10.0.2.2"], timeout=30)
    assert run([zaigr, "project", "vm", "exec", "--", "curl", "--noproxy", "*",
                "-4fsS", "--max-time", "4", f"http://10.0.2.2:{endpoint['tcp_port']}/"],
               timeout=20).strip() == endpoint["token"]
    run([zaigr, "project", "vm", "exec", "--", "bash", "-c",
         (f"nohup curl --noproxy '*' -4fsSN --max-time 120 {stream_url} "
          f"> {stream_log.name} 2>&1 < /dev/null &")], timeout=20)
    wait_text(stream_log, endpoint["token"])

    record = json.loads((project.store_dir / "vm-supervisor.json").read_text())
    assert process_name in record["network_processes"], record
    signal_recorded_process(record, process_name, signal.SIGKILL, network_process=True)
    wait_until(
        lambda: "status: not running" in checked_run(
            [zaigr, "project", "status"], cwd=project.cwd, env=project.env
        ).lower(),
        "project status to report not running after owned process death",
    )

    received = len(stream_log.read_bytes())
    pushes = endpoint["request_counts"]()["stream_pushes"]
    time.sleep(0.5)
    assert endpoint["request_counts"]()["stream_pushes"] > pushes
    assert len(stream_log.read_bytes()) == received


@pytest.mark.timeout(300)
def test_host_network_supervisor_death_closes_network_and_vm(project, host_network_endpoints):
    """A SIGKILL to the recorded supervisor also closes its owned uplink."""
    run = partial(checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    endpoint = host_network_endpoints
    stream_url = f"http://10.0.2.2:{endpoint['tcp_port']}/stream"
    stream_log = project.cwd / "hostnet-supervisor-death.log"

    run([zaigr, "project", "vm", "start"],
        input="y\n", timeout=180)
    run([zaigr, "project", "firewall", "allow", "10.0.2.2"], timeout=30)
    assert run([zaigr, "project", "vm", "exec", "--", "curl", "--noproxy", "*",
                "-4fsS", "--max-time", "4", f"http://10.0.2.2:{endpoint['tcp_port']}/"],
               timeout=20).strip() == endpoint["token"]
    run([zaigr, "project", "vm", "exec", "--", "bash", "-c",
         (f"nohup curl --noproxy '*' -4fsSN --max-time 120 {stream_url} "
          f"> {stream_log.name} 2>&1 < /dev/null &")], timeout=20)
    wait_text(stream_log, endpoint["token"])

    record = json.loads((project.store_dir / "vm-supervisor.json").read_text())
    signal_recorded_process(record, "supervisor", signal.SIGKILL)
    wait_until(
        lambda: "not running" in checked_run(
            [zaigr, "project", "status"], cwd=project.cwd, env=project.env
        ).lower(),
        "project status to report not running after supervisor death",
    )

    received = len(stream_log.read_bytes())
    pushes = endpoint["request_counts"]()["stream_pushes"]
    time.sleep(0.5)
    assert endpoint["request_counts"]()["stream_pushes"] > pushes
    assert len(stream_log.read_bytes()) == received


@pytest.mark.timeout(300)
def test_host_network_liveness_expiry_drops_old_flow_and_keeps_exact_grant(
    project, host_network_endpoints
):
    """Expiring the owner liveness gate drops old flows while exact grants survive."""
    run = partial(checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    endpoint = host_network_endpoints
    stream_url = f"http://10.0.2.2:{endpoint['tcp_port']}/stream"
    stream_log = project.cwd / "hostnet-liveness-expiry.log"

    run([zaigr, "project", "vm", "start"], input="y\n", timeout=180)
    run([zaigr, "project", "firewall", "allow", "10.0.2.2"], timeout=30)
    run([zaigr, "project", "vm", "exec", "--", "bash", "-c",
         (f"nohup curl --noproxy '*' -4fsSN --max-time 120 {stream_url} "
          f"> {stream_log.name} 2>&1 < /dev/null &")], timeout=20)
    wait_text(stream_log, endpoint["token"])

    record = json.loads((project.store_dir / "vm-supervisor.json").read_text())
    signal_recorded_process(record, "supervisor", signal.SIGSTOP)
    try:
        time.sleep(11)
        quiet_length = len(stream_log.read_bytes())
        pushes = endpoint["request_counts"]()["stream_pushes"]
        time.sleep(0.5)
        assert len(stream_log.read_bytes()) == quiet_length
        assert endpoint["request_counts"]()["stream_pushes"] > pushes
    finally:
        signal_recorded_process(record, "supervisor", signal.SIGCONT)

    # The persistent IP grant remains usable after renewal resumes, but the
    # pre-expiry TCP connection never resumes with it.
    fresh = run([zaigr, "project", "vm", "exec", "--", "curl", "--noproxy", "*",
                 "-4fsS", "--max-time", "4",
                 f"http://10.0.2.2:{endpoint['tcp_port']}/"], timeout=20)
    assert fresh.strip() == endpoint["token"]
    time.sleep(0.5)
    assert len(stream_log.read_bytes()) == quiet_length
