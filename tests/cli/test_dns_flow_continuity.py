"""Established DNS flows outlive answer TTLs, but never explicit revocation."""

import os
import shlex
import signal
import time

import pytest

from .host_network_fixture.processes import open_supervisor_pidfd
from .host_network_fixture.public_site import public_address
from .test_full_network import checked_run, stream_goes_quiet, stream_grows


@pytest.fixture(autouse=True)
def small_vm(monkeypatch):
    monkeypatch.setenv("ZAIGR_VM_RAM", "512")
    monkeypatch.setenv("ZAIGR_VM_CPU", "1")
    monkeypatch.setenv("ZAIGR_DISK_SIZE", "8G")


@pytest.mark.timeout(240)
def test_dns_refresh_outage_preserves_existing_flow_and_blocks_new_flows(
    project, host_network_dns, public_http_stream_client
):
    zaigr = project.zaigr_bin
    resolver = host_network_dns["resolver"]
    checked_run([zaigr, "project", "vm", "start"], cwd=project.cwd, env=project.env,
                input="y\n", timeout=180)
    address = public_address("deb.debian.org")
    resolver.set_answer("outage.test", address, 5)
    checked_run([zaigr, "project", "firewall", "allow", "outage.test"],
                cwd=project.cwd, env=project.env)
    assert address in checked_run(
        [zaigr, "project", "vm", "exec", "--", "getent", "ahostsv4", "outage.test"],
        cwd=project.cwd, env=project.env,
    )
    stream = project.cwd / "outage-stream.log"
    checked_run(
        [zaigr, "project", "vm", "exec", "--", "bash", "-c",
         (f"nohup timeout 180 ./{shlex.quote(public_http_stream_client.name)} {address} 80 "
         "/debian/dists/trixie/main/binary-amd64/Packages.xz "
         f"> {stream.name} 2>&1 < /dev/null &")],
        cwd=project.cwd, env=project.env,
    )
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline and not (stream.exists() and stream.stat().st_size > 1024):
        time.sleep(0.05)
    assert stream.exists() and stream.read_bytes().startswith(b"HTTP/1.1 200 OK")
    queries = resolver.count("outage.test")
    resolver.drop_replies("outage.test")
    time.sleep(12)
    assert resolver.count("outage.test") > queries
    assert stream_grows(stream, 4), "DNS refresh failure stopped an admitted connection"
    denied = checked_run(
        [zaigr, "project", "vm", "exec", "--", "bash", "-c",
         (f"if curl --noproxy '*' -4fsS --connect-timeout 3 --max-time 5 "
         f"--resolve outage.test:80:{address} -H 'Host: deb.debian.org' "
         "-o /dev/null http://outage.test/debian/dists/trixie/Release; "
         "then echo UNEXPECTED_ACCESS; else echo NEW_FLOW_BLOCKED; fi")],
        cwd=project.cwd, env=project.env,
    )
    assert "NEW_FLOW_BLOCKED" in denied and "UNEXPECTED_ACCESS" not in denied
    assert stream_grows(stream, 4)
    checked_run([zaigr, "project", "firewall", "remove", "outage.test"],
                cwd=project.cwd, env=project.env)
    assert stream_goes_quiet(stream, 8)
    stopped_length = stream.stat().st_size
    resolver.drop_replies("outage.test", False)
    checked_run([zaigr, "project", "firewall", "allow", "outage.test"],
                cwd=project.cwd, env=project.env)
    assert address in checked_run(
        [zaigr, "project", "vm", "exec", "--", "getent", "ahostsv4", "outage.test"],
        cwd=project.cwd, env=project.env,
    )
    checked_run(
        [zaigr, "project", "vm", "exec", "--", "curl", "--noproxy", "*", "-4fsS",
         "--connect-timeout", "4", "--max-time", "12", "--resolve",
         f"outage.test:80:{address}", "-H", "Host: deb.debian.org", "-o", "/dev/null",
         "http://outage.test/debian/dists/trixie/Release"],
        cwd=project.cwd, env=project.env,
    )
    time.sleep(2)
    assert stream.stat().st_size == stopped_length, "regrant resumed the revoked stream"


@pytest.mark.timeout(240)
def test_manual_flow_can_transfer_to_a_later_dns_permission(
    project, host_network_dns, public_http_stream_client
):
    zaigr = project.zaigr_bin
    checked_run([zaigr, "project", "vm", "start"], cwd=project.cwd, env=project.env,
                input="y\n", timeout=180)
    address = public_address("deb.debian.org")
    host_network_dns["resolver"].set_answer("handoff.test", address, 30)
    checked_run([zaigr, "project", "firewall", "allow", address],
                cwd=project.cwd, env=project.env)
    stream = project.cwd / "handoff-stream.log"
    checked_run(
        [zaigr, "project", "vm", "exec", "--", "bash", "-c",
         (f"nohup timeout 180 ./{shlex.quote(public_http_stream_client.name)} {address} 80 "
         "/debian/dists/trixie/main/binary-amd64/Packages.xz "
         f"> {stream.name} 2>&1 < /dev/null &")],
        cwd=project.cwd, env=project.env,
    )
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline and not (stream.exists() and stream.stat().st_size > 1024):
        time.sleep(0.05)
    assert stream.exists() and stream.read_bytes().startswith(b"HTTP/1.1 200 OK")
    checked_run([zaigr, "project", "firewall", "allow", "handoff.test"],
                cwd=project.cwd, env=project.env)
    assert address in checked_run(
        [zaigr, "project", "vm", "exec", "--", "getent", "ahostsv4", "handoff.test"],
        cwd=project.cwd, env=project.env,
    )
    assert stream_grows(stream, 4), "the manual connection stopped before removing its grant"
    checked_run([zaigr, "project", "firewall", "remove", address],
                cwd=project.cwd, env=project.env)
    assert stream_grows(stream, 4), "removing the manual grant lost a live DNS reference"
    checked_run([zaigr, "project", "firewall", "remove", "handoff.test"],
                cwd=project.cwd, env=project.env)
    assert stream_goes_quiet(stream, 8), "the final permission did not revoke the flow"


@pytest.mark.timeout(240)
def test_dns_flow_does_not_resume_after_network_liveness_expires(
    project, host_network_dns, public_http_stream_client
):
    zaigr = project.zaigr_bin
    checked_run([zaigr, "project", "vm", "start"], cwd=project.cwd, env=project.env,
                input="y\n", timeout=180)
    address = public_address("deb.debian.org")
    host_network_dns["resolver"].set_answer("liveness.test", address, 60)
    checked_run([zaigr, "project", "firewall", "allow", "liveness.test"],
                cwd=project.cwd, env=project.env)
    assert address in checked_run(
        [zaigr, "project", "vm", "exec", "--", "getent", "ahostsv4", "liveness.test"],
        cwd=project.cwd, env=project.env,
    )
    stream = project.cwd / "dns-liveness-stream.log"
    checked_run(
        [zaigr, "project", "vm", "exec", "--", "bash", "-c",
         (f"nohup timeout 180 ./{shlex.quote(public_http_stream_client.name)} {address} 80 "
          "/debian/dists/trixie/main/binary-amd64/Packages.xz "
          f"> {stream.name} 2>&1 < /dev/null &")],
        cwd=project.cwd, env=project.env,
    )
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline and not (stream.exists() and stream.stat().st_size > 1024):
        time.sleep(0.05)
    assert stream.exists() and stream.read_bytes().startswith(b"HTTP/1.1 200 OK")
    supervisor = open_supervisor_pidfd(project)
    try:
        signal.pidfd_send_signal(supervisor, signal.SIGSTOP)
        time.sleep(11)
        assert stream_goes_quiet(stream, 8), "DNS continuation bypassed the liveness gate"
        stopped_length = stream.stat().st_size
    finally:
        try:
            signal.pidfd_send_signal(supervisor, signal.SIGCONT)
        finally:
            os.close(supervisor)
    # The saved domain still permits a fresh connection once the supervisor
    # renews liveness, but its old conntrack entry must have been purged.
    time.sleep(3)
    checked_run(
        [zaigr, "project", "vm", "exec", "--", "curl", "--noproxy", "*", "-4fsS",
         "--connect-timeout", "4", "--max-time", "12", "--resolve",
         f"liveness.test:80:{address}", "-H", "Host: deb.debian.org", "-o", "/dev/null",
         "http://liveness.test/debian/dists/trixie/Release"],
        cwd=project.cwd, env=project.env,
    )
    time.sleep(2)
    assert stream.stat().st_size == stopped_length, "liveness renewal revived the old DNS flow"
