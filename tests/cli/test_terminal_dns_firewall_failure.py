"""Public CLI regression for terminal DNS-policy failures during firewall edits."""

import json
import signal
import time
from functools import partial
from pathlib import Path

import pytest

from ..conftest import err_msg
from ..conftest import run as _run
from .host_access_endpoints import wait_text
from .host_network_fixture.processes import signal_recorded_process


def checked_run(command, **kwargs):
    """Record a visible CLI command and return successful stdout."""
    stdout, stderr, code = _run(command, **kwargs)
    assert code == 0, err_msg(stdout, stderr)
    return stdout


def wait_until(predicate, description, timeout=20):
    """Poll a public CLI result until it reaches the expected state."""
    deadline = time.monotonic() + timeout
    observed = None
    while time.monotonic() < deadline:
        observed = predicate()
        if observed:
            return observed
        time.sleep(0.2)
    pytest.fail(f"timed out waiting for {description}; last result was {observed!r}")


def wait_process_stopped(record, name, timeout=5):
    """Wait until a supervisor-recorded helper is stopped by SIGSTOP."""
    identity = record["network_processes"][name]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            stat = Path(f"/proc/{identity['pid']}/stat").read_text()
        except FileNotFoundError:
            pytest.fail(f"recorded {name} process exited instead of stopping")
        fields = stat[stat.rfind(")") + 2 :].split()
        assert fields[19] == str(identity["start_time"]), identity
        if fields[0] in {"T", "t"}:
            return
        time.sleep(0.02)
    pytest.fail(f"recorded {name} process did not enter stopped state")


def continue_recorded_process_if_alive(record, name):
    """Resume an owned helper after a failure, if the supervisor has not reaped it."""
    identity = record["network_processes"][name]
    proc_stat = Path(f"/proc/{identity['pid']}/stat")
    try:
        fields = proc_stat.read_text().rsplit(")", 1)[1].split()
    except FileNotFoundError:
        return
    if fields[0] in {"Z", "X"}:
        return
    try:
        signal_recorded_process(record, name, signal.SIGCONT, network_process=True)
    except (ProcessLookupError, FileNotFoundError):
        try:
            fields = proc_stat.read_text().rsplit(")", 1)[1].split()
        except FileNotFoundError:
            return
        if fields[0] not in {"Z", "X"}:
            raise


@pytest.fixture(autouse=True)
def small_vm(monkeypatch):
    """Keep the acceptance VM economical."""
    monkeypatch.setenv("ZAIGR_VM_RAM", "512")
    monkeypatch.setenv("ZAIGR_VM_CPU", "1")
    monkeypatch.setenv("ZAIGR_DISK_SIZE", "8G")


@pytest.mark.timeout(420)
def test_terminal_dns_policy_failure_saves_firewall_rule_and_requires_restart(
    project, host_network_endpoints
):
    """A failed live firewall apply closes traffic, stops at 60s, and recovers on restart."""
    endpoint = host_network_endpoints
    if endpoint["private_ip"] is None:
        pytest.skip("host has no active private IPv4 address for the saved allow rule")

    run = partial(checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    baseline_url = f"http://10.0.2.2:{endpoint['tcp_port']}/"
    saved_rule_url = f"http://{endpoint['private_ip']}:{endpoint['private_tcp_port']}/"
    probe_log = project.cwd / "terminal-dns-firewall-probe.log"
    probe_script = project.cwd / "terminal-dns-firewall-probe.sh"
    probe_stop = project.cwd / "terminal-dns-firewall-probe.stop"

    run([zaigr, "project", "vm", "start"], input="y\n", timeout=180)
    run([zaigr, "project", "firewall", "allow", "10.0.2.2"], timeout=30)
    assert run([zaigr, "project", "vm", "exec", "--", "curl", "--noproxy", "*",
                "-4fsS", "--max-time", "4", baseline_url], timeout=20).strip() == endpoint["token"]
    _stdout, _stderr, code = _run(
        [zaigr, "project", "vm", "exec", "--", "curl", "--noproxy", "*",
         "-4fsS", "--max-time", "2", saved_rule_url],
        cwd=project.cwd, env=project.env, timeout=15,
    )
    assert code != 0, "private endpoint unexpectedly worked before its firewall rule was saved"

    run([zaigr, "project", "vm", "exec", "--", "rm", "-f",
         probe_log.name, probe_stop.name, probe_script.name], timeout=20)
    run([zaigr, "project", "vm", "exec", "--", "tee", probe_script.name],
        input=("#!/bin/bash\n"
               f"while [ ! -e {probe_stop.name} ]; do\n"
               f"  if curl --noproxy '*' -4fsS --max-time 2 {baseline_url} >/dev/null 2>&1; then\n"
               f"    echo ok >> {probe_log.name}\n"
               "  else\n"
               f"    echo blocked >> {probe_log.name}\n"
               "  fi\n"
               "  sleep 0.5\n"
               "done\n"), timeout=20)
    run([zaigr, "project", "vm", "exec", "--", "bash", "-c",
         f"nohup bash {probe_script.name} >/dev/null 2>&1 < /dev/null &"], timeout=20)
    wait_text(probe_log, "ok")
    probe_offset = len(probe_log.read_bytes())

    record = json.loads((project.store_dir / "vm-supervisor.json").read_text())
    assert "hostnet-helper" in record["network_processes"], record
    helper_pause_started = time.monotonic()
    signal_recorded_process(record, "hostnet-helper", signal.SIGSTOP, network_process=True)
    try:
        wait_process_stopped(record, "hostnet-helper")
        # This public operation first saves the exact IP rule, then fails at
        # live policy reconciliation while the host helper is frozen.
        stdout, stderr, code = _run(
            [zaigr, "project", "firewall", "allow", endpoint["private_ip"]],
            cwd=project.cwd, env=project.env, timeout=20,
        )
        failure = stdout + stderr
        assert code != 0, failure
        assert "couldn't confirm the saved firewall policy" in failure.lower(), failure
        assert "terminal host dns policy failure:" in failure.lower(), failure
        assert "context deadline exceeded" in failure.lower(), failure
        assert "network access is being blocked" in failure.lower(), failure
        assert "network access is being blocked (within 10 seconds)" in failure.lower(), failure
        assert "vm will stop within 60 seconds" in failure.lower(), failure
        assert "your saved firewall rules will be applied when you start the vm again" in failure.lower(), failure

        # The probe was running before the fault, so this records a real
        # fail-closed transition while the VM itself remains alive.
        status = run([zaigr, "project", "status"], timeout=20)
        assert "status: running" in status.lower(), status
        deadline = time.monotonic() + 20
        probe_during_failure = ""
        while time.monotonic() < deadline:
            probe_during_failure = probe_log.read_bytes()[probe_offset:].decode()
            if "blocked\n" in probe_during_failure:
                break
            time.sleep(0.2)
        assert "ok\n" in probe_during_failure, probe_during_failure
        assert "blocked\n" in probe_during_failure, probe_during_failure
        status = run([zaigr, "project", "status"], timeout=20)
        assert "status: running" in status.lower(), status
    finally:
        continue_recorded_process_if_alive(record, "hostnet-helper")

    # Resuming DNS does not clear the terminal policy failure: existing guest
    # traffic remains blocked until the supervisor has stopped the VM.
    post_resume_offset = len(probe_log.read_bytes())
    deadline = time.monotonic() + 5
    post_resume_probe = ""
    while time.monotonic() < deadline:
        post_resume_probe = probe_log.read_bytes()[post_resume_offset:].decode()
        if "blocked\n" in post_resume_probe:
            break
        time.sleep(0.2)
    assert "blocked\n" in post_resume_probe, post_resume_probe
    assert "ok\n" not in post_resume_probe, post_resume_probe
    saved = run([zaigr, "project", "firewall", "show"], timeout=20)
    assert endpoint["private_ip"] in saved, saved
    assert "status: saved; application to the running project VM is pending or unconfirmed" in saved

    stopped = wait_until(
        lambda: (output if "status: not running" in (output := run(
            [zaigr, "project", "status"], timeout=20
        ).lower()) else None),
        "the VM to stop after 60 seconds of terminal DNS-policy failure",
        timeout=75,
    )
    assert "status: not running" in stopped
    stopped_after = time.monotonic() - helper_pause_started
    assert stopped_after >= 59, (
        "VM stopped before the 60-second grace elapsed from helper pause "
        f"({stopped_after:.1f}s)"
    )
    supervisor_log = (project.store_dir / "vm-supervisor.log").read_text().lower()
    assert "terminal host dns policy failure:" in supervisor_log
    assert "context deadline exceeded" in supervisor_log
    assert "network access is being blocked" in supervisor_log
    assert "vm will stop within 60 seconds" in supervisor_log

    stdout, stderr, code = _run(
        [zaigr, "project", "vm", "start"],
        cwd=project.cwd, env=project.env, timeout=180,
    )
    startup_output = stdout + stderr
    assert code == 0, err_msg(stdout, stderr)
    assert "the vm stopped at" in startup_output.lower(), startup_output
    assert "terminal host dns policy failure:" in startup_output.lower()
    assert "context deadline exceeded" in startup_output.lower()
    assert run([zaigr, "project", "vm", "exec", "--", "curl", "--noproxy", "*",
                "-4fsS", "--max-time", "4", saved_rule_url], timeout=20).strip() == endpoint["token"]
    assert run([zaigr, "project", "vm", "exec", "--", "curl", "--noproxy", "*",
                "-4fsS", "--max-time", "4", baseline_url], timeout=20).strip() == endpoint["token"]
    run([zaigr, "project", "vm", "exec", "--", "touch", probe_stop.name], timeout=20)
