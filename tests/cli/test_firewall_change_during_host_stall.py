"""Public CLI regression for firewall edits made while the host network is frozen."""

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


@pytest.mark.timeout(300)
def test_firewall_changes_made_during_a_freeze_land_when_the_helper_returns(
    project, host_network_endpoints
):
    """A frozen helper closes traffic, keeps the VM, and applies saved rules when it resumes."""
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

    in_vm = [zaigr, "project", "vm", "exec", "--"]
    fetch_saved = in_vm + ["curl", "--noproxy", "*", "-4fsS", "--max-time", "2", saved_rule_url]
    boot_id = run(in_vm + ["cat", "/proc/sys/kernel/random/boot_id"], timeout=20)
    record = json.loads((project.store_dir / "vm-supervisor.json").read_text())
    assert "hostnet-helper" in record["network_processes"], record

    def saved_rule_reachable():
        stdout, _stderr, code = _run(fetch_saved, cwd=project.cwd, env=project.env, timeout=10)
        return code == 0 and stdout.strip() == endpoint["token"]

    def change_while_frozen(*command):
        """Run a firewall change with the helper frozen and expect a saved, pending result."""
        signal_recorded_process(record, "hostnet-helper", signal.SIGSTOP, network_process=True)
        try:
            wait_process_stopped(record, "hostnet-helper")
            stdout, stderr, code = _run(
                [zaigr, "project", "firewall", *command],
                cwd=project.cwd, env=project.env, timeout=20,
            )
            result = (stdout + stderr).lower()
            assert code != 0, result
            assert "saved" in result, result
            assert "keeps retrying" in result, result
            assert "status: running" in run([zaigr, "project", "status"], timeout=20).lower()

            # The probe was running before the fault, so this records a real
            # fail-closed transition while the VM itself remains alive.
            offset = len(probe_log.read_bytes())
            deadline = time.monotonic() + 20
            during = ""
            while time.monotonic() < deadline and "blocked\n" not in during:
                during = probe_log.read_bytes()[offset:].decode()
                time.sleep(0.2)
            assert "blocked\n" in during, during
            assert "status: running" in run([zaigr, "project", "status"], timeout=20).lower()
        finally:
            continue_recorded_process_if_alive(record, "hostnet-helper")

    change_while_frozen("allow", endpoint["private_ip"])
    assert endpoint["private_ip"] in run([zaigr, "project", "firewall", "show"], timeout=20)
    wait_until(saved_rule_reachable, "the saved rule to land without a restart", timeout=30)
    assert run(in_vm + ["curl", "--noproxy", "*", "-4fsS", "--max-time", "4", baseline_url],
               timeout=20).strip() == endpoint["token"]

    # A removal is the change that must not be lost.
    change_while_frozen("remove", endpoint["private_ip"])
    wait_until(lambda: not saved_rule_reachable(), "the removed rule to stop working", timeout=30)

    assert run(in_vm + ["cat", "/proc/sys/kernel/random/boot_id"], timeout=20) == boot_id
    assert "the vm stopped at" not in (project.store_dir / "vm-supervisor.log").read_text().lower()
    run(in_vm + ["touch", probe_stop.name], timeout=20)
