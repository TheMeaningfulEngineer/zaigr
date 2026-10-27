"""Public CLI acceptance for slow host-network checks."""

import json
import signal
import time
from functools import partial
from pathlib import Path

import pexpect
import pytest

from ..conftest import err_msg, spawn_interactive
from ..conftest import run as _run
from .host_access_endpoints import wait_text
from .host_network_fixture.processes import signal_recorded_process


def checked_run(command, **kwargs):
    """Record a visible CLI command and return successful stdout."""
    stdout, stderr, code = _run(command, **kwargs)
    assert code == 0, err_msg(stdout, stderr)
    return stdout


def wait_until(predicate, description, timeout=20):
    """Poll a visible CLI result until it reaches the expected state."""
    deadline = time.monotonic() + timeout
    observed = None
    while time.monotonic() < deadline:
        observed = predicate()
        if observed:
            return observed
        time.sleep(0.1)
    pytest.fail(f"timed out waiting for {description}; last result was {observed!r}")


def wait_process_stopped(record, name, network_process=False, timeout=5):
    """Wait until the recorded owned process is observably stopped by SIGSTOP."""
    identity = record["network_processes"][name] if network_process else record[name]
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


def continue_recorded_process_if_alive(record, name, network_process=False):
    """Resume the recorded process if it remains alive after the fault."""
    identity = record["network_processes"][name] if network_process else record[name]
    proc_stat = Path(f"/proc/{identity['pid']}/stat")
    try:
        fields = proc_stat.read_text().rsplit(")", 1)[1].split()
    except FileNotFoundError:
        return
    if fields[0] in {"Z", "X"}:
        return
    try:
        signal_recorded_process(record, name, signal.SIGCONT, network_process)
    except (ProcessLookupError, FileNotFoundError):
        # The 60-second failure path owns and may already have reaped the helper.
        try:
            fields = proc_stat.read_text().rsplit(")", 1)[1].split()
        except FileNotFoundError:
            return
        if fields[0] not in {"Z", "X"}:
            raise


@pytest.fixture(autouse=True)
def small_vm(monkeypatch):
    """Keep independent host-network acceptance VMs economical."""
    monkeypatch.setenv("ZAIGR_VM_RAM", "512")
    monkeypatch.setenv("ZAIGR_VM_CPU", "1")
    monkeypatch.setenv("ZAIGR_DISK_SIZE", "8G")


@pytest.mark.timeout(360)
def test_paused_host_network_helper_preserves_vm_then_fails_closed_and_recovers(
    project, host_network_endpoints
):
    """Short stalls preserve sessions; expired liveness drops old flows and recovers."""
    run = partial(checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    endpoint = host_network_endpoints
    stream_log = project.cwd / "host-network-check-grace-stream.log"
    stream_url = f"http://10.0.2.2:{endpoint['tcp_port']}/stream"

    run([zaigr, "project", "vm", "start"], input="y\n", timeout=180)
    run([zaigr, "project", "firewall", "allow", "10.0.2.2"], timeout=30)
    assert run([zaigr, "project", "vm", "exec", "--", "curl", "--noproxy", "*",
                "-4fsS", "--max-time", "4",
                f"http://10.0.2.2:{endpoint['tcp_port']}/"], timeout=20).strip() == endpoint["token"]
    run([zaigr, "project", "vm", "exec", "--", "bash", "-c",
         (f"nohup curl --noproxy '*' -4fsSN --max-time 180 {stream_url} "
          f"> {stream_log.name} 2>&1 < /dev/null &")], timeout=20)
    wait_text(stream_log, endpoint["token"])

    # Keep one actual SSH shell open across the helper stall.
    shell = spawn_interactive(
        f"{zaigr} shell", cwd=project.cwd, env=project.env, timeout=90
    )
    try:
        shell.expect(r"user@[^:]+:.*[$] ", timeout=60)
        record = json.loads((project.store_dir / "vm-supervisor.json").read_text())
        assert "hostnet-helper" in record["network_processes"], record
        stream_before = len(stream_log.read_bytes())
        # Let a two-second loop interval pass with the helper available. The
        # public CLI exposes no successful-renewal timestamp to synchronize on.
        time.sleep(2.2)

        signal_recorded_process(
            record, "hostnet-helper", signal.SIGSTOP, network_process=True
        )
        try:
            wait_process_stopped(record, "hostnet-helper", network_process=True)
            stream_during_stall = len(stream_log.read_bytes())
            pushes_during_stall = endpoint["request_counts"]()["stream_pushes"]
            time.sleep(6)
            stream_after_stall = len(stream_log.read_bytes())
            assert stream_after_stall > stream_during_stall
            assert endpoint["request_counts"]()["stream_pushes"] > pushes_during_stall
        finally:
            continue_recorded_process_if_alive(
                record, "hostnet-helper", network_process=True
            )

        stream_after_resume = len(stream_log.read_bytes())
        time.sleep(1)
        assert len(stream_log.read_bytes()) > stream_after_resume
        # Split the marker so terminal command echo cannot satisfy the check.
        shell.sendline("printf 'existing-'; printf 'ssh-session-survived\\n'")
        shell.expect_exact("existing-ssh-session-survived", timeout=15)
        assert stream_after_stall > stream_before
        status = run([zaigr, "project", "status"], timeout=20)
        assert "status: running" in status.lower(), status

        # Let the same helper remain stopped beyond the 10-second liveness TTL.
        record = json.loads((project.store_dir / "vm-supervisor.json").read_text())
        probe_log = project.cwd / "host-network-check-grace-probe.log"
        probe_stop = project.cwd / "host-network-check-grace-probe.stop"
        probe_script = project.cwd / "host-network-check-grace-probe.sh"
        run([zaigr, "project", "vm", "exec", "--", "rm", "-f",
             probe_log.name, probe_stop.name, probe_script.name], timeout=20)
        run([zaigr, "project", "vm", "exec", "--", "tee", probe_script.name],
            input=("#!/bin/bash\n"
                   "while [ ! -e host-network-check-grace-probe.stop ]; do\n"
                   f"  if curl --noproxy '*' -4fsS --max-time 2 "
                   f"http://10.0.2.2:{endpoint['tcp_port']}/ >/dev/null 2>&1; then\n"
                   "    echo ok >> host-network-check-grace-probe.log\n"
                   "  else\n"
                   "    echo blocked >> host-network-check-grace-probe.log\n"
                   "  fi\n"
                   "  sleep 0.5\n"
                   "done\n"), timeout=20)
        run([zaigr, "project", "vm", "exec", "--", "bash", "-c",
             f"nohup bash {probe_script.name} >/dev/null 2>&1 < /dev/null &"], timeout=20)
        wait_text(probe_log, "ok")
        probe_offset = len(probe_log.read_bytes())
        assert run([zaigr, "project", "vm", "exec", "--", "curl", "--noproxy", "*",
                    "-4fsS", "--max-time", "4",
                    f"http://10.0.2.2:{endpoint['tcp_port']}/"], timeout=20).strip() == endpoint["token"]
        time.sleep(2.2)
        signal_recorded_process(
            record, "hostnet-helper", signal.SIGSTOP, network_process=True
        )
        try:
            wait_process_stopped(record, "hostnet-helper", network_process=True)
            time.sleep(20)
            probe_during_stall = probe_log.read_bytes()[probe_offset:].decode()
            assert "ok\n" in probe_during_stall, probe_during_stall
            assert "blocked\n" in probe_during_stall, probe_during_stall
            stream_when_closed = len(stream_log.read_bytes())
        finally:
            continue_recorded_process_if_alive(
                record, "hostnet-helper", network_process=True
            )

        status = wait_until(
            lambda: (output if "status: running" in (output := run(
                [zaigr, "project", "status"], timeout=20
            ).lower()) else None),
            "project status to remain running after a 20-second helper stall",
        )
        assert "status: running" in status
        fresh = None
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and fresh != endpoint["token"]:
            stdout, _stderr, code = _run(
                [zaigr, "project", "vm", "exec", "--", "curl", "--noproxy", "*",
                 "-4fsS", "--max-time", "4",
                 f"http://10.0.2.2:{endpoint['tcp_port']}/"],
                cwd=project.cwd, env=project.env, timeout=10,
            )
            if code == 0:
                fresh = stdout.strip()
            if fresh != endpoint["token"]:
                time.sleep(0.1)
        assert fresh == endpoint["token"]
        time.sleep(0.5)
        assert len(stream_log.read_bytes()) == stream_when_closed
        run([zaigr, "project", "vm", "exec", "--", "touch", probe_stop.name], timeout=20)
    finally:
        if shell.isalive():
            shell.sendline("exit")
            shell.expect(pexpect.EOF, timeout=10)
        shell.close()

@pytest.mark.timeout(420)
def test_host_network_checks_stopping_vm_after_continuous_failure_is_reported(project):
    """A 60-second helper stall stops the VM and reports the failed check."""
    run = partial(checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    run([zaigr, "project", "vm", "start"], input="y\n", timeout=180)
    record = json.loads((project.store_dir / "vm-supervisor.json").read_text())
    assert "hostnet-helper" in record["network_processes"], record

    signal_recorded_process(
        record, "hostnet-helper", signal.SIGSTOP, network_process=True
    )
    try:
        wait_process_stopped(record, "hostnet-helper", network_process=True)
        time.sleep(66)
    finally:
        continue_recorded_process_if_alive(record, "hostnet-helper", network_process=True)

    stopped = wait_until(
        lambda: (output if "status: not running" in (output := run(
            [zaigr, "project", "status"], timeout=20
        ).lower()) else None),
        "project status to report stopped after 60 seconds of failed checks",
        timeout=15,
    )
    assert "status: not running" in stopped

    supervisor_log = (project.store_dir / "vm-supervisor.log").read_text()
    assert "host network checks failed for 60 s" in supervisor_log.lower()
    assert "renew host network liveness gate" in supervisor_log.lower()

    stdout, stderr, code = _run(
        [zaigr, "project", "vm", "start"],
        cwd=project.cwd, env=project.env, timeout=180,
    )
    startup_output = stdout + stderr
    assert code == 0, err_msg(stdout, stderr)
    assert "the vm stopped at" in startup_output.lower(), startup_output
    assert "host network checks failed for 60 s" in startup_output.lower(), startup_output
    assert "renew host network liveness gate" in startup_output.lower(), startup_output
