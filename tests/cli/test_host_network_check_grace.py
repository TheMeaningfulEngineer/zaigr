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
        # A dying VM owns and may already have reaped the helper.
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

@pytest.mark.timeout(300)
def test_frozen_host_network_warns_every_command_and_recovers_without_stopping_vm(
    project, host_network_endpoints, host_network_dns
):
    """A helper frozen past every deadline blocks traffic, warns, and never stops the VM."""
    run = partial(checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    endpoint = host_network_endpoints
    in_vm = [zaigr, "project", "vm", "exec", "--"]
    fetch = in_vm + ["curl", "--noproxy", "*", "-4fsS", "--max-time", "4",
                     f"http://10.0.2.2:{endpoint['tcp_port']}/"]
    host_network_dns["resolver"].set_answer("stall.test", "93.184.216.34", 30)

    run([zaigr, "project", "vm", "start"], input="y\n", timeout=180)
    run([zaigr, "project", "firewall", "allow", "10.0.2.2"], timeout=30)
    run([zaigr, "project", "firewall", "allow", "stall.test"], timeout=30)
    assert run(fetch, timeout=20).strip() == endpoint["token"]
    boot_id = run(in_vm + ["cat", "/proc/sys/kernel/random/boot_id"], timeout=20)
    record = json.loads((project.store_dir / "vm-supervisor.json").read_text())
    assert "hostnet-helper" in record["network_processes"], record

    def warning(command=("project", "status")):
        _stdout, stderr, _code = _run([zaigr, *command], cwd=project.cwd, env=project.env, timeout=20)
        return stderr if "network has been blocked" in stderr else None

    signal_recorded_process(record, "hostnet-helper", signal.SIGSTOP, network_process=True)
    frozen_at = time.monotonic()
    try:
        wait_process_stopped(record, "hostnet-helper", network_process=True)
        # A lookup whose firewall update never finishes used to doom the VM.
        _run(in_vm + ["getent", "ahostsv4", "stall.test"],
             cwd=project.cwd, env=project.env, timeout=30)

        warned = wait_until(warning, "a warning from zaigr project status", timeout=30)
        assert "the vm is running" in warned.lower(), warned
        assert "keeps retrying" in warned, warned
        assert "zaigr project vm stop" in warned, warned
        assert "vm-supervisor.log" in warned, warned
        assert warning(("project", "firewall", "show")), "another command gave no warning"

        # Stay frozen well past the 60 seconds that used to stop the VM.
        time.sleep(max(0, 70 - (time.monotonic() - frozen_at)))
        assert warning(), "the VM should still be running and blocked"
        assert "status: running" in run([zaigr, "project", "status"], timeout=20).lower()
    finally:
        continue_recorded_process_if_alive(record, "hostnet-helper", network_process=True)

    def recovered():
        stdout, stderr, code = _run(fetch, cwd=project.cwd, env=project.env, timeout=10)
        return code == 0 and stdout.strip() == endpoint["token"] and "blocked" not in stderr

    wait_until(recovered, "the network to return without a warning", timeout=30)
    assert "93.184.216.34" in run(in_vm + ["getent", "ahostsv4", "stall.test"], timeout=20)
    assert run(in_vm + ["cat", "/proc/sys/kernel/random/boot_id"], timeout=20) == boot_id
    assert "the vm stopped at" not in (project.store_dir / "vm-supervisor.log").read_text().lower()


@pytest.mark.timeout(180)
def test_restart_advice_in_the_warning_works_while_the_helper_is_frozen(
    project, host_network_endpoints
):
    """The commands the warning recommends stop and restart a VM with a frozen helper."""
    run = partial(checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    endpoint = host_network_endpoints
    run([zaigr, "project", "vm", "start"], input="y\n", timeout=120)
    run([zaigr, "project", "firewall", "allow", "10.0.2.2"], timeout=30)
    record = json.loads((project.store_dir / "vm-supervisor.json").read_text())

    def warned():
        _stdout, stderr, _code = _run([zaigr, "project", "status"],
                                      cwd=project.cwd, env=project.env, timeout=20)
        return "network has been blocked" in stderr

    signal_recorded_process(record, "hostnet-helper", signal.SIGSTOP, network_process=True)
    try:
        wait_process_stopped(record, "hostnet-helper", network_process=True)
        wait_until(warned, "the warning that recommends a restart", timeout=30)
        started = time.monotonic()
        run([zaigr, "project", "vm", "stop"], timeout=60)
        print(f"\nRESULT vm stop took {time.monotonic() - started:.1f}s", flush=True)
    finally:
        continue_recorded_process_if_alive(record, "hostnet-helper", network_process=True)

    assert "status: not running" in run([zaigr, "project", "status"], timeout=20).lower()
    assert not warned(), "a stopped VM must not warn about its network"
    run([zaigr, "project", "vm", "start"], timeout=120)
    assert not warned(), "a restarted VM must not repeat the old warning"
    assert run([zaigr, "project", "vm", "exec", "--", "curl", "--noproxy", "*", "-4fsS",
                "--max-time", "4", f"http://10.0.2.2:{endpoint['tcp_port']}/"],
               timeout=20).strip() == endpoint["token"]
