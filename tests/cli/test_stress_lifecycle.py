"""Repeated lifecycle and concurrent-session acceptance under the stress marker."""

import concurrent.futures
import json
import os
import shlex
import statistics
import time

import pexpect
import pytest

from ..conftest import err_msg, spawn_interactive
from ..conftest import run as _run
from .stress_resources import (
    assert_resource_growth_bounded,
    assert_stopped_resources_gone,
    sample_resources,
    summarize_samples,
)

USER_PROMPT = r"user@[^:]+:.*[$] "


def _checked_run(project, command, **kwargs):
    stdout, stderr, rc = _run(command, cwd=project.cwd, env=project.env, **kwargs)
    assert rc == 0, err_msg(stdout, stderr)
    return stdout


def _tiny_mode():
    return os.environ.get("ZAIGR_STRESS_TINY") == "1"


def _assert_no_stop_notice(output):
    unexpected = [line for line in output.splitlines() if line.startswith(":: The VM stopped")]
    assert not unexpected, output


@pytest.mark.stress
@pytest.mark.timeout(7200)
def test_stress_start_stop_churn_and_shells(project, monkeypatch, request):
    """Repeated public start/exec/stop and interactive shell workflows leave no resources."""
    monkeypatch.setenv("ZAIGR_VM_RAM", "512")
    monkeypatch.setenv("ZAIGR_VM_CPU", "1")
    monkeypatch.setenv("ZAIGR_DISK_SIZE", "8G")
    cycles = 2 if _tiny_mode() else 50
    shell_cycles = 2 if _tiny_mode() else 20
    samples = []
    starts = []
    timings = []
    shell_samples = []
    summary_state = {"completed": False}
    zaigr = project.zaigr_bin

    def publish_summary():
        extra = {
            "start_seconds_median": statistics.median(starts) if starts else None,
            "start_seconds_worst": max(starts) if starts else None,
            "completed": summary_state["completed"],
        }
        summary = summarize_samples(
            "start-stop-churn", samples, timings, cycles + shell_cycles, extra
        )
        request.node.user_properties.append(("stress_summary", json.dumps(summary)))

    request.addfinalizer(publish_summary)

    for cycle in range(1, cycles + 1):
        started = time.monotonic()
        start_began = time.monotonic()
        start_output = _checked_run(
            project, [zaigr, "project", "vm", "start"], input="y\n", timeout=180
        )
        if cycle > 1:
            _assert_no_stop_notice(start_output)
        starts.append(time.monotonic() - start_began)
        samples.append(sample_resources([project]))
        output = _checked_run(
            project,
            [zaigr, "project", "vm", "exec", "--", "printf", f"lifecycle-{cycle}"],
            timeout=90,
        )
        assert output == f"lifecycle-{cycle}", output
        before_stop = sample_resources([project], include_network_inventory=True)
        samples.append(before_stop)
        stop_command = [zaigr, "project", "vm", "stop"]
        if cycle % 5 == 0 or (_tiny_mode() and cycle == 2):
            stop_command.append("--abrupt")
        stop_stdout, stop_stderr, stop_rc = _run(
            stop_command, cwd=project.cwd, env=project.env, timeout=90
        )
        assert stop_rc == 0, err_msg(stop_stdout, stop_stderr)
        after_stop = sample_resources([project])
        assert_stopped_resources_gone([before_stop, after_stop])
        samples.append(after_stop)
        timings.append(time.monotonic() - started)

    # Keep one VM running while each public interactive shell is opened and exited.
    start_began = time.monotonic()
    start_output = _checked_run(
        project, [zaigr, "project", "vm", "start"], input="y\n", timeout=180
    )
    _assert_no_stop_notice(start_output)
    starts.append(time.monotonic() - start_began)
    shell_samples.append(sample_resources([project]))
    for cycle in range(1, shell_cycles + 1):
        began = time.monotonic()
        shell = spawn_interactive(
            shlex.quote(str(zaigr)) + " shell", cwd=project.cwd, env=project.env, timeout=30
        )
        request.addfinalizer(lambda shell=shell: shell.close(force=True) if shell.isalive() else None)
        shell.expect(USER_PROMPT, timeout=90)
        shell.sendline(f"printf 'STRESS_SHELL_MARKER_{cycle}\\n'")
        shell.expect(rf"STRESS_SHELL_MARKER_{cycle}\r?\n", timeout=30)
        shell.expect(USER_PROMPT, timeout=30)
        shell.sendline("exit")
        shell.expect(pexpect.EOF, timeout=30)
        timings.append(time.monotonic() - began)
        shell.close()
        assert shell.exitstatus == 0
        shell_sample = sample_resources([project])
        samples.append(shell_sample)
        shell_samples.append(shell_sample)

    assert_resource_growth_bounded(shell_samples)
    before_stop = sample_resources([project], include_network_inventory=True)
    stop_stdout, stop_stderr, stop_rc = _run(
        [zaigr, "project", "vm", "stop"], cwd=project.cwd, env=project.env, timeout=90
    )
    assert stop_rc == 0, err_msg(stop_stdout, stop_stderr)
    after_stop = sample_resources([project])
    assert_stopped_resources_gone([before_stop, after_stop])
    samples.extend([before_stop, after_stop])

    restart_output = _checked_run(
        project,
        [project.zaigr_bin, "project", "vm", "start"],
        input="y\n",
        timeout=180,
    )
    _assert_no_stop_notice(restart_output)
    assert _checked_run(
        project,
        [project.zaigr_bin, "project", "vm", "exec", "--", "printf", "PARALLEL_VM_RESTARTED"],
        timeout=45,
    ) == "PARALLEL_VM_RESTARTED"
    restart_before_stop = sample_resources([project], include_network_inventory=True)
    restart_stop_stdout, restart_stop_stderr, restart_stop_rc = _run(
        [project.zaigr_bin, "project", "vm", "stop"],
        cwd=project.cwd,
        env=project.env,
        timeout=90,
    )
    assert restart_stop_rc == 0, err_msg(restart_stop_stdout, restart_stop_stderr)
    restart_after_stop = sample_resources([project])
    assert_stopped_resources_gone([restart_before_stop, restart_after_stop])
    samples.extend([restart_before_stop, restart_after_stop])
    boot_ids = {snapshot["boot_id"] for snapshot in samples if snapshot["boot_id"]}
    assert len(boot_ids) == 1, f"outer host boot ID changed during lifecycle stress: {boot_ids}"
    summary_state["completed"] = True


def _run_parallel_session(project, command, mode, expected, timeout):
    stdout, stderr, rc = _run(command, cwd=project.cwd, env=project.env, timeout=timeout + 45)
    assert rc == 0, err_msg(stdout, stderr)
    if mode == "output":
        assert stdout == expected and len(stdout) == 10485760
    else:
        assert stdout == expected, stdout


@pytest.mark.stress
@pytest.mark.timeout(2400)
def test_stress_parallel_sessions(project, monkeypatch, request):
    """Concurrent exec streams and shells complete their full workload across rounds."""
    monkeypatch.setenv("ZAIGR_VM_RAM", "512")
    monkeypatch.setenv("ZAIGR_VM_CPU", "1")
    monkeypatch.setenv("ZAIGR_DISK_SIZE", "8G")
    tiny = _tiny_mode()
    rounds = 2 if tiny else 5
    sessions = 3 if tiny else 30
    shell_count = 2 if tiny else 10
    sleep_seconds = 2 if tiny else 60
    _checked_run(project, [project.zaigr_bin, "project", "vm", "start"], input="y\n", timeout=180)
    samples = [sample_resources([project])]
    round_timings = []
    summary_state = {"completed": False}

    def publish_summary():
        summary = summarize_samples(
            "parallel-sessions", samples, round_timings, rounds,
            {"exec_sessions_per_round": sessions, "interactive_shells_per_round": shell_count,
             "sleep_seconds": sleep_seconds, "completed": summary_state["completed"]},
        )
        request.node.user_properties.append(("stress_summary", json.dumps(summary)))

    request.addfinalizer(publish_summary)

    for round_number in range(1, rounds + 1):
        began = time.monotonic()
        if tiny:
            workload_types = [(1, "short"), (2, "output"), (3, "sleep")]
        else:
            workload_types = [
                (index, ("short", "output", "sleep")[(index - 1) % 3])
                for index in range(1, sessions + 1)
            ]
        workloads = []
        for index, mode in workload_types:
            if mode == "short":
                workloads.append((
                    [project.zaigr_bin, "project", "vm", "exec", "--", "printf", f"short-{index}"],
                    mode, f"short-{index}", sleep_seconds,
                ))
            elif mode == "output":
                workloads.append((
                    [project.zaigr_bin, "project", "vm", "exec", "--", "bash", "-c",
                     "head -c 10485760 /dev/zero | tr '\\000' x"],
                    mode, "x" * 10485760, sleep_seconds,
                ))
            else:
                workloads.append((
                    [project.zaigr_bin, "project", "vm", "exec", "--", "sleep", str(sleep_seconds)],
                    mode, "", sleep_seconds,
                ))
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(workloads)) as executor:
            futures = [executor.submit(_run_parallel_session, project, command, mode, expected, timeout)
                       for command, mode, expected, timeout in workloads]
            for future in concurrent.futures.as_completed(futures, timeout=sleep_seconds + 180):
                future.result()
        shells = []
        try:
            for _ in range(shell_count):
                shell = spawn_interactive(
                    shlex.quote(str(project.zaigr_bin)) + " shell",
                    cwd=project.cwd,
                    env=project.env,
                    timeout=45,
                )
                shells.append(shell)
            for shell in shells:
                shell.expect(USER_PROMPT, timeout=120)
            for index, shell in enumerate(shells, 1):
                shell.sendline(f"printf 'STRESS_PARALLEL_SHELL_MARKER_{index}\\n'")
            for index, shell in enumerate(shells, 1):
                shell.expect(rf"STRESS_PARALLEL_SHELL_MARKER_{index}\r?\n", timeout=45)
                shell.expect(USER_PROMPT, timeout=45)
            for shell in shells:
                shell.sendline("exit")
            for shell in shells:
                shell.expect(pexpect.EOF, timeout=45)
                shell.close()
                assert shell.exitstatus == 0
        finally:
            for shell in shells:
                if shell.isalive():
                    shell.close(force=True)
        round_timings.append(time.monotonic() - began)
        samples.append(sample_resources([project]))

    assert_resource_growth_bounded(samples)
    before_stop = sample_resources([project], include_network_inventory=True)
    stop_stdout, stop_stderr, stop_rc = _run(
        [project.zaigr_bin, "project", "vm", "stop"], cwd=project.cwd, env=project.env, timeout=90
    )
    assert stop_rc == 0, err_msg(stop_stdout, stop_stderr)
    after_stop = sample_resources([project])
    assert_stopped_resources_gone([before_stop, after_stop])
    samples.extend([before_stop, after_stop])
    boot_ids = {snapshot["boot_id"] for snapshot in samples if snapshot["boot_id"]}
    assert len(boot_ids) == 1, f"outer host boot ID changed during parallel-session stress: {boot_ids}"
    summary_state["completed"] = True
