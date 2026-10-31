"""Outer-VM freeze coverage; a separate controller sends SIGSTOP/SIGCONT."""

import json
import os
import re
import shlex
import time
import uuid
from pathlib import Path

import pexpect
import pytest

from tests.conftest import run, spawn_interactive

from .stress_resources import (
    assert_resource_growth_bounded,
    assert_stopped_resources_gone,
    sample_resources,
    summarize_samples,
)


def _checked(command, project, timeout=30, input=None):
    stdout, stderr, code = run(
        command, cwd=project.cwd, env=project.env, input=input, timeout=timeout
    )
    assert code == 0, f"command failed ({code}): {command}\n{stdout}\n{stderr}"
    return stdout


def _await_resume(control_path, token, timeout):
    ack_path = Path(str(control_path) + ".ack")
    deadline = time.monotonic() + timeout
    last_ack = "<not read>"
    while time.monotonic() < deadline:
        try:
            ack_text = ack_path.read_text(encoding="utf-8")
            last_ack = ack_text
            ack = json.loads(ack_text)
        except (OSError, ValueError):
            time.sleep(0.5)
            continue
        if ack.get("token") == token and ack.get("phase") == "resumed":
            return ack
        time.sleep(0.5)
    raise AssertionError(
        f"outer freeze controller did not confirm resume in {timeout}s; "
        f"expected token={token}, control_path={control_path}, "
        f"last_ack={last_ack}"
    )


@pytest.mark.stress
@pytest.mark.parametrize("freeze_seconds", [120, 900])
@pytest.mark.timeout(40 * 60)
def test_vm_sessions_survive_outer_host_freeze(
    project_factory, freeze_seconds, record_property, monkeypatch
):
    """Existing sessions, running exec, and a separate idle VM survive freeze."""
    control_path = os.environ.get("ZAIGR_STRESS_SUSPEND_CONTROL")
    if not control_path:
        pytest.skip("requires external verified QEMU SIGSTOP/SIGCONT controller")
    control_path = Path(control_path)
    if not control_path.is_absolute():
        raise AssertionError("ZAIGR_STRESS_SUSPEND_CONTROL must be an absolute path")
    tiny = os.environ.get("ZAIGR_STRESS_TINY") == "1"
    actual_freeze_seconds = (
        (2 if freeze_seconds == 120 else 3) if tiny else freeze_seconds
    )
    sleep_seconds = 6 if tiny else 600
    main_boot_id = os.environ.get("ZAIGR_STRESS_MAIN_BOOT_ID")
    if not main_boot_id:
        raise AssertionError("ZAIGR_STRESS_MAIN_BOOT_ID is required for boot identity checks")
    monkeypatch.setenv("ZAIGR_VM_RAM", "512")
    monkeypatch.setenv("ZAIGR_VM_CPU", "1")
    monkeypatch.setenv("ZAIGR_DISK_SIZE", "8G")

    active = project_factory("suspend-active")
    idle = project_factory("suspend-idle")
    for project in (active, idle):
        _checked(
            [project.zaigr_bin, "project", "vm", "start"],
            project,
            timeout=180,
            input="y\n",
        )

    samples = [sample_resources([active, idle])]
    idle_launch_id = samples[0]["projects"][1]["launch_id"]
    assert idle_launch_id, "idle project supervisor did not record a VM launch"

    shells = []
    exec_session = None
    summary_written = False
    freeze_started = None
    try:
        for _ in range(2):
            shell = spawn_interactive(
                f"{shlex.quote(str(active.zaigr_bin))} shell",
                cwd=active.cwd,
                env=active.env,
                timeout=180,
            )
            shells.append(shell)
            shell.expect(r"\$ ", timeout=180)
            shell.sendline("printf 'SHELL_BEFORE_FREEZE\\n'")
            shell.expect(r"SHELL_BEFORE_FREEZE\r?\n", timeout=20)
            shell.expect(r"\$ ", timeout=20)

        exec_session = spawn_interactive(
            f"{shlex.quote(str(active.zaigr_bin))} project vm exec -- sh -c "
            + shlex.quote(
                f"echo EXEC_SLEEP_STARTED; sleep {sleep_seconds}; echo EXEC_SLEEP_COMPLETED"
            ),
            cwd=active.cwd,
            env=active.env,
            timeout=actual_freeze_seconds + sleep_seconds + 100,
        )
        exec_session.expect_exact("EXEC_SLEEP_STARTED", timeout=60)

        token = uuid.uuid4().hex
        control_path.parent.mkdir(parents=True, exist_ok=True)
        freeze_started = time.monotonic()
        temporary_control_path = control_path.with_name(
            control_path.name + "." + token + ".tmp"
        )
        temporary_control_path.write_text(
            json.dumps(
                {
                    "token": token,
                    "duration": actual_freeze_seconds,
                    "phase": "ready",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        os.replace(temporary_control_path, control_path)
        ack = _await_resume(control_path, token, actual_freeze_seconds + 180)
        freeze_elapsed = time.monotonic() - freeze_started
        assert not ack.get("cancelled", False), "outer freeze controller was cancelled early"
        assert ack.get("elapsed", 0) >= actual_freeze_seconds, (
            f"controller resumed early: {ack}"
        )
        assert ack.get("main_boot_id") == main_boot_id, (
            f"developer VM boot ID changed during freeze: {ack}"
        )

        for shell in shells:
            shell.sendline("printf 'SHELL_AFTER_FREEZE\\n'")
            shell.expect(r"SHELL_AFTER_FREEZE\r?\n", timeout=30)
            shell.expect(r"\$ ", timeout=30)
            shell.sendline("exit")
            shell.expect(pexpect.EOF, timeout=30)
            shell.close()
            assert shell.exitstatus == 0, "open shell ended unsuccessfully after resume"

        opened = spawn_interactive(
            f"{shlex.quote(str(active.zaigr_bin))} shell",
            cwd=active.cwd,
            env=active.env,
            timeout=30,
        )
        shells.append(opened)
        opened.expect(r"\$ ", timeout=20)
        opened.sendline("printf 'NEW_SHELL_OK\\n'")
        opened.expect(r"NEW_SHELL_OK\r?\n", timeout=20)
        opened.expect(r"\$ ", timeout=20)
        opened.sendline("exit")
        opened.expect(pexpect.EOF, timeout=20)
        opened.close()
        assert opened.exitstatus == 0, "new shell did not work immediately after resume"

        active_status = _checked([active.zaigr_bin, "project", "status"], active)
        assert re.search(
            r"(?m)^  status: running \(vsock CID [0-9]+\)$", active_status
        ), active_status
        idle_after = sample_resources([idle])
        samples.append(sample_resources([active, idle]))
        assert samples[-1]["projects"][1]["launch_id"] == idle_launch_id
        assert idle_after["projects"][0]["processes"], (
            "idle VM stopped during outer freeze"
        )
        idle_output = _checked(
            [idle.zaigr_bin, "project", "vm", "exec", "--", "printf", "IDLE_VM_OK"],
            idle,
        )
        assert "IDLE_VM_OK" in idle_output
        exec_session.expect_exact("EXEC_SLEEP_COMPLETED", timeout=sleep_seconds + 60)
        exec_session.expect(pexpect.EOF, timeout=30)
        exec_session.close()
        assert exec_session.exitstatus == 0, "vm exec did not return success after resume"
        samples.append(sample_resources([active, idle]))
        samples.append(
            sample_resources([active, idle], include_network_inventory=True)
        )
        _checked([active.zaigr_bin, "project", "vm", "stop"], active, timeout=90)
        _checked([idle.zaigr_bin, "project", "vm", "stop"], idle, timeout=90)
        samples.append(sample_resources([active, idle]))
        for project in (active, idle):
            restart_output = _checked(
                [project.zaigr_bin, "project", "vm", "start"],
                project,
                timeout=180,
                input="y\n",
            )
            assert "the vm stopped" not in restart_output.lower(), restart_output
        samples.append(
            sample_resources([active, idle], include_network_inventory=True)
        )
        _checked([active.zaigr_bin, "project", "vm", "stop"], active, timeout=90)
        _checked([idle.zaigr_bin, "project", "vm", "stop"], idle, timeout=90)
        samples.append(sample_resources([active, idle]))
        summary = summarize_samples(
            "host-suspend",
            samples,
            [freeze_elapsed],
            1,
            extra={
                "requested_freeze_seconds": actual_freeze_seconds,
                "host_boot_id_stable": samples[0]["boot_id"] == samples[-1]["boot_id"],
                "main_boot_id_before": main_boot_id,
                "main_boot_id_after": ack["main_boot_id"],
                "outer_boot_id_before": samples[0]["boot_id"],
                "outer_boot_id_after": samples[-1]["boot_id"],
            },
        )
        record_property("stress_summary", json.dumps(summary, sort_keys=True))
        summary_written = True
        assert_stopped_resources_gone(samples)
        assert summary["host_boot_id_stable"], (
            "outer host boot ID changed during freeze"
        )
        assert_resource_growth_bounded(samples)
    finally:
        if exec_session is not None and exec_session.isalive():
            exec_session.close(force=True)
        for shell in shells:
            if shell.isalive():
                shell.close(force=True)
        if not summary_written:
            samples.append(sample_resources([active, idle]))
            summary = summarize_samples(
                "host-suspend",
                samples,
                [time.monotonic() - freeze_started] if freeze_started else [],
                1,
                extra={"incomplete": True},
            )
            record_property("stress_summary", json.dumps(summary, sort_keys=True))
