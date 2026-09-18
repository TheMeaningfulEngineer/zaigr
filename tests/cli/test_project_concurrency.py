"""Public CLI coverage for project operation concurrency."""

import shlex
import time
from functools import partial
from pathlib import Path

import pexpect
import pytest

from ..conftest import err_msg, spawn_interactive
from ..conftest import run as _run

USER_PROMPT = r"user@[^:]+:.*[$] "
ROOT_PROMPT = r"root@[^:]+:.*# "
ROOT_DIRTY_CONFIRM_PROMPT = r"Continue with root shell\? \[y/N\]"


def _checked_run(cmd, **kwargs):
    stdout, stderr, rc = _run(cmd, **kwargs)
    assert rc == 0, err_msg(stdout, stderr)
    return stdout


def _blocked_setup_script(marker):
    """Hold fixture work until the host removes its workspace barrier file."""
    return f"""
barrier=
for workspace in /home/user/workspace /workspace; do
    if [ -f "$workspace/.zaigr-test-barrier" ]; then
        barrier="$workspace/.zaigr-test-barrier"
        break
    fi
done
test -n "$barrier"
printf '{marker}\\n'
timeout 180 sh -c 'while test -e "$1"; do sleep 0.1; done' sh "$barrier"
"""


def test_lock_conflict_reports_holder_pid_and_invocation(project):
    """A legacy lock without an operation marker still identifies its holder."""
    zaigr = project.zaigr_bin
    stdout, stderr, rc = _run(
        f"{zaigr} misc test-helpers project-store-dir",
        cwd=project.cwd,
        env=project.env,
        timeout=10,
    )
    assert rc == 0, err_msg(stdout, stderr)
    project_hash = Path(stdout.strip()).name
    lock_dir = project.home / ".zaigr" / "project-locks"
    lock_dir.mkdir(parents=True, exist_ok=True)
    lock_path = lock_dir / f"{project_hash}.lock"

    holder = spawn_interactive(
        shlex.join([
            "flock",
            "--no-fork",
            "--exclusive",
            str(lock_path),
            "bash",
            "-c",
            "exec -a 'zaigr shell --preset legacy' sleep 30",
        ]),
        cwd=project.cwd,
        env=project.env,
    )
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if lock_path.exists():
                locks = _checked_run(
                    ["lslocks", "--pid", str(holder.pid), "-o", "PID,PATH"],
                    cwd=project.cwd,
                    env=project.env,
                    timeout=5,
                )
                if str(lock_path) in locks:
                    break
            time.sleep(0.05)
        else:
            raise AssertionError("external project lock was not acquired")

        stdout, stderr, rc = _run(
            f"{zaigr} project status",
            cwd=project.cwd,
            env=project.env,
            timeout=10,
        )
        assert rc != 0, err_msg(stdout, stderr)
        message = stdout + stderr
        assert f"PID {holder.pid}" in message
        assert "zaigr shell --preset legacy" in message
    finally:
        try:
            if holder.isalive():
                _checked_run(
                    ["kill", "-TERM", str(holder.pid)],
                    cwd=project.cwd,
                    env=project.env,
                    timeout=5,
                )
                holder.expect(pexpect.EOF, timeout=5)
        finally:
            holder.close(force=True)
        assert not holder.isalive()
        _checked_run(
            ["flock", "--exclusive", "--nonblock", lock_path, "true"],
            cwd=project.cwd,
            env=project.env,
            timeout=5,
        )


@pytest.mark.timeout(300)
def test_setup_run_allows_documented_commands_but_serializes_setup_and_vm_stop(
    project, setup_factory
):
    """A live setup permits inspection, exec, and shells while blocking conflicts."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    setup_factory(
        setup_name="concurrent-setup",
        script_content=_blocked_setup_script("SETUP_CONCURRENCY_READY")
        + "printf 'setup-finished\\n' > /etc/zaigr-concurrent-setup\n",
    )
    barrier = project.cwd / ".zaigr-test-barrier"
    barrier.touch()

    run(f"{zaigr} project vm start", input="y\n", timeout=180)

    setup = spawn_interactive(
        f"{zaigr} project setup run concurrent-setup",
        cwd=project.cwd,
        env=project.env,
        timeout=180,
    )
    try:
        setup.expect(r"SETUP_CONCURRENCY_READY", timeout=60)

        status = run(f"{zaigr} project status", timeout=20)
        assert "status: running" in status

        setup_list = run(f"{zaigr} project setup list", timeout=20)
        assert "applied" in setup_list

        executed = run(
            f"{zaigr} project vm exec -- printf 'EXEC_DURING_SETUP\\n'",
            timeout=20,
        )
        assert executed.strip() == "EXEC_DURING_SETUP"

        shell = spawn_interactive(
            f"{zaigr} shell",
            cwd=project.cwd,
            env=project.env,
            timeout=60,
        )
        shell.expect(USER_PROMPT)
        shell.sendline("printf 'SHELL_DURING_SETUP\\n'")
        shell.expect(r"SHELL_DURING_SETUP")
        shell.expect(USER_PROMPT)

        stdout, stderr, rc = _run(
            f"{zaigr} project setup run concurrent-setup --force",
            cwd=project.cwd,
            env=project.env,
            timeout=20,
        )
        assert rc != 0, err_msg(stdout, stderr)
        assert "project setup run concurrent-setup is running in another terminal" in (
            stdout + stderr
        )

        stdout, stderr, rc = _run(
            f"{zaigr} project vm stop",
            cwd=project.cwd,
            env=project.env,
            timeout=20,
        )
        assert rc != 0, err_msg(stdout, stderr)
        assert "project setup run concurrent-setup is running in another terminal" in (
            stdout + stderr
        )

        barrier.unlink()
        setup.expect(pexpect.EOF, timeout=60)
        setup.close()
        assert setup.exitstatus == 0

        shell.sendline("printf 'SHELL_AFTER_SETUP\\n'")
        shell.expect(r"SHELL_AFTER_SETUP")
        shell.expect(USER_PROMPT)
        shell.sendline("exit")
        shell.expect(pexpect.EOF)
        shell.close()
        assert shell.exitstatus == 0
    finally:
        barrier.unlink(missing_ok=True)
        if "shell" in locals() and shell.isalive():
            shell.close(force=True)
        if setup.isalive():
            setup.close(force=True)


@pytest.mark.timeout(300)
def test_multiple_root_shells_keep_each_others_network_access(project):
    """Concurrent root shells retain independent temporary firewall access."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    run(f"{zaigr} project vm start", input="y\n", timeout=180)

    first = spawn_interactive(
        f"{zaigr} shell --root",
        cwd=project.cwd,
        env=project.env,
        timeout=120,
    )
    second = None
    try:
        first.expect(ROOT_DIRTY_CONFIRM_PROMPT)
        first.sendline("y")
        first.expect(ROOT_PROMPT)

        second = spawn_interactive(
            f"{zaigr} shell --root",
            cwd=project.cwd,
            env=project.env,
            timeout=120,
        )
        second.expect(ROOT_DIRTY_CONFIRM_PROMPT)
        second.sendline("y")
        second.expect(ROOT_PROMPT)

        first.sendline("printf 'ROOT_ONE_ACTIVE\\n'")
        first.expect(r"ROOT_ONE_ACTIVE")
        first.expect(ROOT_PROMPT)
        second.sendline("printf 'ROOT_TWO_ACTIVE\\n'")
        second.expect(r"ROOT_TWO_ACTIVE")
        second.expect(ROOT_PROMPT)

        stdout, stderr, rc = _run(
            f"{zaigr} project setup capture start",
            cwd=project.cwd,
            env=project.env,
            timeout=20,
        )
        assert rc != 0, err_msg(stdout, stderr)
        assert "a root shell is running in another terminal" in stdout + stderr

        second.sendline("exit")
        second.expect(pexpect.EOF)
        second.close()
        assert second.exitstatus == 0

        first.sendline(
            "curl -4 -fsS --connect-timeout 5 --max-time 15 "
            "http://deb.debian.org >/dev/null; "
            "printf '\\nROOT_NETWORK_STATUS:%s\\n' \"$?\""
        )
        first.expect(r"\r?\nROOT_NETWORK_STATUS:0\r?\n", timeout=30)
        first.expect(ROOT_PROMPT)
        first.sendline("exit")
        first.expect(pexpect.EOF)
        first.close()
        assert first.exitstatus == 0
    finally:
        if second is not None and second.isalive():
            second.close(force=True)
        if first.isalive():
            first.close(force=True)


@pytest.mark.timeout(300)
def test_capture_starts_with_existing_user_shell_and_rejects_new_operations(project):
    """Capture leaves an existing user shell alive and closes entry to new operations."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    run(f"{zaigr} project vm start", input="y\n", timeout=180)

    shell = spawn_interactive(
        f"{zaigr} shell",
        cwd=project.cwd,
        env=project.env,
        timeout=120,
    )
    capture = None
    try:
        shell.expect(USER_PROMPT)
        capture = spawn_interactive(
            f"{zaigr} project setup capture start",
            cwd=project.cwd,
            env=project.env,
            timeout=120,
        )
        capture.expect(r"A project VM is already running\.")
        capture.expect(r"Continue\? \[y/N\]")
        capture.sendline("y")
        capture.expect(ROOT_PROMPT, timeout=60)

        shell.sendline("printf 'EXISTING_SHELL_STILL_OPEN\\n'")
        shell.expect(r"EXISTING_SHELL_STILL_OPEN")
        shell.expect(USER_PROMPT)

        stdout, stderr, rc = _run(
            f"{zaigr} shell",
            cwd=project.cwd,
            env=project.env,
            timeout=20,
        )
        assert rc != 0, err_msg(stdout, stderr)
        assert "project setup capture is active" in stdout + stderr

        stdout, stderr, rc = _run(
            f"{zaigr} project status",
            cwd=project.cwd,
            env=project.env,
            timeout=20,
        )
        assert rc != 0, err_msg(stdout, stderr)
        assert "project setup capture is active" in stdout + stderr

        review = run(f"{zaigr} project setup capture review", timeout=20)
        assert "setup capture:" in review

        discarded = run(
            f"{zaigr} project setup capture discard",
            timeout=30,
        )
        assert "discarded setup capture" in discarded.lower()

        capture.sendline("exit")
        capture.expect(pexpect.EOF)
        shell.sendline("exit")
        shell.expect(pexpect.EOF)
    finally:
        if capture is not None and capture.isalive():
            capture.close(force=True)
        if shell.isalive():
            shell.close(force=True)


@pytest.mark.timeout(300)
def test_rebuild_blocks_every_project_command_while_replacing_image(
    project, setup_factory
):
    """A host-side rebuild identifies itself to rejected project commands."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    setup_factory(setup_name="rebuild-lock", script_content="true")
    run(
        f"{zaigr} project setup run rebuild-lock",
        input="y\n",
        timeout=180,
    )
    run(f"{zaigr} project vm stop", timeout=60)

    setup_factory(
        setup_name="rebuild-lock",
        script_content=_blocked_setup_script("REBUILD_LOCK_READY"),
    )
    barrier = project.cwd / ".zaigr-test-barrier"
    barrier.touch()
    rebuild = spawn_interactive(
        f"{zaigr} project rebuild --force",
        cwd=project.cwd,
        env=project.env,
        timeout=240,
    )
    try:
        rebuild.expect(r"REBUILD_LOCK_READY", timeout=180)

        for command in (
            f"{zaigr} project status",
            f"{zaigr} project setup list",
            f"{zaigr} project vm show-config",
        ):
            stdout, stderr, rc = _run(
                command,
                cwd=project.cwd,
                env=project.env,
                timeout=20,
            )
            assert rc != 0, err_msg(stdout, stderr)
            assert "project rebuild --force is running in another terminal" in (
                stdout + stderr
            )

        barrier.unlink()
        rebuild.expect(pexpect.EOF, timeout=60)
        rebuild.close()
        assert rebuild.exitstatus == 0
    finally:
        barrier.unlink(missing_ok=True)
        if rebuild.isalive():
            rebuild.close(force=True)
