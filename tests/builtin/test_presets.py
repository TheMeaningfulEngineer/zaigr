"""Tests for real builtin presets shipped with zaigr."""

import time
from functools import partial

import pytest

from ..conftest import err_msg, spawn_interactive
from ..conftest import run as _run

run = _run


def _checked_run(cmd, **kwargs):
    stdout, stderr, rc = _run(cmd, **kwargs)
    assert rc == 0, err_msg(stdout, stderr)
    return stdout


@pytest.mark.timeout(1200)
def test_codex_preset_installs_codex_and_launches(project):
    """The builtin `codex` preset installs Codex and launches it."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    codex_state = project.store_dir / "agent-state" / "codex"
    shell = spawn_interactive(
        f"{zaigr} shell --preset codex --ram 2048 --cpu 2",
        cwd=project.cwd,
        env=project.env,
        timeout=1200,
    )
    try:
        shell.expect(r"Initialize project and continue\? \[y/N\]")
        shell.sendline("y")
        shell.expect("\x1b\\[\\?2026h")
    finally:
        shell.close(force=True)

    status = run(
        f"{zaigr} project status",
        timeout=10,
    )
    assert "applied (1):" in status
    assert "codex" in status

    output = run(
        f"{zaigr} project setup list --applied",
        timeout=10,
    )
    assert "applied (1):" in output
    assert "codex" in output
    assert not (project.cwd / ".codex").exists()
    assert codex_state.is_dir()


@pytest.mark.timeout(1200)
def test_claude_preset_installs_claude_and_launches(project):
    """The builtin `claude` preset installs Claude and launches it."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    claude_state = project.store_dir / "agent-state" / "claude"
    shell = spawn_interactive(
        f"{zaigr} shell --preset claude --ram 2048 --cpu 2",
        cwd=project.cwd,
        env=project.env,
        timeout=1200,
    )
    try:
        shell.expect(r"Initialize project and continue\? \[y/N\]")
        shell.sendline("y")
        shell.expect(r":: Setup applied to (?:stopped project image|running project VM):")
        deadline = time.monotonic() + 180
        while not claude_state.is_dir():
            if not shell.isalive():
                pytest.fail("claude preset exited before creating agent state")
            if time.monotonic() >= deadline:
                pytest.fail("claude preset did not create agent state")
            time.sleep(1)
    finally:
        shell.close(force=True)

    status = run(
        f"{zaigr} project status",
        timeout=10,
    )
    assert "applied (1):" in status
    assert "claude" in status

    output = run(
        f"{zaigr} project setup list --applied",
        timeout=10,
    )
    assert "applied (1):" in output
    assert "claude" in output
    assert not (project.cwd / ".claude-config").exists()
    assert claude_state.is_dir()


@pytest.mark.timeout(1200)
def test_mistral_preset_installs_vibe_and_launches(project):
    """The builtin `mistral` preset installs Vibe and launches it."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    mistral_state = project.store_dir / "agent-state" / "mistral"
    shell = spawn_interactive(
        f"{zaigr} shell --preset mistral --ram 2048 --cpu 2",
        cwd=project.cwd,
        env=project.env,
        timeout=1200,
    )
    try:
        shell.expect(r"Initialize project and continue\? \[y/N\]")
        shell.sendline("y")
        shell.expect(r":: Setup applied to (?:stopped project image|running project VM):")
        deadline = time.monotonic() + 180
        while not mistral_state.is_dir():
            if not shell.isalive():
                pytest.fail("mistral preset exited before creating agent state")
            if time.monotonic() >= deadline:
                pytest.fail("mistral preset did not create agent state")
            time.sleep(1)
    finally:
        shell.close(force=True)

    status = run(
        f"{zaigr} project status",
        timeout=10,
    )
    assert "applied (1):" in status
    assert "mistral" in status

    output = run(
        f"{zaigr} project setup list --applied",
        timeout=10,
    )
    assert "applied (1):" in output
    assert "mistral" in output
    assert not (project.cwd / ".vibe").exists()
    assert mistral_state.is_dir()


@pytest.mark.timeout(1200)
def test_antigravity_preset_installs_agy_and_launches(project):
    """The builtin `antigravity` preset installs and launches Google's CLI."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    antigravity_state = project.store_dir / "agent-state" / "antigravity"
    shell = spawn_interactive(
        f"{zaigr} shell --preset antigravity --ram 2048 --cpu 2",
        cwd=project.cwd,
        env=project.env,
        timeout=1200,
    )
    try:
        shell.expect(r"Initialize project and continue\? \[y/N\]")
        shell.sendline("y")
        shell.expect_exact("Antigravity CLI", timeout=1200)
        shell.expect_exact("Select login method:", timeout=1200)
    finally:
        shell.close(force=True)

    status = run(f"{zaigr} project status", timeout=10)
    assert "applied (1):" in status
    assert "antigravity" in status

    applied = run(f"{zaigr} project setup list --applied", timeout=10)
    assert "applied (1):" in applied
    assert "antigravity" in applied
    assert "1.4.0" in run(f"{zaigr} project vm exec -- agy --version", timeout=10)
    assert antigravity_state.is_dir()
    assert (antigravity_state / ".gemini").is_dir()
    assert not (project.cwd / ".gemini").exists()
