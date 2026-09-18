"""Acceptance tests for project-local setup discovery and installation."""

from functools import partial

import pexpect
import pytest

from ..conftest import err_msg, spawn_interactive
from ..conftest import run as _run


def _checked_run(cmd, **kwargs):
    stdout, stderr, rc = _run(cmd, **kwargs)
    assert rc == 0, err_msg(stdout, stderr)
    return stdout, stderr


def test_local_skeleton_creates_an_editable_project_local_setup(zaigr_bin, tmp_path):
    """`project setup local-skeleton` creates the complete local setup structure."""
    stdout, stderr, rc = _run(
        [zaigr_bin, "project", "setup", "local-skeleton"],
        cwd=tmp_path,
        timeout=10,
    )

    assert rc == 0, err_msg(stdout, stderr)
    setup_dir = tmp_path / ".zaigr" / "setups" / "local"
    assert stdout.strip() == (
        ":: Created project-local setup skeleton: "
        ".zaigr/setups/local"
    )
    assert (setup_dir / "setup.script").read_text(encoding="utf-8") == (
        "#!/bin/bash\nset -eu\n"
    )
    assert (setup_dir / "setup.firewall").read_text(encoding="utf-8") == ""


def test_local_skeleton_does_not_overwrite_an_existing_setup(zaigr_bin, tmp_path):
    """Creating a skeleton never replaces existing project-local setup content."""
    setup_dir = tmp_path / ".zaigr" / "setups" / "local"
    setup_dir.mkdir(parents=True)
    script = setup_dir / "setup.script"
    script.write_text("apt-get update\n", encoding="utf-8")

    stdout, stderr, rc = _run(
        [zaigr_bin, "project", "setup", "local-skeleton"],
        cwd=tmp_path,
        timeout=10,
    )

    assert rc != 0, err_msg(stdout, stderr)
    assert "project-local setup already exists" in stdout + stderr
    assert script.read_text(encoding="utf-8") == "apt-get update\n"
    assert not (setup_dir / "setup.firewall").exists()


@pytest.mark.timeout(180)
def test_vm_start_offers_installs_and_labels_project_local_setup(project):
    """A confirmed project-local setup is installed and identified in setup output."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    run(
        f"{zaigr} project setup local-skeleton",
        timeout=10,
    )
    setup_dir = project.cwd / ".zaigr" / "setups" / "local"
    (setup_dir / "setup.script").write_text(
        "#!/bin/bash\n"
        "set -eu\n"
        "printf 'project-local-installed\\n' > /etc/project-local-installed\n",
        encoding="utf-8",
    )

    start = spawn_interactive(
        f"{zaigr} project vm start",
        cwd=project.cwd,
        env=project.env,
        timeout=180,
    )
    try:
        start.expect(r"Initialize project and continue\? \[y/N\]")
        start.sendline("y")
        start.expect_exact(":: [Project local] local is available.")
        start.expect(r"Install \[Project local\] local\? \[y/N\]")
        start.sendline("y")
        start.expect(pexpect.EOF)
        start.close()
        assert start.exitstatus == 0
    finally:
        start.close(force=True)

    marker, _ = run(
        f"{zaigr} project vm exec -- cat /etc/project-local-installed",
        timeout=20,
    )
    assert marker.strip() == "project-local-installed"

    applied, _ = run(
        f"{zaigr} project setup list --applied",
        timeout=10,
    )
    assert "[Project local] local" in applied

    skipped, _ = run(
        f"{zaigr} project setup run local",
        timeout=10,
    )
    assert (
        "Skipping setups already applied at the current version: "
        "[Project local] local"
    ) in skipped
