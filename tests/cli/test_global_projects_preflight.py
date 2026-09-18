"""Batch confirmation covers selection errors and warned setup scripts."""

import hashlib

import pexpect

from ..conftest import err_msg, spawn_interactive
from ..conftest import run as _run


def test_global_rebuild_accepts_project_with_no_applied_setups(project, tmp_path):
    zaigr = project.zaigr_bin
    stdout, stderr, rc = _run(
        [zaigr, "project", "vm", "start"],
        cwd=project.cwd,
        env=project.env,
        input="y\n",
        timeout=180,
    )
    assert rc == 0, err_msg(stdout, stderr)
    # The public initialization workflow represents an empty setup list by
    # omitting this metadata file. Its absence must not imply corruption.
    assert not (project.store_dir / "applied-setups.json").exists()
    stdout, stderr, rc = _run(
        [zaigr, "global", "projects", "rebuild", "--outdated"],
        cwd=tmp_path,
        env=project.env,
        timeout=30,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert "No projects need rebuilding." in stdout

    stdout, stderr, rc = _run(
        [zaigr, "global", "projects", "rebuild", "--all", "--yes"],
        cwd=tmp_path,
        env=project.env,
        timeout=180,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert "Rebuilt: 1" in stdout
    details, stderr, rc = _run(
        [zaigr, "global", "projects", "details", project.cwd.name],
        cwd=tmp_path,
        env=project.env,
        timeout=20,
    )
    assert rc == 0, err_msg(details, stderr)
    assert "status: off\n" in details
    assert "applied (0):" in details
    stdout, stderr, rc = _run(
        [zaigr, "project", "vm", "start"],
        cwd=project.cwd,
        env=project.env,
        timeout=180,
    )
    assert rc == 0, err_msg(stdout, stderr)
    stdout, stderr, rc = _run(
        [zaigr, "project", "vm", "exec", "--", "true"],
        cwd=project.cwd,
        env=project.env,
        timeout=20,
    )
    assert rc == 0, err_msg(stdout, stderr)


def test_global_rebuild_cancel_preserves_selection_errors_and_deduplicates(
    project, setup_factory, tmp_path
):
    setup_factory("preview-marker", "true")
    zaigr = project.zaigr_bin
    stdout, stderr, rc = _run(
        [zaigr, "project", "setup", "run", "preview-marker"],
        cwd=project.cwd,
        env=project.env,
        input="y\n",
        timeout=180,
    )
    assert rc == 0, err_msg(stdout, stderr)
    store = project.store_dir
    stdout, stderr, rc = _run(
        [zaigr, "project", "vm", "stop"],
        cwd=project.cwd,
        env=project.env,
        timeout=60,
    )
    assert rc == 0, err_msg(stdout, stderr)
    image = store / "project.qcow2"
    before = hashlib.sha256(image.read_bytes()).digest()
    records = (store / "applied-setups.json").read_bytes()

    for selection in ("--all", "--outdated"):
        stdout, stderr, rc = _run(
            [zaigr, "global", "projects", "rebuild", project.cwd.name, selection],
            cwd=tmp_path,
            env=project.env,
            timeout=10,
        )
        assert rc != 0
        assert "exactly one mode" in stdout + stderr

    batch = spawn_interactive(
        f"{zaigr} global projects rebuild {project.cwd.name} {store.name} nonexistent-selector",
        cwd=tmp_path,
        env=project.env,
        timeout=30,
    )
    try:
        batch.expect(r"Rebuild 1 project\(s\)\? \[y/N\]")
        assert "1 eligible, 1 skipped" in batch.transcript.getvalue()
        batch.sendline("")
        batch.expect(pexpect.EOF)
        batch.close()
        transcript = batch.transcript.getvalue()
        assert batch.exitstatus != 0
    finally:
        if batch.isalive():
            batch.close(force=True)
    assert "nonexistent-selector" in transcript
    assert "cancel" in transcript.lower()
    assert "[1/" not in transcript
    assert hashlib.sha256(image.read_bytes()).digest() == before
    assert (store / "applied-setups.json").read_bytes() == records


def test_global_rebuild_yes_accepts_apt_warning_without_nested_prompt(
    project, setup_factory, tmp_path
):
    setup_factory("warned-marker", "printf old > /etc/zaigr-warned-marker")
    zaigr = project.zaigr_bin
    stdout, stderr, rc = _run(
        [zaigr, "project", "setup", "run", "warned-marker"],
        cwd=project.cwd,
        env=project.env,
        input="y\n",
        timeout=180,
    )
    assert rc == 0, err_msg(stdout, stderr)
    # The public warning scanner sees the APT command. The false branch keeps
    # the test offline and avoids installing anything during setup execution.
    setup_factory(
        "warned-marker",
        "if false; then\napt-get install zaigr-warning-test\nfi\n"
        "printf updated > /etc/zaigr-warned-marker",
    )
    stdout, stderr, rc = _run(
        [zaigr, "global", "projects", "rebuild", "--all", "--yes"],
        cwd=tmp_path,
        env=project.env,
        timeout=300,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert stderr.count("APT command without automatic confirmation") == 1
    assert "apt-get install zaigr-warning-test" in stderr
    assert "Continue with setup execution anyway?" not in stdout + stderr
    assert "Action [a/r]" not in stdout + stderr
    assert "Rebuilt: 1" in stdout

    details, stderr, rc = _run(
        [zaigr, "global", "projects", "details", project.cwd.name],
        cwd=tmp_path,
        env=project.env,
        timeout=10,
    )
    assert rc == 0, err_msg(details, stderr)
    assert "status: off\n" in details
    stdout, stderr, rc = _run(
        [zaigr, "project", "vm", "start"],
        cwd=project.cwd,
        env=project.env,
        timeout=180,
    )
    assert rc == 0, err_msg(stdout, stderr)
    marker, stderr, rc = _run(
        [zaigr, "project", "vm", "exec", "--", "cat", "/etc/zaigr-warned-marker"],
        cwd=project.cwd,
        env=project.env,
        timeout=180,
    )
    assert rc == 0, err_msg(marker, stderr)
    assert marker.strip() == "updated"
