"""Acceptance coverage for global projects --outdated selection.

The selection cases use metadata fixtures after creating isolated project
directories. The replay case uses public setup, base-image, rebuild, VM start,
and guest-exec commands with a real VM.
"""

import json

import pexpect
import pytest

from ..conftest import err_msg, spawn_interactive
from ..conftest import run as _run


@pytest.fixture(autouse=True)
def small_vm_resources(monkeypatch):
    monkeypatch.setenv("ZAIGR_VM_RAM", "512")
    monkeypatch.setenv("ZAIGR_VM_CPU", "1")


def _checked_run(cmd, **kwargs):
    stdout, stderr, rc = _run(cmd, **kwargs)
    assert rc == 0, err_msg(stdout, stderr)
    return stdout


def _seed_current_store(project):
    store = project.store_dir
    store.mkdir(parents=True, exist_ok=True)
    (store / "project-path").write_text(f"{project.cwd}\n", encoding="utf-8")
    (store / "config").write_text("disk=100G\n", encoding="utf-8")
    (store / "image-format").write_text("direct-base-v1\n", encoding="utf-8")
    (store / "applied-setups.json").write_text("[]\n", encoding="utf-8")
    return store


def test_outdated_selects_runtime_upgrade_and_excludes_stale_definition_change(
    project_factory, setup_factory, tmp_path
):
    project = project_factory("outdated-runtime")
    zaigr = project.zaigr_bin
    setup_factory("outdated-marker", "printf 'v1\n' > /etc/outdated-marker")
    _checked_run(
        [zaigr, "project", "setup", "run", "outdated-marker"],
        cwd=project.cwd,
        env=project.env,
        input="y\n",
        timeout=180,
    )
    _checked_run(
        [zaigr, "project", "vm", "stop"],
        cwd=project.cwd,
        env=project.env,
        timeout=60,
    )

    stdout, stderr, rc = _run(
        [zaigr, "global", "projects", "rebuild", "--outdated"],
        cwd=tmp_path,
        env=project.env,
        timeout=20,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert project.cwd.name not in stdout + stderr

    runtime = project.store_dir / "runtime"
    runtime.mkdir(exist_ok=True)
    (runtime / "vm.sock").write_text("stale marker\n", encoding="utf-8")
    setup_factory("outdated-marker", "printf 'v2\n' > /etc/outdated-marker")
    stdout, stderr, rc = _run(
        [zaigr, "global", "projects", "list"],
        cwd=tmp_path,
        env=project.env,
        timeout=10,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert "off, stale" in stdout

    stdout, stderr, rc = _run(
        [zaigr, "global", "projects", "rebuild", "--outdated"],
        cwd=tmp_path,
        env=project.env,
        timeout=20,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert project.cwd.name not in stdout + stderr

    (project.store_dir / "base-image-version").write_text(
        "old-runtime-for-selection\n", encoding="utf-8"
    )
    rebuild = spawn_interactive(
        f"{zaigr} global projects rebuild --outdated",
        cwd=tmp_path,
        env=project.env,
        timeout=30,
    )
    try:
        rebuild.expect(r"Rebuild 1 project\(s\)\? \[y/N\]")
        rebuild.sendline("")
        rebuild.expect(pexpect.EOF)
        rebuild.close()
        transcript = rebuild.transcript.getvalue()
        assert rebuild.exitstatus == 0
    finally:
        if rebuild.isalive():
            rebuild.close(force=True)
    assert project.cwd.name in transcript
    assert "cancel" in transcript.lower()


def test_outdated_skips_missing_or_malformed_version_backing_and_image(
    project_factory, setup_factory, tmp_path
):
    projects = []
    stores = []
    for name in (
        "missing-version",
        "malformed-version",
        "missing-backing",
        "malformed-backing",
        "missing-image",
    ):
        project = project_factory(name)
        store = _seed_current_store(project)
        projects.append(project)
        stores.append(store)

    (stores[0] / "project.qcow2").write_bytes(b"fixture image")
    (stores[1] / "project.qcow2").write_bytes(b"fixture image")
    (stores[1] / "base-image-version").mkdir()
    (stores[2] / "project.qcow2").write_bytes(b"fixture image")
    (stores[2] / "base-image-version").write_text("old-runtime\n", encoding="utf-8")
    (stores[3] / "project.qcow2").write_bytes(b"fixture image")
    (stores[3] / "base-image-version").write_text("old-runtime\n", encoding="utf-8")
    (stores[3] / "base-backing.json").write_text("{broken\n", encoding="utf-8")
    (stores[4] / "base-image-version").write_text("old-runtime\n", encoding="utf-8")

    legacy = project_factory("legacy-supported")
    legacy_store = legacy.store_dir
    legacy_store.mkdir(parents=True, exist_ok=True)
    (legacy_store / "project-path").write_text(f"{legacy.cwd}\n", encoding="utf-8")
    (legacy_store / "config").write_text("disk=100G\n", encoding="utf-8")
    (legacy_store / "base-image-version").write_text("legacy-runtime\n", encoding="utf-8")
    setup_factory("legacy-marker", "printf 'legacy\n' > /etc/legacy-marker")
    committed = legacy_store / "committed"
    committed.mkdir()
    (committed / "001-legacy-marker.sh").write_text(
        "printf 'legacy fixture\n'\n", encoding="utf-8"
    )
    legacy_image = legacy_store / "image-legacy.qcow2"
    stdout, stderr, rc = _run(
        ["qemu-img", "create", "-f", "qcow2", legacy_image, "1G"],
        cwd=legacy.cwd,
        env=legacy.env,
        timeout=30,
    )
    assert rc == 0, err_msg(stdout, stderr)
    projects.append(legacy)

    structured = project_factory("legacy-structured-record")
    structured_store = structured.store_dir
    structured_store.mkdir(parents=True, exist_ok=True)
    (structured_store / "project-path").write_text(
        f"{structured.cwd}\n", encoding="utf-8"
    )
    (structured_store / "config").write_text("disk=100G\n", encoding="utf-8")
    (structured_store / "base-image-version").write_text(
        "legacy-runtime\n", encoding="utf-8"
    )
    structured_script = "printf 'structured legacy\n' > /etc/structured-legacy-marker"
    setup_factory("structured-legacy-marker", structured_script)
    (structured_store / "applied-setups.json").write_text(
        json.dumps(
            [
                {
                    "name": "structured-legacy-marker",
                    # A historical content version; migration replays today's definition.
                    "version": "0123456789ab",
                }
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    structured_image = structured_store / "image-structured.qcow2"
    stdout, stderr, rc = _run(
        ["qemu-img", "create", "-f", "qcow2", structured_image, "1G"],
        cwd=structured.cwd,
        env=structured.env,
        timeout=30,
    )
    assert rc == 0, err_msg(stdout, stderr)
    projects.append(structured)

    zaigr = projects[0].zaigr_bin
    rebuild = spawn_interactive(
        f"{zaigr} global projects rebuild --outdated",
        cwd=tmp_path,
        env=projects[0].env,
        timeout=30,
    )
    try:
        rebuild.expect(r"Rebuild 2 project\(s\)\? \[y/N\]")
        rebuild.sendline("")
        rebuild.expect(pexpect.EOF)
        rebuild.close()
        combined = rebuild.transcript.getvalue()
        assert rebuild.exitstatus != 0
    finally:
        if rebuild.isalive():
            rebuild.close(force=True)
    for project in projects:
        assert project.cwd.name in combined
    assert "7 of 7 projects selected for rebuilding; 2 eligible, 5 skipped." in combined
    assert "action" in combined.lower()
    assert "legacy-supported" in combined and "rebuild" in combined
    assert "legacy-structured-record" in combined
    assert "skip: recorded base runtime version is incomplete" in combined
    assert "skip: project backing selection is incomplete" in combined
    assert "skip: project image is missing or unreadable" in combined
    assert "cancel" in combined.lower()
    assert (stores[1] / "base-image-version").is_dir()
    assert not (stores[4] / "project.qcow2").exists()

    stdout, stderr, rc = _run(
        [zaigr, "global", "projects", "rebuild", "--outdated", "--yes"],
        cwd=tmp_path,
        env=projects[0].env,
        timeout=360,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert "legacy-supported" in stdout
    assert "legacy-structured-record" in stdout
    assert "rebuilt" in stdout.lower()
    assert "2 rebuilt, 0 failed, and 5 skipped" in (stdout + stderr)
    _checked_run(
        [structured.zaigr_bin, "project", "vm", "start"],
        cwd=structured.cwd,
        env=structured.env,
        input="y\n",
        timeout=180,
    )
    marker = _checked_run(
        [
            structured.zaigr_bin,
            "project",
            "vm",
            "exec",
            "--",
            "cat",
            "/etc/structured-legacy-marker",
        ],
        cwd=structured.cwd,
        env=structured.env,
        timeout=20,
    )
    assert marker == "structured legacy\n"
    _checked_run(
        [structured.zaigr_bin, "project", "vm", "stop"],
        cwd=structured.cwd,
        env=structured.env,
        timeout=60,
    )


@pytest.mark.timeout(900)
def test_outdated_rebuild_replays_recorded_setup_after_custom_base_selection(
    project_factory, setup_factory, tmp_path
):
    project = project_factory("custom-outdated-replay")
    zaigr = project.zaigr_bin
    env = project.env
    setup_factory(
        "custom-base-marker", "printf 'factory-base\n' > /etc/custom-base-marker"
    )
    setup_factory(
        "custom-project-marker", "printf 'factory-project\n' > /etc/custom-project-marker"
    )

    _checked_run(
        [zaigr, "project", "setup", "run", "custom-project-marker"],
        cwd=project.cwd,
        env=env,
        input="y\n",
        timeout=180,
    )
    _checked_run(
        [zaigr, "global", "base-image", "setup", "run", "custom-base-marker"],
        cwd=tmp_path,
        env=env,
        timeout=240,
    )

    stdout, stderr, rc = _run(
        [zaigr, "global", "projects", "rebuild", "--outdated", "--yes"],
        cwd=tmp_path,
        env=env,
        timeout=360,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert "rebuilt" in stdout.lower()
    assert "custom-outdated-replay" in stdout

    details = _checked_run(
        [zaigr, "global", "projects", "details", project.cwd.name],
        cwd=tmp_path,
        env=env,
        timeout=20,
    )
    assert "status: off" in details

    _checked_run(
        [zaigr, "project", "vm", "start"],
        cwd=project.cwd,
        env=env,
        input="y\n",
        timeout=180,
    )
    project_marker = _checked_run(
        [zaigr, "project", "vm", "exec", "--", "cat", "/etc/custom-project-marker"],
        cwd=project.cwd,
        env=env,
        timeout=20,
    )
    base_marker = _checked_run(
        [zaigr, "project", "vm", "exec", "--", "cat", "/etc/custom-base-marker"],
        cwd=project.cwd,
        env=env,
        timeout=20,
    )
    assert project_marker == "factory-project\n"
    assert base_marker == "factory-base\n"
    _checked_run(
        [zaigr, "project", "vm", "stop"],
        cwd=project.cwd,
        env=env,
        timeout=60,
    )

    setup_factory(
        "custom-base-marker", "printf 'custom-revision\n' > /etc/custom-base-marker"
    )
    _checked_run(
        [zaigr, "global", "base-image", "setup", "run", "custom-base-marker", "--force"],
        cwd=tmp_path,
        env=env,
        timeout=240,
    )
    rebuild = spawn_interactive(
        f"{zaigr} global projects rebuild --outdated",
        cwd=tmp_path,
        env=env,
        timeout=30,
    )
    try:
        rebuild.expect(r"Rebuild 1 project\(s\)\? \[y/N\]")
        rebuild.sendline("")
        rebuild.expect(pexpect.EOF)
        rebuild.close()
        transcript = rebuild.transcript.getvalue()
        assert rebuild.exitstatus == 0
    finally:
        if rebuild.isalive():
            rebuild.close(force=True)
    assert "custom-outdated-replay" in transcript
    assert "1 eligible" in transcript
    assert "action" in transcript.lower()
    assert "rebuild" in transcript.lower()
    assert "cancel" in transcript.lower()

    _checked_run(
        [zaigr, "global", "base-image", "reset"],
        cwd=tmp_path,
        env=env,
        timeout=30,
    )
    rebuild = spawn_interactive(
        f"{zaigr} global projects rebuild --outdated",
        cwd=tmp_path,
        env=env,
        timeout=30,
    )
    try:
        rebuild.expect(r"Rebuild 1 project\(s\)\? \[y/N\]")
        rebuild.sendline("")
        rebuild.expect(pexpect.EOF)
        rebuild.close()
        transcript = rebuild.transcript.getvalue()
        assert rebuild.exitstatus == 0
    finally:
        if rebuild.isalive():
            rebuild.close(force=True)
    assert "custom-outdated-replay" in transcript
    assert "1 eligible" in transcript
    assert "rebuild" in transcript.lower()
    assert "cancel" in transcript.lower()
