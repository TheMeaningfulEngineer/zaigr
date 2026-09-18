"""Acceptance coverage for global project rebuild selection and execution."""

import fcntl
import hashlib
import json
import re
from pathlib import Path

import pexpect
import pytest

from ..conftest import ProjectTestEnv, err_msg, spawn_interactive
from ..conftest import run as _run


@pytest.fixture
def metadata_projects(test_root, zaigr_bin, zaigr_home):
    projects = []
    for name in ("damaged", "healthy"):
        cwd = test_root / name
        cwd.mkdir()
        project = ProjectTestEnv(cwd, Path(zaigr_bin), Path(zaigr_home))
        store = project.store_dir
        store.mkdir(parents=True, exist_ok=True)
        (store / "project-path").write_text(f"{cwd}\n", encoding="utf-8")
        (store / "ram").write_text("512\n", encoding="utf-8")
        (store / "cpus").write_text("1\n", encoding="utf-8")
        (store / "config").write_text("disk=100G\n", encoding="utf-8")
        (store / "image-format").write_text("direct-base-v1\n", encoding="utf-8")
        projects.append((project, store))
    return projects


def test_global_rebuild_requires_one_selection_mode_before_mutation(metadata_projects, tmp_path):
    project, first = metadata_projects[0]
    zaigr = project.zaigr_bin
    protected = first / "setup-capture.json"
    protected.write_text('{"name":"pending"}\n', encoding="utf-8")
    before = protected.read_bytes()

    for args in (
        ["global", "projects", "rebuild"],
        ["global", "projects", "rebuild", "--all", "--outdated"],
    ):
        stdout, stderr, rc = _run(
            [zaigr, *args], cwd=tmp_path, env=project.env, timeout=10
        )
        assert rc != 0, err_msg(stdout, stderr)
        assert "stop" not in (stdout + stderr).lower()
        assert protected.read_bytes() == before


def test_global_rebuild_cancelled_preview_leaves_capture_and_images_untouched(
    project_factory, setup_factory, test_root, zaigr_bin, zaigr_home, tmp_path
):
    project = project_factory("healthy-target")
    setup_factory(setup_name="cancel-marker", script_content="true")
    stdout, stderr, rc = _run(
        [project.zaigr_bin, "project", "setup", "run", "cancel-marker"],
        cwd=project.cwd,
        env=project.env,
        input="y\n",
        timeout=180,
    )
    assert rc == 0, err_msg(stdout, stderr)
    stdout, stderr, rc = _run(
        [project.zaigr_bin, "project", "vm", "start"],
        cwd=project.cwd,
        env=project.env,
        input="y\n",
        timeout=180,
    )
    assert rc == 0, err_msg(stdout, stderr)
    details, stderr, rc = _run(
        [project.zaigr_bin, "global", "projects", "details", project.cwd.name],
        cwd=tmp_path,
        env=project.env,
        timeout=20,
    )
    assert rc == 0, err_msg(details, stderr)
    project_pid = details.split("vm-pid: ", 1)[1].splitlines()[0]
    blocked_dir = test_root / "blocked-target"
    blocked_dir.mkdir()
    blocked = ProjectTestEnv(blocked_dir, Path(zaigr_bin), Path(zaigr_home))
    second = blocked.store_dir
    second.mkdir(parents=True)
    (second / "project-path").write_text(f"{blocked_dir}\n", encoding="utf-8")
    (second / "ram").write_text("512\n", encoding="utf-8")
    (second / "cpus").write_text("1\n", encoding="utf-8")
    (second / "config").write_text("disk=100G\n", encoding="utf-8")
    (second / "image-format").write_text("direct-base-v1\n", encoding="utf-8")
    zaigr = project.zaigr_bin
    capture = second / "setup-capture.json"
    capture.write_text('{"name":"pending-capture"}\n', encoding="utf-8")
    before_capture = capture.read_bytes()
    batch = spawn_interactive(
        f"{zaigr} global projects rebuild {project.cwd.name} {blocked_dir.name}",
        cwd=tmp_path,
        env=project.env,
        timeout=20,
    )
    try:
        batch.expect(r"Rebuild 1 project\(s\)\? \[y/N\]")
        preview = batch.transcript.getvalue()
        assert "1 eligible, 1 skipped" in preview
        assert "stop and rebuild" in preview
        assert "close attached shells" in preview
        batch.sendline("n")
        batch.expect(pexpect.EOF)
        batch.close()
        transcript = batch.transcript.getvalue()
    finally:
        if batch.isalive():
            batch.close(force=True)
    assert batch.exitstatus != 0
    assert "cancel" in transcript.lower()
    assert capture.read_bytes() == before_capture
    ps_stdout, ps_stderr, ps_rc = _run(
        ["ps", "-p", project_pid, "-o", "stat="], cwd=tmp_path, env=project.env, timeout=10
    )
    assert ps_rc == 0 and ps_stdout.strip() and not ps_stdout.strip().startswith("Z"), err_msg(ps_stdout, ps_stderr)


def test_global_rebuild_skips_malformed_and_duplicate_setup_records(
    metadata_projects, tmp_path
):
    project, first = metadata_projects[0]
    _, second = metadata_projects[1]
    zaigr = project.zaigr_bin
    # These sentinel images are never opened: invalid setup records must block
    # preflight before base validation or any VM/image operation.
    (first / "applied-setups.json").write_text("{broken", encoding="utf-8")
    (second / "applied-setups.json").write_text(
        json.dumps([{"name": "duplicate", "version": "v1"}] * 2), encoding="utf-8"
    )
    first_image = first / "project.qcow2"
    second_image = second / "project.qcow2"
    first_image.write_bytes(b"old-image")
    second_image.write_bytes(b"unknown-image")

    stdout, stderr, rc = _run(
        [zaigr, "global", "projects", "rebuild", "--outdated"],
        cwd=tmp_path,
        env=project.env,
        timeout=20,
    )
    assert rc != 0
    combined = stdout + stderr
    assert first.name in combined
    assert second.name in combined
    assert "skip: parse applied setups:" in combined
    assert "skip: duplicate applied setup record: duplicate" in combined
    assert "Skipped: 2" in combined
    assert "[y/N]" not in combined
    assert first_image.read_bytes() == b"old-image"
    assert second_image.read_bytes() == b"unknown-image"


@pytest.mark.timeout(300)
@pytest.mark.parametrize("answer", ["\n", ""])
def test_global_rebuild_clean_cancel_default_no_and_eof(project, setup_factory, tmp_path, answer):
    zaigr = project.zaigr_bin
    setup_factory(setup_name="cancel-marker", script_content="true")
    stdout, stderr, rc = _run(
        [zaigr, "project", "setup", "run", "cancel-marker"],
        cwd=project.cwd,
        env=project.env,
        input="y\n",
        timeout=180,
    )
    assert rc == 0, err_msg(stdout, stderr)
    stdout, stderr, rc = _run(
        [zaigr, "project", "vm", "stop"], cwd=project.cwd, env=project.env, timeout=60
    )
    assert rc == 0, err_msg(stdout, stderr)
    image = project.store_dir / "project.qcow2"
    applied = project.store_dir / "applied-setups.json"
    before_image = hashlib.sha256(image.read_bytes()).digest()
    before_applied = applied.read_bytes()
    batch = spawn_interactive(
        f"{zaigr} global projects rebuild {project.cwd.name}",
        cwd=tmp_path, env=project.env, timeout=30,
    )
    try:
        batch.expect(r"Rebuild .*\? \[y/N\]", timeout=20)
        if answer:
            batch.sendline("")
        else:
            batch.sendeof()
        batch.expect(pexpect.EOF, timeout=30)
        batch.close()
        transcript = batch.transcript.getvalue()
    finally:
        if batch.isalive():
            batch.close(force=True)
    assert batch.exitstatus == 0
    assert "cancel" in transcript.lower()
    assert hashlib.sha256(image.read_bytes()).digest() == before_image
    assert applied.read_bytes() == before_applied


@pytest.mark.timeout(300)
def test_global_rebuild_force_only_overrides_dirty_marker(project, setup_factory, tmp_path):
    zaigr = project.zaigr_bin
    setup_factory(setup_name="force-marker", script_content="touch /etc/recorded-force-marker")
    stdout, stderr, rc = _run(
        [zaigr, "project", "setup", "run", "force-marker"],
        cwd=project.cwd,
        env=project.env,
        input="y\n",
        timeout=180,
    )
    assert rc == 0, err_msg(stdout, stderr)
    stdout, stderr, rc = _run(
        [zaigr, "project", "vm", "start"],
        cwd=project.cwd,
        env=project.env,
        input="y\n",
        timeout=180,
    )
    assert rc == 0, err_msg(stdout, stderr)
    stdout, stderr, rc = _run(
        [zaigr, "project", "vm", "exec", "--root", "--", "touch", "/etc/unrecorded-force-marker"],
        cwd=project.cwd,
        env=project.env,
        input="y\n",
        timeout=30,
    )
    assert rc == 0, err_msg(stdout, stderr)
    stdout, stderr, rc = _run(
        [zaigr, "project", "vm", "stop"], cwd=project.cwd, env=project.env, timeout=60
    )
    assert rc == 0, err_msg(stdout, stderr)
    dirty = project.store_dir / "project-image-dirty"
    assert dirty.exists()
    image = project.store_dir / "project.qcow2"
    before = hashlib.sha256(image.read_bytes()).hexdigest()
    stdout, stderr, rc = _run(
        [zaigr, "global", "projects", "rebuild", project.cwd.name, "--yes"],
        cwd=tmp_path,
        env=project.env,
        timeout=30,
    )
    assert rc != 0
    assert "manual image changes" in (stdout + stderr).lower()
    assert hashlib.sha256(image.read_bytes()).hexdigest() == before

    stdout, stderr, rc = _run(
        [zaigr, "global", "projects", "rebuild", project.cwd.name, "--force", "--yes"],
        cwd=tmp_path,
        env=project.env,
        timeout=300,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert "rebuilt" in stdout.lower()
    assert not dirty.exists()
    details, stderr, rc = _run(
        [zaigr, "global", "projects", "details", project.cwd.name],
        cwd=tmp_path, env=project.env, timeout=20,
    )
    assert rc == 0, err_msg(details, stderr)
    assert "status: off\n" in details
    stdout, stderr, rc = _run(
        [zaigr, "project", "vm", "start"], cwd=project.cwd, env=project.env, timeout=180,
    )
    assert rc == 0, err_msg(stdout, stderr)
    stdout, stderr, rc = _run(
        [zaigr, "project", "vm", "exec", "--", "test", "-e", "/etc/recorded-force-marker"],
        cwd=project.cwd, env=project.env, timeout=20,
    )
    assert rc == 0, err_msg(stdout, stderr)
    stdout, stderr, rc = _run(
        [zaigr, "project", "vm", "exec", "--", "test", "!", "-e", "/etc/unrecorded-force-marker"],
        cwd=project.cwd, env=project.env, timeout=20,
    )
    assert rc == 0, err_msg(stdout, stderr)


@pytest.mark.timeout(600)
def test_global_rebuild_rechecks_busy_project_after_preview(project_factory, setup_factory, tmp_path):
    first = project_factory("recheck-first")
    second = project_factory("recheck-second")
    zaigr = first.zaigr_bin
    setup_factory(setup_name="recheck-marker", script_content="true")
    for project in (first, second):
        stdout, stderr, rc = _run(
            [zaigr, "project", "setup", "run", "recheck-marker"],
            cwd=project.cwd,
            env=project.env,
            input="y\n",
            timeout=180,
        )
        assert rc == 0, err_msg(stdout, stderr)
    stdout, stderr, rc = _run(
        [zaigr, "project", "vm", "start"], cwd=second.cwd, env=second.env, input="y\n", timeout=180
    )
    assert rc == 0, err_msg(stdout, stderr)
    details, stderr, rc = _run(
        [zaigr, "global", "projects", "details", second.cwd.name], cwd=tmp_path, env=second.env, timeout=20
    )
    assert rc == 0, err_msg(details, stderr)
    second_pid = details.split("vm-pid: ", 1)[1].splitlines()[0]

    batch = spawn_interactive(
        f"{zaigr} global projects rebuild recheck-first recheck-second",
        cwd=tmp_path,
        env=first.env,
        timeout=600,
    )
    lock = None
    try:
        batch.expect(r"Rebuild .*\? \[y/N\]", timeout=30)
        lock_dir = first.home / ".zaigr" / "project-locks"
        lock_dir.mkdir(parents=True, exist_ok=True)
        lock = (lock_dir / f"{second.store_dir.name}.lock").open("w")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        batch.sendline("y")
        batch.expect(pexpect.EOF, timeout=500)
        batch.close()
        transcript = batch.transcript.getvalue()
    finally:
        if lock is not None:
            fcntl.flock(lock, fcntl.LOCK_UN)
            lock.close()
        if batch.isalive():
            batch.close(force=True)
    assert "recheck-first" in transcript
    assert "recheck-second" in transcript
    assert "is running in another terminal" in transcript.lower()
    assert "Rebuilt: 1" in transcript
    assert re.search(r"Failed:\s+0", transcript)
    assert "Skipped: 1" in transcript
    assert "skipped" in transcript.lower()
    assert batch.exitstatus != 0
    ps_stdout, ps_stderr, ps_rc = _run(
        ["ps", "-p", second_pid, "-o", "stat="], cwd=tmp_path, env=second.env, timeout=10
    )
    assert ps_rc == 0 and ps_stdout.strip() and not ps_stdout.strip().startswith("Z"), err_msg(ps_stdout, ps_stderr)


@pytest.mark.timeout(600)
def test_global_rebuild_rechecks_capture_created_after_preview(
    project_factory, setup_factory, tmp_path, request
):
    first = project_factory("capture-recheck-first")
    second = project_factory("capture-recheck-second")
    zaigr = first.zaigr_bin
    setup_factory(setup_name="capture-recheck-marker", script_content="true")
    for project in (first, second):
        stdout, stderr, rc = _run(
            [zaigr, "project", "setup", "run", "capture-recheck-marker"],
            cwd=project.cwd,
            env=project.env,
            input="y\n",
            timeout=180,
        )
        assert rc == 0, err_msg(stdout, stderr)
    stdout, stderr, rc = _run(
        [zaigr, "project", "vm", "start"], cwd=second.cwd, env=second.env, input="y\n", timeout=180
    )
    assert rc == 0, err_msg(stdout, stderr)
    details, stderr, rc = _run(
        [zaigr, "global", "projects", "details", second.cwd.name], cwd=tmp_path, env=second.env, timeout=20
    )
    assert rc == 0, err_msg(details, stderr)
    second_pid = details.split("vm-pid: ", 1)[1].splitlines()[0]

    batch = spawn_interactive(
        f"{zaigr} global projects rebuild capture-recheck-first capture-recheck-second",
        cwd=tmp_path,
        env=first.env,
        timeout=600,
    )
    try:
        batch.expect(r"Rebuild .*\? \[y/N\]", timeout=30)
        capture = second.store_dir / "setup-capture.json"
        request.addfinalizer(lambda: capture.unlink(missing_ok=True))
        capture.write_text("{created-after-preview", encoding="utf-8")
        batch.sendline("y")
        batch.expect(pexpect.EOF, timeout=500)
        batch.close()
        transcript = batch.transcript.getvalue()
    finally:
        if batch.isalive():
            batch.close(force=True)
    assert "capture-recheck-first" in transcript
    assert "capture-recheck-second" in transcript
    assert "capture metadata is unreadable" in transcript.lower()
    assert "Rebuilt: 1" in transcript
    assert re.search(r"Failed:\s+0", transcript)
    assert "Skipped: 1" in transcript
    assert re.search(r"\[1/2\] capture-recheck-first \([^)]+\): rebuilt, VM off", transcript)
    assert batch.exitstatus != 0
    assert capture.read_text(encoding="utf-8") == "{created-after-preview"
    ps_stdout, ps_stderr, ps_rc = _run(
        ["ps", "-p", second_pid, "-o", "stat="], cwd=tmp_path, env=second.env, timeout=10
    )
    assert ps_rc == 0 and ps_stdout.strip() and not ps_stdout.strip().startswith("Z"), err_msg(ps_stdout, ps_stderr)


@pytest.mark.timeout(900)
def test_global_rebuild_graceful_stop_failure_keeps_vm_and_continues(
    project_factory, setup_factory, tmp_path, request
):
    blocked = project_factory("graceful-stop-failure")
    healthy = project_factory("after-stop-failure")
    zaigr = blocked.zaigr_bin
    setup_factory(setup_name="stop-failure-marker", script_content="true")
    for project in (blocked, healthy):
        stdout, stderr, rc = _run(
            [zaigr, "project", "setup", "run", "stop-failure-marker"],
            cwd=project.cwd,
            env=project.env,
            input="y\n",
            timeout=180,
        )
        assert rc == 0, err_msg(stdout, stderr)
    stdout, stderr, rc = _run(
        [zaigr, "project", "vm", "start"],
        cwd=blocked.cwd,
        env=blocked.env,
        input="y\n",
        timeout=180,
    )
    assert rc == 0, err_msg(stdout, stderr)
    details, stderr, rc = _run(
        [zaigr, "global", "projects", "details", blocked.cwd.name],
        cwd=tmp_path,
        env=blocked.env,
        timeout=20,
    )
    assert rc == 0, err_msg(details, stderr)
    pid = details.split("vm-pid: ", 1)[1].splitlines()[0]
    monitor = blocked.store_dir / "runtime" / "vm.sock"
    hidden_monitor = monitor.with_name("vm.sock.hidden-for-test")
    monitor.rename(hidden_monitor)
    request.addfinalizer(lambda: hidden_monitor.rename(monitor) if hidden_monitor.exists() else None)
    image = blocked.store_dir / "project.qcow2"
    before_identity = (image.stat().st_dev, image.stat().st_ino)
    applied = blocked.store_dir / "applied-setups.json"
    before_applied = applied.read_bytes()

    stdout, stderr, rc = _run(
        [
            zaigr,
            "global",
            "projects",
            "rebuild",
            blocked.cwd.name,
            healthy.cwd.name,
            "--yes",
        ],
        cwd=tmp_path,
        env=blocked.env,
        timeout=600,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert "graceful-stop-failure" in stdout
    assert "after-stop-failure" in stdout
    assert "VM remains running; monitor is unavailable" in stderr
    assert re.search(r"Rebuilt:\s+1", stdout)
    assert re.search(r"Failed:\s+1", stdout)
    assert re.search(r"Skipped:\s+0", stdout)
    assert re.search(r"\[2/2\] after-stop-failure \([^)]+\): rebuilt, VM off", stdout)
    assert "escalat" not in (stdout + stderr).lower()
    after_identity = (image.stat().st_dev, image.stat().st_ino)
    assert after_identity == before_identity
    assert applied.read_bytes() == before_applied
    ps_stdout, ps_stderr, ps_rc = _run(
        ["ps", "-p", pid, "-o", "stat="], cwd=tmp_path, env=blocked.env, timeout=10
    )
    assert ps_rc == 0 and ps_stdout.strip() and not ps_stdout.strip().startswith("Z"), err_msg(ps_stdout, ps_stderr)
    stdout, stderr, rc = _run(
        [zaigr, "project", "vm", "start"],
        cwd=healthy.cwd,
        env=healthy.env,
        input="y\n",
        timeout=180,
    )
    assert rc == 0, err_msg(stdout, stderr)
    stdout, stderr, rc = _run(
        [zaigr, "project", "vm", "exec", "--", "true"],
        cwd=healthy.cwd,
        env=healthy.env,
        timeout=30,
    )
    assert rc == 0, err_msg(stdout, stderr)


@pytest.mark.timeout(900)
def test_global_rebuild_missing_setup_skips_before_stopping_vm(
    project_factory, tmp_path
):
    healthy = project_factory("missing-setup-healthy")
    missing = project_factory("missing-setup-blocked")
    zaigr = healthy.zaigr_bin
    for project in (healthy, missing):
        setup_dir = project.cwd / ".zaigr" / "setups" / "recorded-local"
        setup_dir.mkdir(parents=True)
        (setup_dir / "setup.script").write_text("true\n", encoding="utf-8")
        stdout, stderr, rc = _run(
            [zaigr, "project", "setup", "run", "recorded-local"],
            cwd=project.cwd,
            env=project.env,
            input="y\n",
            timeout=180,
        )
        assert rc == 0, err_msg(stdout, stderr)
    (missing.cwd / ".zaigr" / "setups" / "recorded-local").rename(
        missing.cwd / ".zaigr" / "setups" / "recorded-local.removed"
    )
    stdout, stderr, rc = _run(
        [zaigr, "project", "vm", "start"],
        cwd=missing.cwd,
        env=missing.env,
        input="y\n",
        timeout=180,
    )
    assert rc == 0, err_msg(stdout, stderr)
    details, stderr, rc = _run(
        [zaigr, "global", "projects", "details", missing.cwd.name],
        cwd=tmp_path,
        env=missing.env,
        timeout=20,
    )
    assert rc == 0, err_msg(details, stderr)
    pid = details.split("vm-pid: ", 1)[1].splitlines()[0]
    stdout, stderr, rc = _run(
        [
            zaigr,
            "global",
            "projects",
            "rebuild",
            healthy.cwd.name,
            missing.cwd.name,
            "--yes",
        ],
        cwd=tmp_path,
        env=healthy.env,
        timeout=600,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert "missing applied setup definitions:" in stdout + stderr
    assert "recorded-local" in stdout + stderr
    assert re.search(r"Rebuilt:\s+1", stdout)
    assert re.search(r"Failed:\s+0", stdout)
    assert re.search(r"Skipped:\s+1", stdout)
    assert re.search(r"\[1/1\] missing-setup-healthy \([^)]+\): rebuilt, VM off", stdout)
    ps_stdout, ps_stderr, ps_rc = _run(
        ["ps", "-p", pid, "-o", "stat="], cwd=tmp_path, env=missing.env, timeout=10
    )
    assert ps_rc == 0 and ps_stdout.strip() and not ps_stdout.strip().startswith("Z"), err_msg(ps_stdout, ps_stderr)
    stdout, stderr, rc = _run(
        [zaigr, "project", "vm", "start"],
        cwd=healthy.cwd,
        env=healthy.env,
        input="y\n",
        timeout=180,
    )
    assert rc == 0, err_msg(stdout, stderr)


@pytest.mark.timeout(300)
def test_global_rebuild_force_yes_still_skips_malformed_capture(project, setup_factory, tmp_path, request):
    zaigr = project.zaigr_bin
    setup_factory(setup_name="malformed-capture-marker", script_content="true")
    stdout, stderr, rc = _run(
        [zaigr, "project", "setup", "run", "malformed-capture-marker"],
        cwd=project.cwd,
        env=project.env,
        input="y\n",
        timeout=180,
    )
    assert rc == 0, err_msg(stdout, stderr)
    stdout, stderr, rc = _run(
        [zaigr, "project", "vm", "start"],
        cwd=project.cwd,
        env=project.env,
        input="y\n",
        timeout=180,
    )
    assert rc == 0, err_msg(stdout, stderr)
    details, stderr, rc = _run(
        [zaigr, "global", "projects", "details", project.cwd.name],
        cwd=tmp_path,
        env=project.env,
        timeout=20,
    )
    assert rc == 0, err_msg(details, stderr)
    pid = details.split("vm-pid: ", 1)[1].splitlines()[0]
    capture = project.store_dir / "setup-capture.json"
    request.addfinalizer(lambda: capture.unlink(missing_ok=True))
    capture.write_text("{malformed", encoding="utf-8")
    stdout, stderr, rc = _run(
        [
            zaigr,
            "global",
            "projects",
            "rebuild",
            project.cwd.name,
            "--force",
            "--yes",
        ],
        cwd=tmp_path,
        env=project.env,
        timeout=300,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert "capture metadata is unreadable" in (stdout + stderr).lower()
    assert capture.read_text(encoding="utf-8") == "{malformed"
    ps_stdout, ps_stderr, ps_rc = _run(
        ["ps", "-p", pid, "-o", "stat="], cwd=tmp_path, env=project.env, timeout=10
    )
    assert ps_rc == 0 and ps_stdout.strip() and not ps_stdout.strip().startswith("Z"), err_msg(ps_stdout, ps_stderr)


@pytest.mark.timeout(1200)
def test_global_rebuild_all_is_serial_and_leaves_selected_vms_off(
    project_factory, setup_factory, tmp_path
):
    projects = [
        project_factory(name) for name in ("batch-one", "batch-two", "batch-three")
    ]
    unselected = project_factory("batch-unselected")
    zaigr = projects[0].zaigr_bin
    setup_factory(
        setup_name="batch-rebuild-marker",
        script_content="printf 'batch-v1\\n' > /etc/zaigr-batch-rebuilt",
    )

    for project in projects:
        stdout, stderr, rc = _run(
            [zaigr, "project", "setup", "run", "batch-rebuild-marker"],
            cwd=project.cwd,
            env=project.env,
            input="y\n",
            timeout=180,
        )
        assert rc == 0, err_msg(stdout, stderr)
        stdout, stderr, rc = _run(
            [zaigr, "project", "vm", "stop"], cwd=project.cwd, env=project.env, timeout=60
        )
        assert rc == 0, err_msg(stdout, stderr)

    stdout, stderr, rc = _run(
        [zaigr, "project", "setup", "run", "batch-rebuild-marker"],
        cwd=unselected.cwd,
        env=unselected.env,
        input="y\n",
        timeout=180,
    )
    assert rc == 0, err_msg(stdout, stderr)
    stdout, stderr, rc = _run(
        [zaigr, "project", "vm", "stop"], cwd=unselected.cwd, env=unselected.env, timeout=60
    )
    assert rc == 0, err_msg(stdout, stderr)
    stdout, stderr, rc = _run(
        [zaigr, "project", "vm", "start"], cwd=unselected.cwd,
        env=unselected.env, input="y\n", timeout=180
    )
    assert rc == 0, err_msg(stdout, stderr)
    details, stderr, rc = _run(
        [zaigr, "global", "projects", "details", unselected.cwd.name],
        cwd=tmp_path, env=unselected.env, timeout=20
    )
    assert rc == 0, err_msg(details, stderr)
    unselected_pid = details.split("vm-pid: ", 1)[1].splitlines()[0]
    setup_factory(
        setup_name="batch-rebuild-marker",
        script_content="printf 'batch-v2\\n' > /etc/zaigr-batch-rebuilt",
    )

    stdout, stderr, rc = _run(
        [zaigr, "project", "vm", "start", "--ram", "768", "--cpu", "sockets=1,cpus=2,cores=2"],
        cwd=projects[1].cwd,
        env=projects[1].env,
        input="y\n",
        timeout=180,
    )
    assert rc == 0, err_msg(stdout, stderr)
    stdout, stderr, rc = _run(
        [
            zaigr,
            "global",
            "projects",
            "rebuild",
            "batch-one",
            "batch-two",
            "batch-three",
            "--yes",
        ],
        cwd=tmp_path,
        env=projects[0].env,
        timeout=600,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert "batch-one" in stdout
    assert "batch-two" in stdout
    assert "batch-three" in stdout
    assert "Rebuilt: 3" in stdout
    progress = re.findall(
        r"\[[1-3]/3\] (batch-\w+) \([^)]+\): (rebuilding\.\.\.|rebuilt, VM off)",
        stdout,
    )
    assert progress == [
        ("batch-one", "rebuilding..."),
        ("batch-one", "rebuilt, VM off"),
        ("batch-two", "rebuilding..."),
        ("batch-two", "rebuilt, VM off"),
        ("batch-three", "rebuilding..."),
        ("batch-three", "rebuilt, VM off"),
    ]

    listing, stderr, rc = _run(
        [zaigr, "global", "projects", "list"],
        cwd=tmp_path,
        env=projects[0].env,
        timeout=20,
    )
    assert rc == 0, err_msg(listing, stderr)
    for name in ("batch-one", "batch-two", "batch-three"):
        row = next(line for line in listing.splitlines() if line.startswith(name))
        assert row.split()[1].startswith("off")

    for project in projects:
        stdout, stderr, rc = _run(
            [zaigr, "project", "vm", "start"],
            cwd=project.cwd,
            env=project.env,
            input="y\n",
            timeout=180,
        )
        assert rc == 0, err_msg(stdout, stderr)
        marker, stderr, rc = _run(
            [zaigr, "project", "vm", "exec", "--", "cat", "/etc/zaigr-batch-rebuilt"],
            cwd=project.cwd,
            env=project.env,
            timeout=30,
        )
        assert rc == 0, err_msg(marker, stderr)
        assert marker.strip() == "batch-v2"

    marker, stderr, rc = _run(
        [zaigr, "project", "vm", "exec", "--", "cat", "/etc/zaigr-batch-rebuilt"],
        cwd=unselected.cwd, env=unselected.env, timeout=30
    )
    assert rc == 0, err_msg(marker, stderr)
    assert marker.strip() == "batch-v1"
    ps_stdout, ps_stderr, ps_rc = _run(
        ["ps", "-p", unselected_pid, "-o", "stat="],
        cwd=tmp_path, env=unselected.env, timeout=10
    )
    assert ps_rc == 0 and ps_stdout.strip() and not ps_stdout.strip().startswith("Z"), err_msg(ps_stdout, ps_stderr)


@pytest.mark.timeout(1200)
def test_global_rebuild_failure_keeps_middle_image_and_continues(
    project_factory, tmp_path
):
    projects = [
        project_factory(name) for name in ("healthy-one", "failing", "healthy-two")
    ]
    zaigr = projects[0].zaigr_bin
    for project in projects:
        local_setup = project.cwd / ".zaigr" / "setups" / "batch-local"
        local_setup.mkdir(parents=True)
        (local_setup / "setup.script").write_text(
            "printf 'batch-local-ok\\n' > /etc/zaigr-batch-local\n",
            encoding="utf-8",
        )
        stdout, stderr, rc = _run(
            [zaigr, "project", "setup", "run", "batch-local"],
            cwd=project.cwd,
            env=project.env,
            input="y\n",
            timeout=180,
        )
        assert rc == 0, err_msg(stdout, stderr)
        stdout, stderr, rc = _run(
            [zaigr, "project", "vm", "stop"], cwd=project.cwd, env=project.env, timeout=60
        )
        assert rc == 0, err_msg(stdout, stderr)

    middle = projects[1]
    image = middle.store_dir / "project.qcow2"
    applied = middle.store_dir / "applied-setups.json"
    image_identity = (image.stat().st_dev, image.stat().st_ino)
    image_digest = hashlib.sha256(image.read_bytes()).digest()
    applied_before = applied.read_bytes()
    (middle.cwd / ".zaigr" / "setups" / "batch-local" / "setup.script").write_text(
        "printf 'failure-before-mutation\\n'\nexit 42\n", encoding="utf-8"
    )

    stdout, stderr, rc = _run(
        [
            zaigr,
            "global",
            "projects",
            "rebuild",
            "healthy-one",
            "failing",
            "healthy-two",
            "--yes",
        ],
        cwd=tmp_path,
        env=projects[0].env,
        timeout=600,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert "failing" in stdout
    assert "failed" in stdout.lower()
    assert "healthy-two" in stdout
    assert "2 rebuilt, 1 failed, and 0 skipped" in stderr
    assert (image.stat().st_dev, image.stat().st_ino) == image_identity
    assert hashlib.sha256(image.read_bytes()).digest() == image_digest
    assert applied.read_bytes() == applied_before
    assert "Remove the failing setup and restart the rebuild?" not in (stdout + stderr)
    for project in projects:
        details, stderr, rc = _run(
            [zaigr, "global", "projects", "details", project.cwd.name],
            cwd=tmp_path, env=project.env, timeout=20,
        )
        assert rc == 0, err_msg(details, stderr)
        assert "status: off\n" in details
    for project in (projects[0], projects[2]):
        stdout, stderr, rc = _run(
            [zaigr, "project", "vm", "start"],
            cwd=project.cwd, env=project.env, input="y\n", timeout=180
        )
        assert rc == 0, err_msg(stdout, stderr)
        marker, stderr, rc = _run(
            [zaigr, "project", "vm", "exec", "--", "cat", "/etc/zaigr-batch-local"],
            cwd=project.cwd, env=project.env, timeout=30
        )
        assert rc == 0, err_msg(marker, stderr)
        assert marker.strip() == "batch-local-ok"
