"""Public recovery boundaries for virtiofs VM ownership."""

import json
import signal
import time
from functools import partial
from pathlib import Path

import pytest

from ..conftest import err_msg, spawn_interactive
from ..conftest import run as _run
from .test_virtiofs_failures import _wait_clean
from .test_virtiofs_lifecycle import _verified_signal


def _checked_run(command, **kwargs):
    stdout, stderr, code = _run(command, **kwargs)
    assert code == 0, err_msg(stdout, stderr)
    return stdout


@pytest.mark.timeout(300)
def test_comma_and_spaces_in_home_support_both_mounts_and_stop(project, test_root):
    project.home = test_root / "h, s"
    project.home.mkdir()
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    run([zaigr, "project", "vm", "start"], input="y\n", timeout=180)
    assert run([zaigr, "project", "vm", "exec", "--", "findmnt", "-n", "-o", "FSTYPE", "/home/user/workspace"]).strip() == "virtiofs"
    assert run([zaigr, "project", "vm", "exec", "--", "findmnt", "-n", "-o", "FSTYPE", "/home/user/.zaigr-agent-state"]).strip() == "virtiofs"
    run([zaigr, "project", "vm", "stop"], timeout=60)
    assert not (project.store_dir / "vm-supervisor.json").exists()


@pytest.mark.timeout(240)
def test_image_identity_probe_uses_store_disk_when_tmpdir_is_unusable(project):
    zaigr = project.zaigr_bin
    run = partial(_checked_run, cwd=project.cwd, env=project.env)

    run([zaigr, "project", "vm", "start"], input="y\n", timeout=180)
    run([zaigr, "project", "vm", "stop"], timeout=60)
    store = project.store_dir
    assert (store / "project.qcow2").exists()
    blocked_tmp = project.home / "not-a-directory"
    blocked_tmp.write_text("blocked\n", encoding="utf-8")
    env = project.env
    env["TMPDIR"] = str(blocked_tmp)

    stdout, stderr, code = _run(
        [zaigr, "project", "vm", "start"],
        cwd=project.cwd, env=env, timeout=180,
    )
    assert code == 0, err_msg(stdout, stderr)
    assert not list(store.glob(".zaigr-identity-*.raw"))
    assert _checked_run(
        [zaigr, "project", "vm", "exec", "--", "findmnt", "-n", "-o", "FSTYPE", "/home/user/workspace"],
        cwd=project.cwd, env=project.env,
    ).strip() == "virtiofs"
    run([zaigr, "project", "vm", "stop"], timeout=60)
    assert not list(store.glob(".zaigr-identity-*.raw"))


@pytest.mark.timeout(180)
def test_overlong_runtime_socket_path_fails_before_owned_children(project, test_root):
    project.home = test_root / ("long-home-" + "x" * 75)
    project.home.mkdir()
    zaigr = project.zaigr_bin

    stdout, stderr, code = _run(
        [zaigr, "project", "vm", "start"],
        cwd=project.cwd,
        env=project.env,
        input="y\n",
        timeout=120,
    )
    assert code != 0, err_msg(stdout, stderr)
    assert "Unix socket path exceeds Linux's 107-byte limit" in stdout + stderr
    assert not (project.store_dir / "vm-supervisor.json").exists()
    assert not (project.store_dir / "runtime" / "virtiofsd-workspace.sock").exists()
    assert not (project.store_dir / "runtime" / "virtiofsd-agent-state.sock").exists()


@pytest.mark.timeout(240)
def test_live_owner_and_unconfirmed_record_preserve_project_state(project):
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    workspace = project.cwd / "ownership-canary"
    workspace.write_text("workspace stays\n", encoding="utf-8")

    run([zaigr, "project", "vm", "start"], input="y\n", timeout=180)
    store = project.store_dir
    state = store / "agent-state" / "ownership-canary"
    state.write_text("state stays\n", encoding="utf-8")
    record_path = store / "vm-supervisor.json"
    original_record = record_path.read_bytes()
    assert json.loads(original_record)["qemu"]["pid"] > 0

    for command in (
        [zaigr, "project", "clean"],
        [zaigr, "project", "rebuild", "--force"],
        [zaigr, "project", "delete", "--force"],
    ):
        stdout, stderr, code = _run(command, cwd=project.cwd, env=project.env, timeout=20)
        assert code != 0, err_msg(stdout, stderr)
        assert record_path.read_bytes() == original_record
        assert workspace.read_text(encoding="utf-8") == "workspace stays\n"
        assert state.read_text(encoding="utf-8") == "state stays\n"

    run([zaigr, "project", "vm", "stop", "--abrupt"], timeout=60)
    damaged = json.loads(original_record)
    damaged["qemu"]["start_time"] = ""
    runtime = store / "runtime"
    runtime.mkdir(exist_ok=True)
    marker = runtime / "owned-cleanup-uncertain"
    marker.write_text("retain\n", encoding="utf-8")
    record_path.write_text(json.dumps(damaged), encoding="utf-8")
    try:
        for command in (
            [zaigr, "project", "clean"],
            [zaigr, "project", "rebuild", "--force"],
            [zaigr, "project", "delete", "--force"],
        ):
            stdout, stderr, code = _run(command, cwd=project.cwd, env=project.env, timeout=20)
            assert code != 0, err_msg(stdout, stderr)
            assert marker.read_text(encoding="utf-8") == "retain\n"
            assert record_path.exists()
            assert workspace.read_text(encoding="utf-8") == "workspace stays\n"
            assert state.read_text(encoding="utf-8") == "state stays\n"
    finally:
        record_path.unlink(missing_ok=True)


@pytest.mark.timeout(300)
def test_attached_teardown_uncertainty_retains_global_staging(project, setup_factory, tmp_path):
    """A stopped supervisor keeps publication and staged cleanup blocked."""
    zaigr = project.zaigr_bin
    env = project.env
    env.update({"ZAIGR_VM_RAM": "512", "ZAIGR_VM_CPU": "1", "ZAIGR_DISK_SIZE": "8G"})
    setup_factory("teardown-proof", "printf 'TEARDOWN_PROOF_READY\\n'\nsleep 8")
    staging_root = project.home / ".zaigr/base-images/custom/staging"
    custom_root = staging_root.parent
    current = custom_root / "current.json"
    build = spawn_interactive(
        f"{zaigr} global base-image setup run teardown-proof",
        cwd=tmp_path, env=env, timeout=180,
    )
    record = None
    suspended = False
    try:
        build.expect_exact("TEARDOWN_PROOF_READY", timeout=150)
        stages = list(staging_root.glob("build-*"))
        assert len(stages) == 1
        stage = stages[0]
        record_path = stage / "runtime-store/vm-supervisor.json"
        record = json.loads(record_path.read_text(encoding="utf-8"))
        original_selection = current.read_bytes() if current.exists() else None
        _verified_signal(record["supervisor"], signal.SIGSTOP)
        suspended = True

        deadline = time.monotonic() + 90
        while build.isalive() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert not build.isalive(), "the build did not finish its bounded setup and teardown"
        # The deliberately stopped supervisor still owns the inherited PTY,
        # so EOF cannot be used as the launcher-death oracle here.
        build.close()
        assert build.exitstatus != 0 or build.signalstatus is not None
        assert stage.exists()
        assert record_path.exists()
        assert (custom_root / "vm-supervisor.log").exists()
        assert (stage / "working.qcow2").exists()
        assert (stage / "workspace").is_dir()
        assert (stage / "agent-state").is_dir()
        assert (current.read_bytes() if current.exists() else None) == original_selection

        started = time.monotonic()
        stdout, stderr, code = _run(
            [zaigr, "global", "base-image", "setup", "run", "teardown-proof"],
            cwd=tmp_path, env=env, timeout=35,
        )
        assert code != 0, err_msg(stdout, stderr)
        assert "VM operation in progress; cannot run global base staging cleanup" in stdout + stderr
        assert 20 <= time.monotonic() - started < 35
        assert stage.exists() and record_path.exists()
        assert (custom_root / "vm-supervisor.log").exists()
        assert (stage / "working.qcow2").exists()
        assert (stage / "workspace").is_dir()
        assert (stage / "agent-state").is_dir()
        assert (current.read_bytes() if current.exists() else None) == original_selection

        # Removing the lock pathname does not release the supervisor's open
        # lock. Its record must still prevent destruction of this staging VM.
        lock_path = stage / "runtime-store/vm-supervisor.lock"
        saved_lock = stage / "runtime-store/saved-lifetime-lock"
        lock_path.rename(saved_lock)
        try:
            stdout, stderr, code = _run(
                [zaigr, "global", "base-image", "setup", "run", "teardown-proof"],
                cwd=tmp_path, env=env, timeout=35,
            )
            assert code != 0, err_msg(stdout, stderr)
            assert "previous VM supervisor is still live" in stdout + stderr
            assert record_path.exists()
            assert (stage / "working.qcow2").exists()
            assert (stage / "workspace").is_dir()
            assert (stage / "agent-state").is_dir()
            assert (current.read_bytes() if current.exists() else None) == original_selection
        finally:
            saved_lock.rename(lock_path)
    finally:
        if suspended:
            try:
                _verified_signal(record["supervisor"], signal.SIGCONT)
            except (FileNotFoundError, ProcessLookupError):
                pass
        if build.isalive():
            build.close(force=True)
        if suspended:
            _wait_clean(record, record_path, timeout=30)


@pytest.mark.timeout(360)
def test_same_workspace_in_two_homes_has_independent_socket_ownership(project_factory, test_root):
    first = project_factory("shared-workspace")
    second = project_factory("unused-workspace")
    second.cwd = first.cwd
    second.home = test_root / "second-home"
    second.home.mkdir()
    zaigr = first.zaigr_bin
    one = partial(_checked_run, cwd=first.cwd, env=first.env)
    two = partial(_checked_run, cwd=second.cwd, env=second.env)

    one([zaigr, "project", "vm", "start"], input="y\n", timeout=180)
    first_record = json.loads((first.store_dir / "vm-supervisor.json").read_text())
    first_sockets = Path(first_record["socket_dir"])
    two([zaigr, "project", "vm", "start"], input="y\n", timeout=180)
    second_record = json.loads((second.store_dir / "vm-supervisor.json").read_text())
    second_sockets = Path(second_record["socket_dir"])
    assert first_sockets != second_sockets
    for root in (first_sockets, second_sockets):
        assert (root / "workspace.sock").is_socket()
        assert (root / "agent-state.sock").is_socket()
        assert root.stat().st_mode & 0o777 == 0o700
    one([zaigr, "project", "vm", "exec", "--", "tee", "/home/user/workspace/shared-canary"], input="workspace persisted\n")
    assert two([zaigr, "project", "vm", "exec", "--", "cat", "/home/user/workspace/shared-canary"]) == "workspace persisted\n"
    one([zaigr, "project", "vm", "stop"], timeout=60)
    assert not first_sockets.exists()
    assert second_sockets.is_dir()
    assert two([zaigr, "project", "vm", "exec", "--", "findmnt", "-n", "-o", "FSTYPE", "/home/user/workspace"]).strip() == "virtiofs"
    one([zaigr, "project", "vm", "start"], timeout=180)
    restarted = json.loads((first.store_dir / "vm-supervisor.json").read_text())
    assert restarted["socket_dir"] not in (str(first_sockets), str(second_sockets))
    assert one([zaigr, "project", "vm", "exec", "--", "cat", "/home/user/workspace/shared-canary"]) == "workspace persisted\n"
