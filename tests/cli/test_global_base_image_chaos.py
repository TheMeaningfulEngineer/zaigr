"""Failure and recovery coverage for the documented global base image store."""

import hashlib
import json
import os
import shutil
import signal
import time
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from pathlib import Path

import pexpect
import pytest

from ..conftest import err_msg, spawn_interactive
from ..conftest import run as _run


@pytest.fixture(autouse=True)
def small_vm_resources(monkeypatch):
    """Keep independent test homes economical during parallel VM runs."""
    monkeypatch.setenv("ZAIGR_VM_RAM", "512")
    monkeypatch.setenv("ZAIGR_VM_CPU", "1")
    monkeypatch.setenv("ZAIGR_DISK_SIZE", "8G")


def _checked_run(cmd, **kwargs):
    """Record a visible command and return its successful stdout."""
    stdout, stderr, rc = _run(cmd, **kwargs)
    assert rc == 0, err_msg(stdout, stderr)
    return stdout


def _staging_qemu_pids(home):
    """Find only QEMU processes using this test home's documented staging tree."""
    staging = str(home / ".zaigr/base-images/custom/staging").encode()
    pids = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            command = (entry / "cmdline").read_bytes()
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        if (
            command.split(b"\0", 1)[0].endswith(b"qemu-system-x86_64")
            and staging in command
        ):
            pids.append(int(entry.name))
    return pids


@pytest.mark.timeout(900)
def test_firewall_version_removal_respects_other_setup_owners(
    project_factory, setup_factory, tmp_path
):
    """A removed hostname survives shared ownership, then becomes blocked."""
    shared = project_factory("shared-firewall")
    removed = project_factory("removed-firewall")
    zaigr = shared.zaigr_bin
    run = partial(_checked_run, env=shared.env)
    global_run = partial(run, cwd=tmp_path)
    setup_factory(
        "network-owner",
        "printf 'owner-v1\\n' > /etc/network-owner",
        firewall=["pypi.org"],
    )
    setup_factory(
        "network-sharer",
        "printf 'sharer-v1\\n' > /etc/network-sharer",
        firewall=["pypi.org", "github.com"],
    )
    global_run(
        "curl -4 -fsS -o /dev/null --connect-timeout 5 --max-time 15 https://pypi.org",
        timeout=20,
    )
    global_run(
        "curl -4 -fsS -o /dev/null --connect-timeout 5 --max-time 15 https://github.com",
        timeout=20,
    )
    global_run(
        f"{zaigr} global base-image setup run network-owner network-sharer", timeout=180
    )

    setup_factory(
        "network-owner", "printf 'owner-v2\\n' > /etc/network-owner", firewall=[]
    )
    global_run(f"{zaigr} global base-image setup run network-owner", timeout=180)
    run(f"{zaigr} project vm start", cwd=shared.cwd, input="y\n", timeout=180)
    run(
        f"{zaigr} project vm exec -- curl -4 -fsS -o /dev/null --connect-timeout 5 --max-time 15 https://pypi.org",
        cwd=shared.cwd,
        timeout=20,
    )
    run(
        f"{zaigr} project vm exec -- curl -4 -fsS -o /dev/null --connect-timeout 5 --max-time 15 https://github.com",
        cwd=shared.cwd,
        timeout=20,
    )
    run(f"{zaigr} project vm stop", cwd=shared.cwd, timeout=60)

    before_failure = global_run(f"{zaigr} global base-image status", timeout=10)
    # The installer really removes a utility needed by the following reconciliation.
    setup_factory(
        "network-sharer",
        "rm /usr/bin/mv\nprintf 'RECONCILIATION_FAILURE_READY\\n'",
        firewall=["github.com"],
    )
    stdout, stderr, rc = _run(
        f"{zaigr} global base-image setup run network-sharer",
        cwd=tmp_path,
        env=shared.env,
        timeout=180,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert "RECONCILIATION_FAILURE_READY" in stdout
    assert "reconcile global base image firewall" in stdout + stderr
    assert "panic" not in stdout + stderr
    assert global_run(f"{zaigr} global base-image status", timeout=10) == before_failure
    setup_factory(
        "network-sharer",
        "printf 'sharer-v2\\n' > /etc/network-sharer",
        firewall=["github.com"],
    )
    global_run(f"{zaigr} global base-image setup run network-sharer", timeout=180)
    run(f"{zaigr} project vm start", cwd=removed.cwd, input="y\n", timeout=180)
    run(
        f"{zaigr} project vm exec -- curl -4 -fsS -o /dev/null --connect-timeout 5 --max-time 15 https://github.com",
        cwd=removed.cwd,
        timeout=20,
    )
    stdout, stderr, rc = _run(
        f"{zaigr} project vm exec -- curl -4 -fsS -o /dev/null --connect-timeout 3 --max-time 8 https://pypi.org",
        cwd=removed.cwd,
        env=removed.env,
        timeout=20,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert (
        run(
            f"{zaigr} project vm exec -- cat /etc/network-owner /etc/network-sharer",
            cwd=removed.cwd,
            timeout=20,
        )
        == "owner-v2\nsharer-v2\n"
    )
    run(f"{zaigr} project vm start", cwd=shared.cwd, timeout=180)
    run(
        f"{zaigr} project vm exec -- curl -4 -fsS -o /dev/null --connect-timeout 5 --max-time 15 https://pypi.org",
        cwd=shared.cwd,
        timeout=20,
    )


@pytest.mark.timeout(600)
def test_corrupt_current_selection_fails_and_reset_preserves_pinned_projects(
    project_factory, setup_factory, tmp_path
):
    """Real manifest and source damage cannot silently select the factory image."""
    pinned = project_factory("pinned")
    fresh = project_factory("fresh")
    zaigr = pinned.zaigr_bin
    run = partial(_checked_run, env=pinned.env)
    global_run = partial(run, cwd=tmp_path)
    setup_factory("damage-probe", "printf 'custom-survives\\n' > /etc/damage-probe")
    global_run(f"{zaigr} global base-image setup run damage-probe", timeout=180)
    run(f"{zaigr} project vm start", cwd=pinned.cwd, input="y\n", timeout=180)
    manifest_path = pinned.home / ".zaigr/base-images/custom/current.json"
    original = manifest_path.read_bytes()
    manifest = json.loads(original)
    invalid_name = json.loads(original)
    invalid_name["applied_setups"][0]["name"] = "../outside"
    invalid_name["setup_firewall"]["../outside"] = invalid_name["setup_firewall"].pop(
        "damage-probe"
    )
    variants = [
        ("invalid applied name", json.dumps(invalid_name).encode()),
        ("truncated JSON", b'{"schema":'),
        (
            "invalid revision",
            json.dumps(dict(manifest, revision="../outside")).encode(),
        ),
        (
            "duplicate applied setup",
            json.dumps(
                dict(manifest, applied_setups=manifest["applied_setups"] * 2)
            ).encode(),
        ),
        (
            "runtime mismatch",
            json.dumps(
                dict(manifest, runtime_version="older-bundled-runtime")
            ).encode(),
        ),
    ]
    for description, damaged in variants:
        manifest_path.write_bytes(damaged)
        stdout, stderr, rc = _run(
            f"{zaigr} global base-image status",
            cwd=tmp_path,
            env=pinned.env,
            timeout=10,
            context=description,
        )
        assert rc != 0, err_msg(stdout, stderr)
        assert "base-image reset" in stdout + stderr
        stdout, stderr, rc = _run(
            f"{zaigr} project vm start",
            cwd=fresh.cwd,
            env=fresh.env,
            input="y\n",
            timeout=30,
            context=description,
        )
        assert rc != 0, err_msg(stdout, stderr)
        assert "base-image reset" in stdout + stderr
        assert (
            run(
                f"{zaigr} project vm exec -- cat /etc/damage-probe",
                cwd=pinned.cwd,
                timeout=20,
            )
            == "custom-survives\n"
        )
        global_run(f"{zaigr} global base-image reset", timeout=30)
        assert "factory" in global_run(f"{zaigr} global base-image status", timeout=10)
    manifest_path.write_bytes(original)

    source = Path(manifest["source_image"])
    backup = source.with_suffix(".saved")
    source.rename(backup)
    for description in ("missing source", "truncated source"):
        if description == "truncated source":
            shutil.copyfile(backup, source)
            with source.open("r+b") as image:
                image.truncate(source.stat().st_size // 2)
        stdout, stderr, rc = _run(
            f"{zaigr} global base-image status",
            cwd=tmp_path,
            env=pinned.env,
            timeout=10,
            context=description,
        )
        assert rc != 0, err_msg(stdout, stderr)
        assert "base-image reset" in stdout + stderr
        stdout, stderr, rc = _run(
            f"{zaigr} project vm start",
            cwd=fresh.cwd,
            env=fresh.env,
            input="y\n",
            timeout=30,
            context=description,
        )
        assert rc != 0, err_msg(stdout, stderr)
        assert "base-image reset" in stdout + stderr
    run(f"{zaigr} project vm stop", cwd=pinned.cwd, timeout=60)
    run(f"{zaigr} project vm start", cwd=pinned.cwd, timeout=180)
    assert (
        run(
            f"{zaigr} project vm exec -- cat /etc/damage-probe",
            cwd=pinned.cwd,
            timeout=20,
        )
        == "custom-survives\n"
    )
    global_run(f"{zaigr} global base-image reset", timeout=30)
    assert "factory" in global_run(f"{zaigr} global base-image status", timeout=10)
    run(f"{zaigr} project vm start", cwd=fresh.cwd, input="y\n", timeout=180)
    run(
        f"{zaigr} project vm exec -- test ! -e /etc/damage-probe",
        cwd=fresh.cwd,
        timeout=20,
    )


@pytest.mark.timeout(300)
def test_missing_build_control_socket_does_not_leave_hung_cli_or_vm(
    zaigr_bin, zaigr_home, setup_factory, tmp_path
):
    """Losing this build's real QMP socket still terminates a failed installer VM."""
    run = partial(_checked_run, cwd=tmp_path)
    setup_factory("qmp-failure", "printf 'QMP_FAILURE_READY\\n'\nsleep 8\nexit 42")
    update = spawn_interactive(
        f"{zaigr_bin} global base-image setup run qmp-failure",
        cwd=tmp_path,
        timeout=120,
    )
    try:
        update.expect_exact("QMP_FAILURE_READY", timeout=120)
        pids = _staging_qemu_pids(zaigr_home)
        assert len(pids) == 1, pids
        args = Path(f"/proc/{pids[0]}/cmdline").read_bytes().decode().split("\0")
        control = args[args.index("-qmp") + 1]
        socket = Path(control.removeprefix("unix:").split(",", 1)[0])
        assert socket.is_socket()
        socket.unlink()
        update.expect(pexpect.EOF, timeout=45)
        update.close()
        assert update.exitstatus != 0
        assert not _staging_qemu_pids(zaigr_home)
    finally:
        # Only runtime processes belonging to this fault injection are eligible.
        for pid in _staging_qemu_pids(zaigr_home):
            run(["kill", "-KILL", str(pid)], timeout=10)
        if update.isalive():
            update.close(force=True)
    assert "factory" in run(f"{zaigr_bin} global base-image status", timeout=10)
    setup_factory("qmp-failure", "printf 'QMP_RECOVERED\\n'")
    run(f"{zaigr_bin} global base-image setup run qmp-failure", timeout=180)
    assert "qmp-failure" in run(f"{zaigr_bin} global base-image status", timeout=10)


@pytest.mark.timeout(600)
def test_reset_during_update_preserves_shared_immutable_project_backings(
    project_factory, setup_factory, tmp_path
):
    """A completed concurrent reset stays factory while old projects share their pin."""
    first = project_factory("first-pin")
    sibling = project_factory("second-pin")
    fresh = project_factory("after-reset")
    zaigr = first.zaigr_bin
    run = partial(_checked_run, env=first.env)
    global_run = partial(run, cwd=tmp_path)
    setup_factory("pin-probe", "cat /proc/sys/kernel/random/uuid > /etc/pin-probe")
    setup_factory(
        "racing-update",
        "printf 'staged\\n' > /etc/racing-update\nprintf 'RESET_RACE_READY\\n'\nsleep 8",
    )
    global_run(f"{zaigr} global base-image setup run pin-probe", timeout=180)
    run(f"{zaigr} project vm start", cwd=first.cwd, input="y\n", timeout=180)
    original = run(
        f"{zaigr} project vm exec -- cat /etc/pin-probe", cwd=first.cwd, timeout=20
    )
    run(f"{zaigr} project vm start", cwd=sibling.cwd, input="y\n", timeout=180)
    assert (
        run(
            f"{zaigr} project vm exec -- cat /etc/pin-probe",
            cwd=sibling.cwd,
            timeout=20,
        )
        == original
    )
    first_pin = json.loads((first.store_dir / "base-backing.json").read_text())
    second_pin = json.loads((sibling.store_dir / "base-backing.json").read_text())
    assert first_pin["path"] == second_pin["path"]
    manifest = json.loads(
        (first.home / ".zaigr/base-images/custom/current.json").read_text()
    )
    published = [Path(first_pin["path"]), Path(manifest["source_image"])]
    before = []
    for path in published:
        assert path.stat().st_mode & 0o222 == 0
        with path.open("rb") as image:
            before.append(
                (path.stat().st_ino, hashlib.file_digest(image, "sha256").hexdigest())
            )
    update = spawn_interactive(
        f"{zaigr} global base-image setup run racing-update",
        cwd=tmp_path,
        env=first.env,
        timeout=180,
    )
    try:
        update.expect_exact("RESET_RACE_READY", timeout=120)
        with ThreadPoolExecutor(max_workers=1) as pool:
            reset = pool.submit(
                _run,
                f"{zaigr} global base-image reset",
                cwd=tmp_path,
                env=first.env,
                timeout=180,
            )
            update.expect(pexpect.EOF, timeout=180)
            update.close()
            assert update.exitstatus == 0
            stdout, stderr, rc = reset.result(timeout=180)
        if rc != 0:
            assert "busy" in (stdout + stderr).lower(), err_msg(stdout, stderr)
            global_run(f"{zaigr} global base-image reset", timeout=30)
    finally:
        if update.isalive():
            update.close(force=True)
    assert "factory" in global_run(f"{zaigr} global base-image status", timeout=10)
    run(f"{zaigr} project vm start", cwd=fresh.cwd, input="y\n", timeout=180)
    run(
        f"{zaigr} project vm exec -- test ! -e /etc/pin-probe",
        cwd=fresh.cwd,
        timeout=20,
    )
    run(
        f"{zaigr} project vm exec -- test ! -e /etc/racing-update",
        cwd=fresh.cwd,
        timeout=20,
    )
    assert "factory" in global_run(f"{zaigr} global base-image status", timeout=10)
    for path, expected in zip(published, before):
        with path.open("rb") as image:
            assert (
                path.stat().st_ino,
                hashlib.file_digest(image, "sha256").hexdigest(),
            ) == expected
    run(f"{zaigr} project vm stop", cwd=first.cwd, timeout=60)
    run(f"{zaigr} project vm start", cwd=first.cwd, timeout=180)
    assert (
        run(f"{zaigr} project vm exec -- cat /etc/pin-probe", cwd=first.cwd, timeout=20)
        == original
    )
    assert (
        run(
            f"{zaigr} project vm exec -- cat /etc/pin-probe",
            cwd=sibling.cwd,
            timeout=20,
        )
        == original
    )


@pytest.mark.parametrize(
    "stop_signal", [signal.SIGTERM, signal.SIGKILL], ids=["sigterm", "sigkill"]
)
@pytest.mark.timeout(600)
def test_killed_build_has_no_orphan_and_next_mutation_recovers(
    project_factory, setup_factory, tmp_path, stop_signal
):
    """Direct CLI termination never publishes partial files or strands its QEMU."""
    fresh = project_factory("after-kill")
    zaigr = fresh.zaigr_bin
    run = partial(_checked_run, cwd=tmp_path, env=fresh.env)
    setup_factory("kill-base", "printf 'last-good\\n' > /etc/kill-base")
    setup_factory(
        "kill-update",
        "printf 'partial\\n' > /etc/kill-partial\nprintf 'KILL_BUILD_READY\\n'\nsleep 300",
    )
    run(f"{zaigr} global base-image setup run kill-base", timeout=180)
    manifest_path = fresh.home / ".zaigr/base-images/custom/current.json"
    original = manifest_path.read_bytes()
    staging = manifest_path.parent / "staging"
    update = spawn_interactive(
        f"{zaigr} global base-image setup run kill-update",
        cwd=tmp_path,
        env=fresh.env,
        timeout=180,
    )
    try:
        update.expect_exact("KILL_BUILD_READY", timeout=120)
        assert len(_staging_qemu_pids(fresh.home)) == 1
        assert list(staging.glob("build-*"))
        run(["kill", f"-{stop_signal.value}", str(update.pid)], timeout=10)
        update.expect(pexpect.EOF, timeout=60)
        update.close()
        assert update.exitstatus != 0 or update.signalstatus is not None
        deadline = time.monotonic() + 5
        while _staging_qemu_pids(fresh.home) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert not _staging_qemu_pids(fresh.home)
        if stop_signal == signal.SIGTERM:
            assert not list(staging.glob("build-*"))
    finally:
        for pid in _staging_qemu_pids(fresh.home):
            run(["kill", "-KILL", str(pid)], timeout=10)
        if update.isalive():
            update.close(force=True)
    assert manifest_path.read_bytes() == original
    setup_factory("kill-update", "printf 'recovered\\n' > /etc/kill-update")
    run(f"{zaigr} global base-image setup run kill-update", timeout=180)
    assert not list(staging.glob("build-*"))
    run(f"{zaigr} project vm start", cwd=fresh.cwd, input="y\n", timeout=180)
    assert (
        run(
            f"{zaigr} project vm exec -- cat /etc/kill-base /etc/kill-update",
            cwd=fresh.cwd,
            timeout=20,
        )
        == "last-good\nrecovered\n"
    )
    run(
        f"{zaigr} project vm exec -- test ! -e /etc/kill-partial",
        cwd=fresh.cwd,
        timeout=20,
    )


@pytest.mark.timeout(600)
def test_publication_permission_failure_keeps_previous_default_and_recovers(
    project_factory, setup_factory, tmp_path
):
    """A real directory permission failure after installation cannot replace current."""
    assert os.geteuid() != 0, (
        "This fault injection requires unprivileged host permissions"
    )
    fresh = project_factory("after-publication-failure")
    zaigr = fresh.zaigr_bin
    run = partial(_checked_run, env=fresh.env)
    global_run = partial(run, cwd=tmp_path)
    setup_factory("publish-base", "printf 'published\\n' > /etc/publish-base")
    setup_factory(
        "publish-update",
        "printf 'unpublished\\n' > /etc/publish-update\nprintf 'PUBLICATION_FAULT_READY\\n'\nsleep 8",
    )
    global_run(f"{zaigr} global base-image setup run publish-base", timeout=180)
    root = fresh.home / ".zaigr/base-images/custom"
    original = (root / "current.json").read_bytes()
    update = spawn_interactive(
        f"{zaigr} global base-image setup run publish-update",
        cwd=tmp_path,
        env=fresh.env,
        timeout=180,
    )
    try:
        update.expect_exact("PUBLICATION_FAULT_READY", timeout=120)
        root.chmod(0o500)
        update.expect(pexpect.EOF, timeout=180)
        output = update.before
        update.close()
        assert update.exitstatus != 0
        assert "publish global base image selection" in output
        assert "permission denied" in output.lower()
    finally:
        root.chmod(0o755)
        if update.isalive():
            update.close(force=True)
    assert (root / "current.json").read_bytes() == original
    assert not _staging_qemu_pids(fresh.home)
    assert not list((root / "staging").glob("build-*"))
    run(f"{zaigr} project vm start", cwd=fresh.cwd, input="y\n", timeout=180)
    assert (
        run(
            f"{zaigr} project vm exec -- cat /etc/publish-base",
            cwd=fresh.cwd,
            timeout=20,
        )
        == "published\n"
    )
    run(
        f"{zaigr} project vm exec -- test ! -e /etc/publish-update",
        cwd=fresh.cwd,
        timeout=20,
    )
    global_run(f"{zaigr} global base-image setup run publish-update", timeout=180)
    assert "publish-update" in global_run(
        f"{zaigr} global base-image status", timeout=10
    )


@pytest.mark.timeout(900)
def test_legacy_factory_pin_capture_and_identical_local_setup_rebuild(
    project_factory, setup_factory, tmp_path
):
    """An unpinned old project stays factory, and equal local/global scripts stay distinct."""
    legacy = project_factory("legacy-factory")
    customized = project_factory("identical-local")
    zaigr = legacy.zaigr_bin
    run = partial(_checked_run, env=legacy.env)
    global_run = partial(run, cwd=tmp_path)
    run(f"{zaigr} project vm start", cwd=legacy.cwd, input="y\n", timeout=180)
    run(
        f"{zaigr} project vm exec -- tee /home/user/legacy-data",
        cwd=legacy.cwd,
        input="legacy-data\n",
        timeout=20,
    )
    run(f"{zaigr} project vm stop", cwd=legacy.cwd, timeout=60)
    # This single absent documented file is exactly the pre-feature factory format.
    (legacy.store_dir / "base-backing.json").unlink()
    setup_factory(
        "same-script",
        "count=0\nif [ -f /etc/same-count ]; then count=$(cat /etc/same-count); fi\nprintf '%s\\n' \"$((count + 1))\" > /etc/same-count",
    )
    local = customized.cwd / ".zaigr/setups/same-script"
    local.mkdir(parents=True)
    shutil.copyfile(
        legacy.home / ".zaigr/setups/same-script/setup.script", local / "setup.script"
    )
    global_run(f"{zaigr} global base-image setup run same-script", timeout=180)
    run(f"{zaigr} project vm start", cwd=legacy.cwd, timeout=180)
    run(
        f"{zaigr} project vm exec -- test ! -e /etc/same-count",
        cwd=legacy.cwd,
        timeout=20,
    )
    assert (
        run(
            f"{zaigr} project vm exec -- cat /home/user/legacy-data",
            cwd=legacy.cwd,
            timeout=20,
        )
        == "legacy-data\n"
    )
    run(f"{zaigr} project vm stop", cwd=legacy.cwd, timeout=60)
    capture = spawn_interactive(
        f"{zaigr} project setup capture start",
        cwd=legacy.cwd,
        env=legacy.env,
        timeout=180,
    )
    try:
        capture.expect(r"root@[^:]+:.*# ", timeout=180)
        capture.sendline("printf 'captured-legacy\\n' > /etc/captured-legacy")
        capture.expect(r"root@[^:]+:.*# ", timeout=20)
        assert "captured-legacy" in run(
            f"{zaigr} project setup capture review", cwd=legacy.cwd, timeout=20
        )
        run(f"{zaigr} project setup capture accept", cwd=legacy.cwd, timeout=180)
        capture.expect(pexpect.EOF, timeout=30)
        capture.close()
    finally:
        if capture.isalive():
            capture.close(force=True)
    run(f"{zaigr} project vm start", cwd=legacy.cwd, timeout=180)
    run(
        f"{zaigr} project vm exec -- test ! -e /etc/same-count",
        cwd=legacy.cwd,
        timeout=20,
    )
    assert (
        run(
            f"{zaigr} project vm exec -- cat /etc/captured-legacy /home/user/legacy-data",
            cwd=legacy.cwd,
            timeout=20,
        )
        == "captured-legacy\nlegacy-data\n"
    )
    run(f"{zaigr} project vm stop", cwd=legacy.cwd, timeout=60)
    run(f"{zaigr} project rebuild", cwd=legacy.cwd, timeout=240)
    run(f"{zaigr} project vm start", cwd=legacy.cwd, timeout=180)
    assert (
        run(
            f"{zaigr} project vm exec -- cat /etc/same-count",
            cwd=legacy.cwd,
            timeout=20,
        )
        == "1\n"
    )

    run(f"{zaigr} project vm start", cwd=customized.cwd, input="y\n", timeout=180)
    assert (
        run(
            f"{zaigr} project vm exec -- cat /etc/same-count",
            cwd=customized.cwd,
            timeout=20,
        )
        == "1\n"
    )
    run(f"{zaigr} project setup run same-script", cwd=customized.cwd, timeout=180)
    assert (
        run(
            f"{zaigr} project vm exec -- cat /etc/same-count",
            cwd=customized.cwd,
            timeout=20,
        )
        == "2\n"
    )
    applied = run(
        f"{zaigr} project setup list --applied", cwd=customized.cwd, timeout=10
    )
    assert "[Project local] same-script" in applied
    assert applied.count("same-script") == 2, applied
    run(f"{zaigr} project vm stop", cwd=customized.cwd, timeout=60)
    run(f"{zaigr} project rebuild", cwd=customized.cwd, timeout=240)
    run(f"{zaigr} project vm start", cwd=customized.cwd, timeout=180)
    assert (
        run(
            f"{zaigr} project vm exec -- cat /etc/same-count",
            cwd=customized.cwd,
            timeout=20,
        )
        == "2\n"
    )


@pytest.mark.timeout(600)
def test_size_suffixes_too_small_recovery_and_damaged_cached_variant(
    project_factory, setup_factory, tmp_path
):
    """Supported suffixes reuse installation; invalid capacity and cache damage fail safely."""
    small = project_factory("too-small")
    decimal = project_factory("decimal")
    binary = project_factory("binary")
    damaged = project_factory("damaged-cache")
    zaigr = small.zaigr_bin
    global_run = partial(_checked_run, cwd=tmp_path, env=small.env)
    setup_factory("size-probe", "cat /proc/sys/kernel/random/uuid > /etc/size-probe")
    global_run(f"{zaigr} global base-image setup run size-probe", timeout=180)
    selection = small.home / ".zaigr/base-images/custom/current.json"
    original = selection.read_bytes()
    small_env = small.env
    small_env["ZAIGR_DISK_SIZE"] = "1M"
    stdout, stderr, rc = _run(
        f"{zaigr} project vm start",
        cwd=small.cwd,
        env=small_env,
        input="y\n",
        timeout=90,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert "too small" in stdout + stderr
    assert selection.read_bytes() == original
    identities = []
    for project, capacity in ((decimal, "8GB"), (binary, "8GiB")):
        env = project.env
        env["ZAIGR_DISK_SIZE"] = capacity
        run = partial(_checked_run, cwd=project.cwd, env=env)
        run(f"{zaigr} project vm start", input="y\n", timeout=180)
        identities.append(
            run(f"{zaigr} project vm exec -- cat /etc/size-probe", timeout=20)
        )
    assert identities[0] == identities[1]
    assert selection.read_bytes() == original
    binary_pin = json.loads((binary.store_dir / "base-backing.json").read_text())
    cached = Path(binary_pin["path"])
    _checked_run(f"{zaigr} project vm stop", cwd=binary.cwd, env=binary.env, timeout=60)
    cached.chmod(0o644)
    with cached.open("r+b") as image:
        image.truncate(cached.stat().st_size // 2)
    cached.chmod(0o444)
    damaged_env = damaged.env
    damaged_env["ZAIGR_DISK_SIZE"] = "8GiB"
    stdout, stderr, rc = _run(
        f"{zaigr} project vm start",
        cwd=damaged.cwd,
        env=damaged_env,
        input="y\n",
        timeout=30,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert "base-image reset" in stdout + stderr
    assert selection.read_bytes() == original
    assert (
        _checked_run(
            f"{zaigr} project vm exec -- cat /etc/size-probe",
            cwd=decimal.cwd,
            env=decimal.env,
            timeout=20,
        )
        == identities[0]
    )
    global_run(f"{zaigr} global base-image reset", timeout=30)
    _checked_run(
        f"{zaigr} project vm start",
        cwd=damaged.cwd,
        env=damaged_env,
        input="y\n",
        timeout=180,
    )
    _checked_run(
        f"{zaigr} project vm exec -- test ! -e /etc/size-probe",
        cwd=damaged.cwd,
        env=damaged_env,
        timeout=20,
    )


@pytest.mark.timeout(600)
def test_missing_local_prompt_rebuild_does_not_resurrect_reset_inheritance(
    project, setup_factory, tmp_path
):
    """The boot-time rebuild choice honors the reset base, like explicit rebuild."""
    zaigr = project.zaigr_bin
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    global_run = partial(_checked_run, cwd=tmp_path, env=project.env)
    setup_factory(
        "removed-inheritance", "printf 'inherited\\n' > /etc/removed-inheritance"
    )
    global_run(f"{zaigr} global base-image setup run removed-inheritance", timeout=180)
    run(f"{zaigr} project vm start", input="y\n", timeout=180)
    acknowledged = project.cwd / ".zaigr/setups/acknowledged-local"
    acknowledged.mkdir(parents=True)
    (acknowledged / "setup.script").write_text(
        "#!/bin/sh\nprintf 'acknowledged\\n' > /etc/acknowledged-local\n"
    )
    run(f"{zaigr} project setup run acknowledged-local", timeout=180)
    local = project.cwd / ".zaigr/setups/disappearing-local"
    local.mkdir(parents=True)
    (local / "setup.script").write_text(
        "#!/bin/sh\nprintf 'local\\n' > /etc/disappearing-local\n"
    )
    run(f"{zaigr} project setup run disappearing-local", timeout=180)
    run(f"{zaigr} project vm stop", timeout=60)
    shutil.rmtree(acknowledged)
    shutil.rmtree(local)
    global_run(f"{zaigr} global base-image reset", timeout=30)
    boot = spawn_interactive(
        f"{zaigr} project vm start", cwd=project.cwd, env=project.env, timeout=180
    )
    try:
        boot.expect_exact("Action [c/r/a]: ", timeout=30)
        # First acknowledge another missing setup, then rebuild and remove both.
        # This also catches stale preflight records written after the rebuild.
        boot.sendline("c")
        boot.expect_exact("Action [c/r/a]: ", timeout=30)
        boot.sendline("r")
        boot.expect_exact("Action [a/r]: ", timeout=30)
        boot.sendline("r")
        boot.expect(pexpect.EOF, timeout=180)
        boot.close()
        assert boot.exitstatus == 0
    finally:
        if boot.isalive():
            boot.close(force=True)
    run(f"{zaigr} project vm exec -- test ! -e /etc/removed-inheritance", timeout=20)
    run(f"{zaigr} project vm exec -- test ! -e /etc/acknowledged-local", timeout=20)
    run(f"{zaigr} project vm exec -- test ! -e /etc/disappearing-local", timeout=20)
    applied = run(f"{zaigr} project setup list --applied", timeout=10)
    assert "removed-inheritance" not in applied
    assert "acknowledged-local" not in applied
    assert "disappearing-local" not in applied
    run(f"{zaigr} project vm stop", timeout=60)
    run(f"{zaigr} project vm start", timeout=180)
    run(f"{zaigr} project vm exec -- test ! -e /etc/removed-inheritance", timeout=20)


@pytest.mark.parametrize("local_problem", ["missing", "failed"])
@pytest.mark.timeout(600)
def test_rebuild_removing_local_keeps_explicit_global_same_name(
    project, setup_factory, tmp_path, local_problem
):
    """Removing one missing or failing scoped setup preserves another explicit intent."""
    zaigr = project.zaigr_bin
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    global_run = partial(_checked_run, cwd=tmp_path, env=project.env)
    setup_factory(
        "scoped-explicit", "printf 'global-explicit\\n' > /etc/global-explicit"
    )
    global_run(f"{zaigr} global base-image setup run scoped-explicit", timeout=180)
    run(f"{zaigr} project vm start", input="y\n", timeout=180)
    run(f"{zaigr} project setup run scoped-explicit --force", timeout=180)
    local = project.cwd / ".zaigr/setups/scoped-explicit"
    local.mkdir(parents=True)
    (local / "setup.script").write_text(
        "#!/bin/sh\nprintf 'local-explicit\\n' > /etc/local-explicit\n"
    )
    run(f"{zaigr} project setup run scoped-explicit", timeout=180)
    applied = run(f"{zaigr} project setup list --applied", timeout=10)
    assert applied.count("scoped-explicit") == 2, applied
    run(f"{zaigr} project vm stop", timeout=60)
    if local_problem == "missing":
        shutil.rmtree(local)
    else:
        (local / "setup.script").write_text("#!/bin/sh\nexit 47\n")
    global_run(f"{zaigr} global base-image reset", timeout=30)
    rebuild = spawn_interactive(
        f"{zaigr} project rebuild", cwd=project.cwd, env=project.env, timeout=180
    )
    try:
        rebuild.expect_exact("Action [a/r]: ", timeout=180)
        rebuild.sendline("r")
        rebuild.expect(pexpect.EOF, timeout=180)
        rebuild.close()
        assert rebuild.exitstatus == 0
    finally:
        if rebuild.isalive():
            rebuild.close(force=True)
    run(f"{zaigr} project vm start", input="n\n", timeout=180)
    assert (
        run(f"{zaigr} project vm exec -- cat /etc/global-explicit", timeout=20)
        == "global-explicit\n"
    )
    run(f"{zaigr} project vm exec -- test ! -e /etc/local-explicit", timeout=20)
    applied = run(f"{zaigr} project setup list --applied", timeout=10)
    assert "scoped-explicit" in applied
    assert "[Project local] scoped-explicit" not in applied


@pytest.mark.timeout(300)
def test_first_project_setup_starts_vm_when_global_base_already_satisfies_it(
    project, setup_factory, tmp_path
):
    """Initialization through setup run still boots when the inherited installer skips."""
    zaigr = project.zaigr_bin
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    global_run = partial(_checked_run, cwd=tmp_path, env=project.env)
    setup_factory(
        "initialization-probe",
        "printf 'already-installed\\n' > /etc/initialization-probe\n"
        "printf 'INITIALIZATION_INSTALLER_EXECUTED\\n'",
    )
    global_run(f"{zaigr} global base-image setup run initialization-probe", timeout=180)
    initialized = run(
        f"{zaigr} project setup run initialization-probe", input="y\n", timeout=180
    )
    assert "INITIALIZATION_INSTALLER_EXECUTED" not in initialized
    assert (
        run(f"{zaigr} project vm exec -- cat /etc/initialization-probe", timeout=20)
        == "already-installed\n"
    )
