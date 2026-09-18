"""Global VM inspection and shutdown remain usable when project state is broken."""

import fcntl
import json
from functools import partial
from pathlib import Path

import pexpect
import pytest

from ..conftest import ProjectTestEnv, err_msg, spawn_interactive
from ..conftest import run as _run


def _checked_run(cmd, **kwargs):
    stdout, stderr, rc = _run(cmd, **kwargs)
    assert rc == 0, err_msg(stdout, stderr)
    return stdout


@pytest.fixture
def metadata_projects(test_root, zaigr_bin, zaigr_home):
    """Two stopped stores with missing images, for metadata inspection tests."""
    projects = []
    for name in ("damaged", "healthy"):
        cwd = test_root / name
        cwd.mkdir()
        project = ProjectTestEnv(cwd=cwd, zaigr_bin=Path(zaigr_bin), home=zaigr_home)
        store = project.store_dir
        store.mkdir(parents=True)
        for filename, value in {
            "project-path": str(cwd),
            "ram": "512",
            "cpus": "1",
            "config": "disk=100G",
            "image-format": "direct-base-v1",
        }.items():
            (store / filename).write_text(value + "\n")
        projects.append((project, store))
    return projects


@pytest.mark.parametrize(
    "filename, content",
    [
        ("setup-capture.json", '{"name":"capture-f8225de"}'),
        ("setup-capture.json", "{broken"),
        ("image-format", "unsupported-format"),
        ("image-format", None),
        ("project-path", None),
        ("applied-setups.json", "{broken"),
        ("base-image-version", None),
        ("base-image-version", "outdated-base"),
    ],
)
def test_global_inspection_survives_capture_and_broken_metadata(
    metadata_projects, tmp_path, filename, content
):
    """A damaged store never hides the other store or its VM parameters."""
    (project, damaged), (_, healthy) = metadata_projects
    path = damaged / filename
    path.unlink(missing_ok=True)
    if content is None:
        # A directory in place of a metadata file represents unreadable state.
        path.mkdir()
    else:
        path.write_text(content)
    run = partial(_checked_run, cwd=tmp_path, env=project.env)
    zaigr = project.zaigr_bin

    status = run(f"{zaigr} global projects list", timeout=5)
    assert damaged.name in status
    assert healthy.name in status
    assert status.count("512.0MiB") == 2
    assert "CPU" in status and "RAM" in status and "DISK" in status

    details = run(
        f"{zaigr} global projects details {damaged.name} {healthy.name}", timeout=5
    )
    assert f"store-path: {damaged}" in details
    assert f"store-path: {healthy}" in details
    assert details.count("resources: cpu=1, ram=512.0MiB\n") == 2
    assert details.count("\ndisk: ") == 2
    if filename == "applied-setups.json":
        assert "applied: unavailable" in details
    if filename == "setup-capture.json" and content.startswith('{"name"'):
        assert "setup-capture: active (capture-f8225de)" in details

    completion = run([zaigr, "__complete", "global", "projects", "kill", ""], timeout=5)
    assert damaged.name in completion
    assert healthy.name in completion
    if content is None:
        assert path.is_dir()
    else:
        assert path.read_text() == content


def test_global_inspection_does_not_lock_recover_or_clean_stores(
    metadata_projects, tmp_path
):
    """Listing and details are read-only snapshots even during a project mutation."""
    (project, store), (_, healthy) = metadata_projects
    # A leftover legacy transaction must not trigger recovery during listing.
    backup = store.with_name(store.name + ".legacy-clean-transaction-old")
    backup.mkdir()
    (backup / "setup-capture.json").write_text("{interrupted")
    shells = store / "runtime" / "shells"
    shells.mkdir(parents=True)
    stale_shell = shells / "99999999"
    stale_shell.write_text("pid=99999999\nstarttime=0\nuser=user\nport=40022\n")
    lock_dir = project.home / ".zaigr" / "project-locks"
    lock_dir.mkdir(parents=True)
    run = partial(_checked_run, cwd=tmp_path, env=project.env)
    zaigr = project.zaigr_bin

    with (lock_dir / f"{store.name}.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        status = run(f"{zaigr} global projects list", timeout=5)
        assert store.name in status and healthy.name in status
        details = run(f"{zaigr} global projects details {store.name}", timeout=5)
        assert "active-shells:" not in details
        completion = run(
            [zaigr, "__complete", "global", "projects", "kill", ""], timeout=5
        )
        assert store.name in completion and healthy.name in completion

    assert (backup / "setup-capture.json").read_text() == "{interrupted"
    assert stale_shell.exists()


@pytest.mark.timeout(300)
def test_global_projects_show_runtime_overrides_and_stop_incompatible_vm(
    project_factory, tmp_path
):
    """Actual allocations stay visible and an incompatible VM can be stopped."""
    target = project_factory("target")
    other = project_factory("other")
    zaigr = target.zaigr_bin
    run = partial(_checked_run, env=target.env)
    run(
        f"{zaigr} project vm start --ram 512 --cpu 1",
        cwd=target.cwd,
        input="y\n",
        timeout=120,
    )
    run(f"{zaigr} project vm stop", cwd=target.cwd, timeout=60)
    run(
        f"{zaigr} project vm start --ram 768 --cpu sockets=1,cores=2,cpus=2",
        cwd=target.cwd,
        timeout=120,
    )
    run(
        f"{zaigr} project vm start --ram 512 --cpu 1",
        cwd=other.cwd,
        input="y\n",
        timeout=120,
    )
    store = target.store_dir
    other_store = other.store_dir
    image_format = store / "image-format"
    original_format = image_format.read_bytes()
    # Model an upgrade plus damaged capture bookkeeping on a live VM.
    image_format.write_text("unsupported-format\n")
    capture = store / "setup-capture.json"
    capture.write_text("{broken")
    try:
        status = run(f"{zaigr} global projects list", cwd=tmp_path, timeout=5)
        row = next(
            line.split() for line in status.splitlines() if line.startswith(target.cwd.name)
        )
        assert row[1].startswith("running")
        assert row[-4:-2] == ["2", "768.0MiB"]
        pid = run(
            f"{zaigr} global projects details {store.name}", cwd=tmp_path, timeout=5
        ).split("vm-pid: ", 1)[1].splitlines()[0]
        details = run(
            f"{zaigr} global projects details {store.name}", cwd=tmp_path, timeout=5
        )
        assert "resources: cpu=2, ram=768.0MiB\n" in details
        assert "\ndisk: " in details
        assert f"vm-pid: {pid}" in details

        # One invalid selector must not prevent a valid target from stopping.
        stdout, stderr, rc = _run(
            f"{zaigr} global projects kill nonexistent .. {store.name}",
            cwd=tmp_path,
            env=target.env,
            timeout=60,
        )
        assert rc != 0
        assert "project not found: nonexistent" in stderr
        assert "project not found: .." in stderr
        assert f"{store.name}: stopped" in stdout
        assert capture.read_text() == "{broken"
        status = run(f"{zaigr} global projects list", cwd=tmp_path, timeout=5)
        rows = [
            line.split()
            for line in status.splitlines()
            if line.startswith((target.cwd.name, other.cwd.name))
        ]
        assert rows[0][0:2] == [other.cwd.name, "running"]
        assert rows[0][-1] == other_store.name
        assert rows[1][0:3] == [target.cwd.name, "off,", "capture"]
        assert rows[1][-4:-2] == ["1", "512.0MiB"]
        assert rows[1][-1] == store.name
        assert (
            run(
                f"{zaigr} project vm exec -- printf still-running", cwd=other.cwd
            ).strip()
            == "still-running"
        )
    finally:
        image_format.write_bytes(original_format)
        capture.unlink(missing_ok=True)


@pytest.mark.timeout(240)
def test_global_projects_can_inspect_and_kill_live_capture(project, tmp_path):
    """Emergency shutdown works while an interactive capture holds the project gate."""
    zaigr = project.zaigr_bin
    run = partial(_checked_run, cwd=tmp_path, env=project.env)
    capture = spawn_interactive(
        f"{zaigr} project setup capture start",
        cwd=project.cwd,
        env=project.env,
        timeout=180,
    )
    try:
        capture.expect(r"Initialize project and continue\? \[y/N\]")
        capture.sendline("y")
        capture.expect(r"root@[^:]+:.*# ")
        capture.sendline("printf 'capture-command\\n'")
        capture.expect(r"root@[^:]+:.*# ")
        store = project.store_dir
        metadata_path = store / "setup-capture.json"
        metadata = metadata_path.read_bytes()
        overlay = Path(json.loads(metadata)["overlay_image_path"])

        status = run(f"{zaigr} global projects list", timeout=5)
        assert project.cwd.name in status and "running" in status and "512.0MiB" in status
        row = next(line for line in status.splitlines() if line.startswith(project.cwd.name))
        assert "running" in row and "capture" in row
        details = run(f"{zaigr} global projects details {store.name}", timeout=5)
        assert "status: running" in details and "setup-capture: active" in details
        pid = details.split("vm-pid: ", 1)[1].splitlines()[0]
        stdout, stderr, rc = _run(
            [zaigr, "global", "projects", "rebuild", project.cwd.name, "--force", "--yes"],
            cwd=tmp_path,
            env=project.env,
            timeout=20,
        )
        assert rc != 0, err_msg(stdout, stderr)
        assert "capture pending" in stdout + stderr
        assert "Skipped: 1" in stdout
        assert metadata_path.read_bytes() == metadata
        details = run(f"{zaigr} global projects details {store.name}", timeout=5)
        assert f"vm-pid: {pid}" in details
        assert "status: running, capture" in details
        stopped = run(
            f"{zaigr} global projects kill {store.name} --abrupt",
            input="y\n",
            timeout=30,
        )
        assert f"{store.name}: stopped" in stopped
        capture.expect(pexpect.EOF, timeout=30)
        capture.close()
        assert metadata_path.read_bytes() == metadata
        assert overlay.exists()
        status = run(f"{zaigr} global projects list", timeout=5)
        row = next(
            line.split() for line in status.splitlines() if line.startswith(project.cwd.name)
        )
        assert row[1].startswith(("off", "stale"))
        stdout, stderr, rc = _run(
            [zaigr, "global", "projects", "rebuild", store.name, "--force", "--yes"],
            cwd=tmp_path,
            env=project.env,
            timeout=20,
        )
        assert rc != 0, err_msg(stdout, stderr)
        assert "capture pending" in stdout + stderr
        assert "Skipped: 1" in stdout
        assert metadata_path.read_bytes() == metadata
        assert overlay.exists()
    finally:
        if capture.isalive():
            capture.close(force=True)
        _checked_run(
            f"{zaigr} project setup capture discard",
            cwd=project.cwd,
            env=project.env,
            timeout=60,
        )


@pytest.mark.timeout(180)
@pytest.mark.parametrize("scope", ["local", "global"])
def test_global_projects_abrupt_kill_finds_vm_without_monitor(project, tmp_path, scope):
    """Losing the monitor socket must not hide or orphan a live QEMU process."""
    zaigr = project.zaigr_bin
    run = partial(_checked_run, env=project.env)
    run(f"{zaigr} project vm start", cwd=project.cwd, input="y\n", timeout=120)
    store = project.store_dir
    # Model damaged runtime metadata while the actual VM process remains alive.
    (store / "runtime" / "vm.sock").unlink()
    (store / "runtime" / "ssh-port").unlink()

    for command in (
        f"{zaigr} project clean",
        f"{zaigr} project rebuild --force",
        f"{zaigr} project delete --force",
    ):
        stdout, stderr, rc = _run(
            command, cwd=project.cwd, env=project.env, timeout=10
        )
        assert rc != 0, err_msg(stdout, stderr)
        assert "project VM is running" in stdout + stderr
        assert store.is_dir()

    status = run(f"{zaigr} global projects list", cwd=tmp_path, timeout=5)
    row = next(
            line.split() for line in status.splitlines() if line.startswith(project.cwd.name)
    )
    assert row[1] == "running"
    assert row[2:4] == ["1", "512.0MiB"]
    pid = run(
        f"{zaigr} global projects details {store.name}", cwd=tmp_path, timeout=5
    ).split("vm-pid: ", 1)[1].splitlines()[0]
    if scope == "local":
        stopped = run(f"{zaigr} project vm stop --abrupt", cwd=project.cwd, timeout=20)
        assert "Project VM stopped" in stopped
    else:
        stopped = run(
            f"{zaigr} global projects kill {store.name} --abrupt", cwd=tmp_path, timeout=20
        )
        assert f"{store.name}: stopped" in stopped
    stdout, stderr, rc = _run(
        ["ps", "-p", pid, "-o", "stat=,nlwp="], cwd=tmp_path, env=project.env
    )
    fields = stdout.split()
    assert rc == 1 or (
        rc == 0
        and len(fields) == 2
        and fields[0][0] in {"Z", "X"}
        and fields[1] in {"0", "1"}
    ), err_msg(stdout, stderr)
    status = run(f"{zaigr} global projects list", cwd=tmp_path, timeout=5)
    row = next(
        line.split() for line in status.splitlines() if line.startswith(project.cwd.name)
    )
    assert row[1] == "off"
