"""Public CLI failure recovery for supervisor-owned virtiofs exports."""
import hashlib
import json
import os
import shutil
import signal
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from functools import partial

import pexpect
import pytest

from ..conftest import err_msg, spawn_interactive
from ..conftest import run as _run
from .test_virtiofs_lifecycle import _live_group_members, _verified_signal


def _checked_run(command, **kwargs):
    stdout, stderr, code = _run(command, **kwargs)
    assert code == 0, err_msg(stdout, stderr)
    return stdout


def _process_identity_live(identity):
    if not identity or not identity.get("pid"):
        return False
    try:
        with open(f"/proc/{identity['pid']}/stat", encoding="utf-8") as stream:
            fields = stream.read().rsplit(")", 1)[1].split()
        if fields[19] != identity["start_time"]:
            return False
        exe = os.stat(f"/proc/{identity['pid']}/exe")
    except (FileNotFoundError, ProcessLookupError):
        return False
    return (exe.st_dev, exe.st_ino) == (identity["exe_device"], identity["exe_inode"])


def _wait_clean(record, record_path, timeout=20):
    groups = [record[name]["process_group"] for name in ("qemu", "workspace_daemon", "agent_state_daemon") if record[name]["pid"]]
    broker = record.get("ssh_broker")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if (
            not record_path.exists()
            and all(not _live_group_members(group) for group in groups)
            and not _process_identity_live(broker)
        ):
            return
        time.sleep(0.05)
    assert not record_path.exists(), record_path
    assert all(not _live_group_members(group) for group in groups), groups
    assert not _process_identity_live(broker), broker


def _assert_record_processes_dead(record):
    names = ("supervisor", "qemu", "workspace_daemon", "agent_state_daemon", "ssh_broker")
    live = {name: record.get(name) for name in names if _process_identity_live(record.get(name))}
    assert not live, live


@pytest.mark.timeout(300)
@pytest.mark.parametrize("name,sig", [
    ("supervisor-term", signal.SIGTERM),
    ("supervisor-int", signal.SIGINT),
    ("qemu-kill", signal.SIGKILL),
    ("ssh-broker-kill", signal.SIGKILL),
    ("workspace-daemon-kill", signal.SIGKILL),
    ("agent-state-daemon-kill", signal.SIGKILL),
])
def test_owned_process_failure_cleans_both_exports_and_restarts(project, name, sig):
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    run([zaigr, "project", "vm", "start"], input="y\n", timeout=180)
    record_path = project.store_dir / "vm-supervisor.json"
    record = json.loads(record_path.read_text())
    assert record["mode"] == "detached"
    assert all(_live_group_members(record[item]["process_group"]) for item in ("qemu", "workspace_daemon", "agent_state_daemon"))
    assert _process_identity_live(record["ssh_broker"])
    target = {"supervisor-term": "supervisor", "supervisor-int": "supervisor", "qemu-kill": "qemu", "ssh-broker-kill": "ssh_broker", "workspace-daemon-kill": "workspace_daemon", "agent-state-daemon-kill": "agent_state_daemon"}[name]
    started = time.monotonic()
    _verified_signal(record[target], sig)
    _wait_clean(record, record_path, timeout=20)
    assert time.monotonic() - started < 20
    for socket in ("vm.sock", "virtiofsd-workspace.sock", "virtiofsd-agent-state.sock"):
        assert not (project.store_dir / "runtime" / socket).exists()
    assert (project.store_dir / "vm-supervisor.log").exists()
    run([zaigr, "project", "vm", "start"], timeout=180)
    assert run([zaigr, "project", "vm", "exec", "--", "findmnt", "-n", "-o", "FSTYPE", "/home/user/workspace"], timeout=20).strip() == "virtiofs"


@pytest.mark.timeout(300)
@pytest.mark.parametrize("abrupt", [False, True])
def test_stop_waits_for_all_owned_processes_then_restarts(project, abrupt):
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    run([zaigr, "project", "vm", "start"], input="y\n", timeout=180)
    record_path = project.store_dir / "vm-supervisor.json"
    record = json.loads(record_path.read_text())
    command = [zaigr, "project", "vm", "stop"] + (["--abrupt"] if abrupt else [])
    started = time.monotonic()
    run(command, timeout=60)
    assert time.monotonic() - started < 20
    _wait_clean(record, record_path, timeout=1)
    run([zaigr, "project", "vm", "start"], timeout=180)
    assert run([zaigr, "project", "vm", "exec", "--", "findmnt", "-n", "-o", "FSTYPE", "/home/user/.zaigr-agent-state"], timeout=20).strip() == "virtiofs"


@pytest.mark.timeout(300)
def test_stopping_one_project_keeps_other_exports_usable(project_factory):
    first = project_factory("first")
    second = project_factory("second")
    run_first = partial(_checked_run, cwd=first.cwd, env=first.env)
    run_second = partial(_checked_run, cwd=second.cwd, env=second.env)
    zaigr = first.zaigr_bin
    run_first([zaigr, "project", "vm", "start"], input="y\n", timeout=180)
    run_second([zaigr, "project", "vm", "start"], input="y\n", timeout=180)
    other_record = json.loads((second.store_dir / "vm-supervisor.json").read_text())
    run_first([zaigr, "project", "vm", "stop"], timeout=60)
    assert run_second([zaigr, "project", "vm", "exec", "--", "findmnt", "-n", "-o", "FSTYPE", "/home/user/workspace"], timeout=20).strip() == "virtiofs"
    assert run_second([zaigr, "project", "vm", "exec", "--", "findmnt", "-n", "-o", "FSTYPE", "/home/user/.zaigr-agent-state"], timeout=20).strip() == "virtiofs"
    assert (second.store_dir / "vm-supervisor.json").exists()
    assert _live_group_members(other_record["qemu"]["process_group"])


@pytest.mark.timeout(300)
def test_two_projects_extract_first_daemon_cache_concurrently(project_factory):
    first = project_factory("first-extraction")
    second = project_factory("second-extraction")
    zaigr = first.zaigr_bin
    launches = [
        spawn_interactive(f"{zaigr} project vm start", cwd=project.cwd, env=project.env, timeout=180)
        for project in (first, second)
    ]
    try:
        for launch in launches:
            launch.expect_exact("Initialize project and continue? [y/N]", timeout=30)
            launch.sendline("y")
        for launch in launches:
            launch.expect(pexpect.EOF, timeout=180)
            launch.close()
            assert launch.exitstatus == 0, launch.transcript.tail(4000)
        caches = [p for p in (first.home / ".zaigr").glob("virtiofsd-*") if p.is_file() and not p.name.endswith(".lock")]
        assert len(caches) == 1, caches
        assert caches[0].stat().st_size > 100_000
        for project in (first, second):
            output = _checked_run([zaigr, "project", "vm", "exec", "--", "findmnt", "-n", "-o", "FSTYPE", "/home/user/workspace"], cwd=project.cwd, env=project.env, timeout=20)
            assert output.strip() == "virtiofs"
    finally:
        for launch in launches:
            if launch.isalive():
                launch.terminate(force=True)


@pytest.mark.timeout(300)
def test_corrupt_cached_daemon_is_reextracted_on_restart(project):
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    run([zaigr, "project", "vm", "start"], input="y\n", timeout=180)
    caches = [p for p in (project.home / ".zaigr").glob("virtiofsd-*") if p.is_file() and not p.name.endswith(".lock")]
    assert len(caches) == 1, caches
    original_hash = hashlib.sha256(caches[0].read_bytes()).hexdigest()
    run([zaigr, "project", "vm", "stop"], timeout=60)
    caches[0].write_bytes(b"corrupt test-only cache\n")
    run([zaigr, "project", "vm", "start"], timeout=180)
    assert hashlib.sha256(caches[0].read_bytes()).hexdigest() == original_hash
    assert run([zaigr, "project", "vm", "exec", "--", "findmnt", "-n", "-o", "FSTYPE", "/home/user/workspace"], timeout=20).strip() == "virtiofs"
    run([zaigr, "project", "vm", "stop"], timeout=60)
    caches[0].unlink()
    run([zaigr, "project", "vm", "start"], timeout=180)
    assert hashlib.sha256(caches[0].read_bytes()).hexdigest() == original_hash


@pytest.mark.timeout(300)
@pytest.mark.parametrize("wrapper_body,expected", [
    ("import sys\nsys.exit(42)\n", "QEMU"),
    ("import time\ntime.sleep(20)\n", "QMP"),
])
def test_qemu_startup_failure_cleans_children_and_can_retry(project, test_root, wrapper_body, expected):
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    # Initialize the project before changing only the QEMU executable lookup.
    run([zaigr, "project", "vm", "start"], input="y\n", timeout=180)
    run([zaigr, "project", "vm", "stop"], timeout=60)
    fake_bin = test_root / "qemu-failure-bin"
    fake_bin.mkdir()
    marker = test_root / "qemu-failure-invoked"
    real_qemu = shutil.which("qemu-system-x86_64")
    assert real_qemu
    wrapper = fake_bin / "qemu-system-x86_64"
    wrapper.write_text(
        "#!/usr/bin/python3\n"
        "import os, sys\n"
        f"real_qemu = {real_qemu!r}\n"
        "if sys.argv[1:] in ([\"--version\"], [\"-device\", \"help\"], [\"-object\", \"help\"]):\n"
        "    os.execv(real_qemu, [real_qemu, *sys.argv[1:]])\n"
        f"open({str(marker)!r}, 'w').close()\n"
        + wrapper_body,
        encoding="utf-8",
    )
    wrapper.chmod(0o755)
    env = project.env
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    started = time.monotonic()
    stdout, stderr, code = _run([zaigr, "project", "vm", "start"], cwd=project.cwd, env=env, timeout=45)
    assert code != 0, stdout
    assert marker.exists()
    assert expected.lower() in (stdout + stderr).lower(), (stdout, stderr)
    assert time.monotonic() - started < 30
    assert not (project.store_dir / "vm-supervisor.json").exists()
    for name in ("virtiofsd-workspace.sock", "virtiofsd-agent-state.sock", "vm.sock"):
        assert not (project.store_dir / "runtime" / name).exists()
    assert (project.store_dir / "vm-supervisor.log").exists()
    assert (project.store_dir / "virtiofsd-workspace.log").exists()
    assert (project.store_dir / "virtiofsd-agent-state.log").exists()
    run([zaigr, "project", "vm", "start"], timeout=180)
    assert run([zaigr, "project", "vm", "exec", "--", "findmnt", "-n", "-o", "FSTYPE", "/home/user/workspace"], timeout=20).strip() == "virtiofs"


@pytest.mark.timeout(360)
def test_vsock_readiness_failure_cleans_live_qemu_and_both_daemons(project, test_root):
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    run([zaigr, "project", "vm", "start"], input="y\n", timeout=180)
    run([zaigr, "project", "vm", "stop"], timeout=60)
    fake_bin = test_root / "vsock-readiness-failure-bin"
    fake_bin.mkdir()
    marker = test_root / "vsock-ssh-socket-masked"
    real_qemu = shutil.which("qemu-system-x86_64")
    assert real_qemu is not None
    wrapper = fake_bin / "qemu-system-x86_64"
    wrapper.write_text(
        "#!/usr/bin/python3\n"
        "import os, sys\n"
        f"real_qemu = {real_qemu!r}\n"
        f"marker = {str(marker)!r}\n"
        "args = sys.argv[1:]\n"
        "vsock_device = any(argument.startswith('vhost-vsock-device,guest-cid=') for argument in args)\n"
        "if not vsock_device:\n"
        "    os.execv(real_qemu, [real_qemu, *args])\n"
        "for index, argument in enumerate(args[:-1]):\n"
        "    if argument == '-append':\n"
        "        args[index + 1] += ' systemd.mask=ssh-vsock.socket'\n"
        "        with open(marker, 'w', encoding='utf-8') as output:\n"
        "            output.write(args[index + 1] + '\\n')\n"
        "        break\n"
        "else:\n"
        "    raise SystemExit('product QEMU arguments did not contain a guest kernel append value')\n"
        "os.execv(real_qemu, [real_qemu, *args])\n",
        encoding="utf-8",
    )
    wrapper.chmod(0o755)
    env = project.env
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    started = time.monotonic()
    record_path = project.store_dir / "vm-supervisor.json"
    with ThreadPoolExecutor(max_workers=1) as pool:
        start = pool.submit(
            _run,
            [zaigr, "project", "vm", "start"],
            cwd=project.cwd,
            env=env,
            timeout=330,
        )
        live_record = None
        capture_deadline = time.monotonic() + 180
        required = ("supervisor", "qemu", "workspace_daemon", "agent_state_daemon", "ssh_broker")
        while time.monotonic() < capture_deadline and not start.done():
            if record_path.exists():
                try:
                    candidate = json.loads(record_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    candidate = None
                if candidate and all(_process_identity_live(candidate.get(key)) for key in required):
                    live_record = candidate
                    break
            time.sleep(0.05)
        stdout, stderr, code = start.result(timeout=330)
    assert code != 0, (stdout, stderr)
    assert live_record is not None, "failed startup did not publish identities for the supervisor, QEMU, daemons, and broker"
    assert "systemd.mask=ssh-vsock.socket" in marker.read_text(encoding="utf-8")
    failure = (stdout + stderr).lower()
    assert "guest ssh readiness: context deadline exceeded" in failure, (stdout, stderr)
    assert time.monotonic() - started < 320
    _wait_clean(live_record, record_path, timeout=20)
    _assert_record_processes_dead(live_record)
    for name in ("virtiofsd-workspace.sock", "virtiofsd-agent-state.sock", "vm.sock"):
        assert not (project.store_dir / "runtime" / name).exists()
    assert not (project.store_dir / "runtime" / "vsock-cid").exists()
    assert (project.store_dir / "vm-supervisor.log").exists()
    run([zaigr, "project", "vm", "start"], timeout=180)
    assert run([zaigr, "project", "vm", "exec", "--", "findmnt", "-n", "-o", "FSTYPE", "/home/user/workspace"], timeout=20).strip() == "virtiofs"


@pytest.mark.timeout(300)
def test_daemon_startup_failure_cleans_started_children(project, test_root):
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    run([zaigr, "project", "vm", "start"], input="y\n", timeout=180)
    run([zaigr, "project", "vm", "stop"], timeout=60)
    # A clean stop records the guest identity, and the next start would skip
    # the image copy this test pauses in. A change zaigr didn't observe forces
    # the copy again.
    os.utime(project.store_dir / "project.qcow2")
    caches = [p for p in (project.home / ".zaigr").glob("virtiofsd-*") if p.is_file() and not p.name.endswith(".lock")]
    assert len(caches) == 1, caches
    cache = caches[0]
    original = cache.read_bytes()
    fake_bin = test_root / "daemon-startup-bin"
    fake_bin.mkdir()
    marker = test_root / "identity-convert-paused"
    release = test_root / "identity-convert-release"
    qemu_img = shutil.which("qemu-img")
    assert qemu_img
    wrapper = fake_bin / "qemu-img"
    wrapper.write_text(
        "#!/usr/bin/python3\n"
        "import os, sys, time\n"
        "from pathlib import Path\n"
        "if any('zaigr-identity-' in arg for arg in sys.argv):\n"
        f"    Path({str(marker)!r}).touch()\n"
        f"    while not Path({str(release)!r}).exists():\n"
        "        time.sleep(0.05)\n"
        f"os.execv({qemu_img!r}, [{qemu_img!r}, *sys.argv[1:]])\n",
        encoding="utf-8",
    )
    wrapper.chmod(0o755)
    state = project.store_dir / "agent-state"
    saved_state = test_root / "saved-agent-state"
    env = project.env
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    launch = spawn_interactive(f"{zaigr} project vm start", cwd=project.cwd, env=env, timeout=90)
    try:
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline and not marker.exists():
            time.sleep(0.05)
        assert marker.exists(), launch.transcript.tail(3000)
        state.rename(saved_state)
        state.write_text("test-only invalid shared directory\n")
        release.touch()
        launch.expect(pexpect.EOF, timeout=70)
        launch.close()
        assert launch.exitstatus != 0, launch.transcript.tail(4000)
        diagnostic = launch.transcript.tail(5000).lower()
        assert "pin agent-state export" in diagnostic, diagnostic
        assert "not a directory" in diagnostic, diagnostic
        record_path = project.store_dir / "vm-supervisor.json"
        assert not record_path.exists(), record_path.read_text() if record_path.exists() else record_path
        for name in ("virtiofsd-workspace.sock", "virtiofsd-agent-state.sock", "vm.sock"):
            assert not (project.store_dir / "runtime" / name).exists()
        assert (project.store_dir / "vm-supervisor.log").exists()
    finally:
        release.touch()
        if launch.isalive():
            launch.terminate(force=True)
        cache.write_bytes(original)
        if saved_state.exists():
            state.unlink(missing_ok=True)
            saved_state.rename(state)
    run([zaigr, "project", "vm", "start"], timeout=180)
    assert run([zaigr, "project", "vm", "exec", "--", "findmnt", "-n", "-o", "FSTYPE", "/home/user/workspace"], timeout=20).strip() == "virtiofs"


@pytest.mark.timeout(60)
def test_legacy_unsafe_virtiofs_setting_is_refused_before_vm_start(project):
    """A saved legacy none setting cannot start a VM without the required sandbox."""
    zaigr = project.zaigr_bin
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    run([zaigr, "project", "vm", "start"], input="y\n", timeout=180)
    run([zaigr, "project", "vm", "stop"], timeout=60)
    setting = project.store_dir / "virtiofs-sandbox"
    setting.parent.mkdir(parents=True, exist_ok=True)
    setting.write_text("none\n", encoding="utf-8")
    stdout, stderr, code = _run(
        [zaigr, "project", "vm", "start"],
        cwd=project.cwd,
        env=project.env,
        input="y\n",
        timeout=30,
    )
    diagnostic = stdout + stderr
    assert code != 0, diagnostic
    assert "saved project setting is virtiofs-sandbox=none" in diagnostic
    assert "host-enforced VM networking requires the namespace file-sharing sandbox" in diagnostic
    assert "misc check" in diagnostic
    assert "Initialize project and continue?" not in diagnostic
    assert not (project.store_dir / "vm-supervisor.json").exists()
    assert not (project.store_dir / "runtime" / "vm.sock").exists()
    assert "virtiofs-sandbox=none" in _checked_run(
        [zaigr, "project", "vm", "show-config"], cwd=project.cwd, env=project.env
    )


@pytest.mark.timeout(300)
def test_stale_record_does_not_signal_unrelated_reused_pid(project):
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    run([zaigr, "project", "vm", "start"], input="y\n", timeout=180)
    record_path = project.store_dir / "vm-supervisor.json"
    stale = json.loads(record_path.read_text())
    run([zaigr, "project", "vm", "stop"], timeout=60)
    sleeper = subprocess.Popen(["sleep", "60"])
    try:
        stale["supervisor"]["pid"] = sleeper.pid
        record_path.write_text(json.dumps(stale))
        run([zaigr, "project", "vm", "start"], timeout=180)
        assert sleeper.poll() is None
        assert run([zaigr, "project", "vm", "exec", "--", "findmnt", "-n", "-o", "FSTYPE", "/home/user/workspace"], timeout=20).strip() == "virtiofs"
    finally:
        sleeper.terminate()
        sleeper.wait(timeout=5)


@pytest.mark.timeout(300)
def test_simultaneous_starts_of_one_project_keep_one_owner(project):
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    run([zaigr, "project", "vm", "start"], input="y\n", timeout=180)
    run([zaigr, "project", "vm", "stop"], timeout=60)
    record_path = project.store_dir / "vm-supervisor.json"
    first = spawn_interactive(f"{zaigr} project vm start", cwd=project.cwd, env=project.env, timeout=180)
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not record_path.exists():
            time.sleep(0.05)
        assert record_path.exists(), first.transcript.tail(3000)
        launch_id = json.loads(record_path.read_text())["launch_id"]
        started = time.monotonic()
        stdout, stderr, code = _run([zaigr, "project", "vm", "start"], cwd=project.cwd, env=project.env, timeout=20)
        assert code != 0, (stdout, stderr)
        assert "is running in another terminal" in (stdout + stderr).lower(), (stdout, stderr)
        assert time.monotonic() - started < 20
        first.expect(pexpect.EOF, timeout=180)
        first.close()
        assert first.exitstatus == 0, first.transcript.tail(4000)
        assert json.loads(record_path.read_text())["launch_id"] == launch_id
        assert run([zaigr, "project", "vm", "exec", "--", "findmnt", "-n", "-o", "FSTYPE", "/home/user/workspace"], timeout=20).strip() == "virtiofs"
    finally:
        if first.isalive():
            first.terminate(force=True)


@pytest.mark.timeout(300)
def test_concurrent_firewall_inspections_do_not_start_a_stopped_vm(project):
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    run([zaigr, "project", "vm", "start"], input="y\n", timeout=180)
    run([zaigr, "project", "vm", "stop"], timeout=60)
    record_path = project.store_dir / "vm-supervisor.json"
    assert not record_path.exists()
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(
            lambda _: _run([zaigr, "project", "firewall", "show"], cwd=project.cwd, env=project.env, timeout=20),
            range(2),
        ))
    for stdout, stderr, code in results:
        assert code == 0, err_msg(stdout, stderr)
    assert results[0][0] == results[1][0]
    assert not record_path.exists()
    status = run([zaigr, "project", "status"])
    assert "status: not running" in status.lower(), status


@pytest.mark.timeout(180)
@pytest.mark.parametrize("missing,action", [
    ("qemu-start-time", "start"),
    ("daemon-process-group", "stop"),
])
def test_malformed_stale_owner_record_blocks_cleanup_without_losing_evidence(project, missing, action):
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    run([zaigr, "project", "vm", "start"], input="y\n", timeout=180)
    record_path = project.store_dir / "vm-supervisor.json"
    stale = json.loads(record_path.read_text())
    run([zaigr, "project", "vm", "stop"], timeout=60)
    if missing == "qemu-start-time":
        stale["qemu"]["start_time"] = ""
    else:
        stale["workspace_daemon"]["process_group"] = 0
    runtime = project.store_dir / "runtime"
    runtime.mkdir(exist_ok=True)
    marker = runtime / "forensic-marker"
    marker.write_text("owned test evidence\n")
    record_path.write_text(json.dumps(stale))
    try:
        stdout, stderr, code = _run([zaigr, "project", "vm", action], cwd=project.cwd, env=project.env, timeout=20)
        assert code != 0, (stdout, stderr)
        assert "record" in (stdout + stderr).lower() or "identity" in (stdout + stderr).lower(), (stdout, stderr)
        assert record_path.exists()
        assert marker.read_text() == "owned test evidence\n"
    finally:
        # Remove only metadata constructed by this test after inspecting it.
        record_path.unlink(missing_ok=True)
        marker.unlink(missing_ok=True)


@pytest.mark.timeout(450)
def test_attached_setup_continues_past_supervisor_startup_deadline(project, setup_factory):
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    setup_factory("long-attached-virtiofs", "sleep 155\nprintf 'attached-setup-complete\\n'\n")
    started = time.monotonic()
    # The 420s command budget includes initialization, two VM boots, the 155s
    # setup sleep, image finalization, and the post-setup VM checks.
    output = run([zaigr, "project", "setup", "run", "long-attached-virtiofs"], input="y\n", timeout=420)
    assert time.monotonic() - started > 150
    assert "attached-setup-complete" in output
    record = json.loads((project.store_dir / "vm-supervisor.json").read_text())
    assert record["mode"] == "detached"
    assert run([zaigr, "project", "vm", "exec", "--", "findmnt", "-n", "-o", "FSTYPE", "/home/user/.zaigr-agent-state"], timeout=20).strip() == "virtiofs"


@pytest.mark.timeout(240)
def test_attached_caller_death_after_commit_reaps_temporary_vm(project, setup_factory):
    zaigr = project.zaigr_bin
    setup_factory("attached-caller-death", "touch /home/user/workspace/attached-committed\nsleep 60\n")
    launch = spawn_interactive(f"{zaigr} project setup run attached-caller-death", cwd=project.cwd, env=project.env, timeout=180)
    try:
        launch.expect_exact("Initialize project and continue? [y/N]", timeout=30)
        launch.sendline("y")
        marker = project.cwd / "attached-committed"
        deadline = time.monotonic() + 90
        record_path = None
        while time.monotonic() < deadline:
            records = list((project.home / ".zaigr").rglob("vm-supervisor.json"))
            if marker.exists() and records:
                record_path = records[0]
                break
            time.sleep(0.05)
        assert marker.exists(), launch.transcript.tail(4000)
        assert record_path is not None
        record = json.loads(record_path.read_text())
        assert record["mode"] == "attached"
        assert all(_live_group_members(record[item]["process_group"]) for item in ("qemu", "workspace_daemon", "agent_state_daemon"))
        os.kill(launch.pid, signal.SIGKILL)
        launch.expect(pexpect.EOF, timeout=10)
        _wait_clean(record, record_path, timeout=5)
    finally:
        if launch.isalive():
            launch.terminate(force=True)


@pytest.mark.timeout(240)
def test_attached_caller_death_before_qemu_connection_reaps_daemons(project, setup_factory, test_root):
    zaigr = project.zaigr_bin
    setup_factory("attached-early-death", "printf 'should-not-run\\n'\n")
    fake_bin = test_root / "attached-qemu-delay"
    fake_bin.mkdir()
    marker = test_root / "attached-qemu-invoked"
    real_qemu = shutil.which("qemu-system-x86_64")
    assert real_qemu
    wrapper = fake_bin / "qemu-system-x86_64"
    wrapper.write_text(
        "#!/usr/bin/python3\n"
        "import os, sys, time\n"
        f"real_qemu = {real_qemu!r}\n"
        "if sys.argv[1:] in ([\"--version\"], [\"-device\", \"help\"], [\"-object\", \"help\"]):\n"
        "    os.execv(real_qemu, [real_qemu, *sys.argv[1:]])\n"
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).touch()\n"
        "time.sleep(60)\n",
        encoding="utf-8",
    )
    wrapper.chmod(0o755)
    env = project.env
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    launch = spawn_interactive(f"{zaigr} project setup run attached-early-death", cwd=project.cwd, env=env, timeout=180)
    try:
        launch.expect_exact("Initialize project and continue? [y/N]", timeout=30)
        launch.sendline("y")
        deadline = time.monotonic() + 90
        record_path = None
        while time.monotonic() < deadline:
            records = list((project.home / ".zaigr").rglob("vm-supervisor.json"))
            if marker.exists() and records:
                record_path = records[0]
                break
            time.sleep(0.05)
        assert marker.exists(), launch.transcript.tail(4000)
        assert record_path is not None
        record = json.loads(record_path.read_text())
        assert record["mode"] == "attached"
        assert all(_live_group_members(record[item]["process_group"]) for item in ("qemu", "workspace_daemon", "agent_state_daemon"))
        os.kill(launch.pid, signal.SIGKILL)
        launch.expect(pexpect.EOF, timeout=10)
        _wait_clean(record, record_path, timeout=5)
    finally:
        if launch.isalive():
            launch.terminate(force=True)
