"""Public VM lifecycle checks for supervisor-owned virtiofsd trees."""

import json
import os
import pathlib
import shutil
import signal
import time
from functools import partial

import pexpect
import pytest

from ..conftest import err_msg, spawn_interactive
from ..conftest import run as _run


def _checked_run(command, **kwargs):
    stdout, stderr, code = _run(command, **kwargs)
    assert code == 0, err_msg(stdout, stderr)
    return stdout


def _live_group_members(group):
    members = []
    for entry in os.scandir("/proc"):
        if not entry.name.isdigit():
            continue
        try:
            stat = (entry.path + "/stat")
            with open(stat, encoding="utf-8") as stream:
                fields = stream.read().rsplit(")", 1)[1].split()
            if int(fields[2]) == group and (fields[0] not in ("Z", "X") or int(fields[17]) > 1):
                members.append(int(entry.name))
        except (FileNotFoundError, ProcessLookupError):
            continue
    return members


def _verified_signal(identity, sig):
    pid = identity["pid"]
    with open(f"/proc/{pid}/stat", encoding="utf-8") as stream:
        fields = stream.read().rsplit(")", 1)[1].split()
    assert fields[19] == identity["start_time"]
    assert int(fields[2]) == identity["process_group"]
    exe = os.stat(f"/proc/{pid}/exe")
    assert (exe.st_dev, exe.st_ino) == (identity["exe_device"], identity["exe_inode"])
    os.kill(pid, sig)


@pytest.mark.timeout(300)
def test_supervisor_death_reaps_qemu_and_both_daemon_groups(project):
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    run(f"{zaigr} project vm start", input="y\n", timeout=180)
    record_path = project.store_dir / "vm-supervisor.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    groups = [
        record["qemu"]["process_group"],
        record["workspace_daemon"]["process_group"],
        record["agent_state_daemon"]["process_group"],
    ]
    assert all(_live_group_members(group) for group in groups)
    assert record["workspace_descendant"]["pid"] in _live_group_members(groups[1])
    assert record["agent_state_descendant"]["pid"] in _live_group_members(groups[2])

    _verified_signal(record["supervisor"], signal.SIGKILL)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and any(_live_group_members(group) for group in groups):
        time.sleep(0.05)
    assert all(not _live_group_members(group) for group in groups)

    run(f"{zaigr} project vm start", timeout=180)
    assert not pathlib.Path(record["socket_dir"]).exists()
    assert run(f"{zaigr} project vm exec -- findmnt -n -o FSTYPE /home/user/workspace", timeout=20).strip() == "virtiofs"


@pytest.mark.timeout(300)
def test_supervisor_death_before_qemu_connects_reaps_daemons(project, test_root):
    zaigr = project.zaigr_bin
    real_qemu = shutil.which("qemu-system-x86_64")
    assert real_qemu
    fake_bin = test_root / "fake-bin"
    fake_bin.mkdir()
    marker = test_root / "qemu-wrapper-ready"
    release = test_root / "qemu-wrapper-release"
    wrapper = fake_bin / "qemu-system-x86_64"
    wrapper.write_text(
        "#!/usr/bin/python3\n"
        "import os, sys, time\n"
        f"real_qemu = {real_qemu!r}\n"
        "if sys.argv[1:] in ([\"--version\"], [\"-device\", \"help\"], [\"-object\", \"help\"]):\n"
        "    os.execv(real_qemu, [real_qemu, *sys.argv[1:]])\n"
        f"marker_tmp = {str(marker) + '.tmp'!r}\n"
        f"open(marker_tmp, 'w').close()\n"
        f"os.replace(marker_tmp, {str(marker)!r})\n"
        f"deadline = time.monotonic() + 120\n"
        f"while not os.path.exists({str(release)!r}):\n"
        "    if time.monotonic() >= deadline:\n"
        "        raise SystemExit('qemu wrapper release barrier timed out')\n"
        "    time.sleep(0.05)\n"
        f"os.execv({real_qemu!r}, [{real_qemu!r}, *sys.argv[1:]])\n",
        encoding="utf-8",
    )
    wrapper.chmod(0o755)
    env = project.env
    env["PATH"] = f"{fake_bin}:{env['PATH']}"

    start = spawn_interactive(f"{zaigr} project vm start", cwd=project.cwd, env=env, timeout=120)
    try:
        start.expect_exact("Initialize project and continue? [y/N]", timeout=30)
        start.sendline("y")
        record_path = project.store_dir / "vm-supervisor.json"
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and not marker.exists():
            time.sleep(0.05)
        assert marker.exists(), start.transcript.tail(4000)
        # The wrapper marker can be written before the supervisor has persisted
        # the QEMU process identity. Wait for the complete public runtime record
        # and live process groups while the wrapper is held behind its barrier.
        deadline = time.monotonic() + 60
        record = None
        groups = []
        while time.monotonic() < deadline:
            try:
                candidate = json.loads(record_path.read_text(encoding="utf-8"))
                names = ("qemu", "workspace_daemon", "agent_state_daemon")
                identities = [candidate.get(name, {}) for name in names]
                candidate_groups = [identity.get("process_group", 0) for identity in identities]
                if (
                    all(group > 1 for group in candidate_groups)
                    and all(_live_group_members(group) for group in candidate_groups)
                    and not pathlib.Path(project.store_dir / "runtime/vm.sock").exists()
                ):
                    record = candidate
                    groups = candidate_groups
                    break
            except (FileNotFoundError, json.JSONDecodeError):
                pass
            time.sleep(0.05)
        assert record is not None, (
            "VM supervisor did not persist live daemon and blocked-QEMU identities; "
            + start.transcript.tail(4000)
        )

        _verified_signal(record["supervisor"], signal.SIGKILL)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and any(_live_group_members(group) for group in groups):
            time.sleep(0.05)
        assert all(not _live_group_members(group) for group in groups)
        start.expect(pexpect.EOF, timeout=30)
    finally:
        if start.isalive():
            start.terminate(force=True)
