"""Public vsock SSH identity and CID collision recovery checks."""

import json
import os
import shutil
import signal
import subprocess
import time
from functools import partial

import pytest

from ..conftest import err_msg
from ..conftest import run as _run


def _checked_run(command, **kwargs):
    stdout, stderr, code = _run(command, **kwargs)
    assert code == 0, err_msg(stdout, stderr)
    return stdout


@pytest.fixture
def cid_holder_qemu(project, test_root):
    real_qemu = shutil.which("qemu-system-x86_64")
    assert real_qemu
    shim_dir = test_root / "cid-holder-bin"
    shim_dir.mkdir()
    holder_pid = test_root / "cid-holder.pid"
    holder_started = test_root / "cid-holder-started"
    holder_cid = test_root / "cid-holder-cid"
    wrapper = shim_dir / "qemu-system-x86_64"
    wrapper.write_text(
        "#!/usr/bin/python3\n"
        "import os, subprocess, sys\n"
        "args = sys.argv[1:]\n"
        "cid = None\n"
        "for arg in args:\n"
        "    if arg.startswith('vhost-vsock-device,'):\n"
        "        for part in arg.split(','):\n"
        "            if part.startswith('guest-cid='):\n"
        "                cid = part.split('=', 1)[1]\n"
        "if cid is None:\n"
        f"    os.execv({real_qemu!r}, [{real_qemu!r}, *args])\n"
        f"if not os.path.exists({str(holder_started)!r}):\n"
        f"    with open({str(holder_started)!r}, 'x', encoding='utf-8'):\n"
        "        pass\n"
        f"    with open({str(holder_cid)!r}, 'w', encoding='utf-8') as stream:\n"
        "        stream.write(cid + '\\n')\n"
        f"    subprocess.run([{real_qemu!r}, '-M', 'microvm', '-nodefaults', '-display', 'none', '-S', '-daemonize', '-pidfile', {str(holder_pid)!r}, '-device', 'vhost-vsock-device,guest-cid=' + cid], check=True)\n"
        f"os.execv({real_qemu!r}, [{real_qemu!r}, *args])\n",
        encoding="utf-8",
    )
    wrapper.chmod(0o755)
    env = project.env
    env["PATH"] = f"{shim_dir}{os.pathsep}{env['PATH']}"
    yield env, holder_pid, holder_cid
    if holder_pid.exists():
        pid = int(holder_pid.read_text(encoding="utf-8").strip())
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.05)
        else:
            os.kill(pid, signal.SIGKILL)


def _qemu_tcp_listeners(pids):
    result = subprocess.run(
        ["ss", "-H", "-ltnp"],
        check=True,
        text=True,
        capture_output=True,
        timeout=5,
    )
    return [
        line
        for line in result.stdout.splitlines()
        if any(f"pid={pid}," in line for pid in pids)
    ]


@pytest.fixture
def small_vm(monkeypatch):
    """Use modest resources for this nested-host prerequisite check."""
    monkeypatch.setenv("ZAIGR_VM_RAM", "512")
    monkeypatch.setenv("ZAIGR_VM_CPU", "1")
    monkeypatch.setenv("ZAIGR_DISK_SIZE", "8G")


@pytest.mark.timeout(420)
def test_two_running_projects_have_distinct_vsock_cids_and_no_qemu_tcp_listener(project_factory):
    first = project_factory("vsock-first")
    second = project_factory("vsock-second")

    first_run = partial(_checked_run, cwd=first.cwd, env=first.env)
    second_run = partial(_checked_run, cwd=second.cwd, env=second.env)
    first_zaigr = first.zaigr_bin
    second_zaigr = second.zaigr_bin

    first_run([first_zaigr, "project", "vm", "start"], input="y\n", timeout=180)
    second_run([second_zaigr, "project", "vm", "start"], input="y\n", timeout=180)

    first_record = json.loads((first.store_dir / "vm-supervisor.json").read_text(encoding="utf-8"))
    second_record = json.loads((second.store_dir / "vm-supervisor.json").read_text(encoding="utf-8"))
    assert first_record["vsock_cid"] >= 3
    assert second_record["vsock_cid"] >= 3
    assert first_record["vsock_cid"] != second_record["vsock_cid"]
    assert (first.store_dir / "runtime" / "vsock-cid").read_text(encoding="utf-8").strip() == str(first_record["vsock_cid"])
    assert (second.store_dir / "runtime" / "vsock-cid").read_text(encoding="utf-8").strip() == str(second_record["vsock_cid"])

    assert first_run([first_zaigr, "project", "vm", "exec", "--", "hostname"], timeout=30).strip()
    assert second_run([second_zaigr, "project", "vm", "exec", "--", "hostname"], timeout=30).strip()
    assert not _qemu_tcp_listeners({first_record["qemu"]["pid"], second_record["qemu"]["pid"]})


@pytest.mark.timeout(300)
def test_qemu_guest_cid_collision_retries_with_new_cid(project, cid_holder_qemu):
    env, holder_pid_path, holder_cid_path = cid_holder_qemu
    zaigr = project.zaigr_bin
    run = partial(_checked_run, cwd=project.cwd, env=env)

    run([zaigr, "project", "vm", "start"], input="y\n", timeout=240)

    holder_pid = int(holder_pid_path.read_text(encoding="utf-8").strip())
    os.kill(holder_pid, 0)
    holder_cid = int(holder_cid_path.read_text(encoding="utf-8").strip())
    record = json.loads((project.store_dir / "vm-supervisor.json").read_text(encoding="utf-8"))
    assert record["vsock_cid"] != holder_cid
    assert record["vsock_cid"] >= 3
    assert (project.store_dir / "runtime" / "vsock-cid").read_text(encoding="utf-8").strip() == str(record["vsock_cid"])
    assert run([zaigr, "project", "vm", "exec", "--", "hostname"], timeout=30).strip()
    qemu_log = (project.store_dir / "vm-qemu.log").read_text(encoding="utf-8").lower()
    assert "vhost-vsock" in qemu_log
    assert "address already in use" in qemu_log
    assert _qemu_tcp_listeners({record["qemu"]["pid"]}) == []


@pytest.mark.timeout(300)
def test_regular_guest_user_can_open_vhost_vsock(project, small_vm):
    """Keep nested QEMU's vhost-vsock device usable by the ordinary guest user."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    run([zaigr, "project", "vm", "start"], input="y\n", timeout=180)

    stdout, stderr, code = _run(
        [
            zaigr,
            "project",
            "vm",
            "exec",
            "--",
            "sh",
            "-c",
            (
                'uid=$(id -u); test "$uid" -eq 1000; printf "%s\\n" "$uid"; '
                'test -c /dev/vhost-vsock && exec 3<>/dev/vhost-vsock'
            ),
        ],
        cwd=project.cwd,
        env=project.env,
        timeout=30,
    )

    assert code == 0, err_msg(stdout, stderr)
    assert stdout.strip() == "1000", err_msg(stdout, stderr)
