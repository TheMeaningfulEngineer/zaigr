"""Host checks exercise the real bundled daemon without creating a project VM."""

import hashlib
import json
import os
import shutil
from functools import partial
from pathlib import Path

import pytest

from ..conftest import err_msg
from ..conftest import run as _run


def _checked_run(cmd, **kwargs):
    stdout, stderr, rc = _run(cmd, **kwargs)
    assert rc == 0, err_msg(stdout, stderr)
    return stdout


def _empty_path(test_root):
    path = test_root / "empty-bin"
    path.mkdir()
    return path


def _path_with_real_tools(test_root, names, directory_name="restricted-bin"):
    path = test_root / directory_name
    path.mkdir()
    for name in names:
        executable = shutil.which(name)
        if executable is None:
            executable = next(
                (
                    str(candidate)
                    for directory in ("/usr/sbin", "/sbin", "/usr/bin", "/bin")
                    if (candidate := Path(directory) / name).is_file()
                    and os.access(candidate, os.X_OK)
                ),
                None,
            )
        assert executable, f"host test prerequisite is missing from the real PATH: {name}"
        (path / name).symlink_to(Path(executable).resolve())
    return path


def _path_without_unshare(test_root):
    path = test_root / "without-unshare-bin"
    path.mkdir()
    directories = [*os.environ.get("PATH", "").split(os.pathsep), "/usr/sbin", "/sbin"]
    linked_names = set()
    for directory in directories:
        if not directory or not Path(directory).is_dir():
            continue
        for executable in Path(directory).iterdir():
            if executable.name in {"unshare", "slirp4netns", "ssh", "ssh-keygen", "setpriv"} or executable.name in linked_names:
                continue
            if not executable.is_file() or not os.access(executable, os.X_OK):
                continue
            (path / executable.name).symlink_to(executable.resolve())
            linked_names.add(executable.name)
    return path


def _is_debian_family():
    release = Path("/etc/os-release").read_text(encoding="utf-8").splitlines()
    values = dict(line.split("=", 1) for line in release if "=" in line)
    family = {values.get("ID", "").strip('"'), *values.get("ID_LIKE", "").strip('"').split()}
    return bool(family & {"debian", "ubuntu"})


def _assert_aggregate_host_preflight(output, operation):
    assert f"Host preflight failed before {operation}" in output
    assert "qemu-system-x86_64" in output
    assert "Run 'zaigr misc check' for the full host report." in output
    assert "setpriv" not in output
    assert "unshare" not in output
    if _is_debian_family():
        assert "sudo apt install" in output
        assert "openssh-client" not in output
        assert "util-linux" not in output


def _sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def test_host_check_probes_sandbox_without_project_state(zaigr_bin, zaigr_home, test_root):
    workspace = test_root / "workspace"
    workspace.mkdir()
    canary = workspace / "keep"
    canary.write_text("unchanged\n")
    # VM socket checks must work even when TMPDIR is unusable.
    tmpdir = test_root / "not-a-directory"
    tmpdir.write_text("keep\n")
    env = {**os.environ, "TMPDIR": str(tmpdir)}

    stdout, stderr, rc = _run([zaigr_bin, "misc", "check"], cwd=workspace, env=env)
    assert rc == 0, err_msg(stdout, stderr)
    assert stdout.startswith("Host: ")
    assert "(kernel " in stdout
    assert "QEMU virtiofs support" in stdout
    assert "vhost-vsock available" in stdout
    assert "host tools" in stdout
    assert "virtiofs sandbox" in stdout
    assert "answered a vhost-user request" in stdout
    assert "7/7 checks passed" in stdout
    assert list(workspace.iterdir()) == [canary]
    assert canary.read_text() == "unchanged\n"
    assert not (zaigr_home / ".zaigr/store").exists()
    assert not list((zaigr_home / ".zaigr").glob("*.qcow2"))

    processes, stderr, rc = _run(["ps", "-eo", "args="])
    assert rc == 0, err_msg(processes, stderr)
    assert str(zaigr_home / ".zaigr/virtiofsd-") not in processes


def test_host_check_reports_missing_tools_and_still_probes_sandbox(
    zaigr_bin, zaigr_home, test_root
):
    empty_path = _empty_path(test_root)
    stdout, stderr, rc = _run(
        [zaigr_bin, "misc", "check"],
        env={**os.environ, "PATH": str(empty_path)},
    )
    assert rc == 1, err_msg(stdout, stderr)
    assert "qemu-system-x86_64 not found in PATH" in stdout
    assert "missing host tools: ssh" not in stdout
    assert "missing host tools: ssh-keygen" not in stdout
    if _is_debian_family():
        install_line = next(
            line for line in stdout.splitlines() if line.startswith("Install missing packages:")
        )
        assert install_line == (
            "Install missing packages: sudo apt install qemu-system-x86"
        )
        assert "qemu-utils" not in install_line
        assert "e2fsprogs" not in install_line
        assert "conntrack" not in install_line
        assert "slirp4netns" not in install_line
        assert "openssh-client" not in install_line
        assert "util-linux" not in install_line
    else:
        assert "Missing tool names are listed above" in stdout
    assert "unshare" not in stdout
    # No newuidmap/newgidmap helpers are needed for the production mapping.
    assert "vhost-vsock available" in stdout
    assert "host-enforced networking" in stdout
    assert "slirp4netns 1.3.4" in stdout
    assert "start/stop probe passed" in stdout
    assert "answered a vhost-user request" in stdout
    assert "6/7 checks passed" in stdout
    assert not (zaigr_home / ".zaigr/store").exists()


def test_host_check_reports_bundled_slirp_version_with_system_shadow(
    project, test_root
):
    fake_tools = test_root / "failing-slirp-bin"
    fake_tools.mkdir()
    fake_slirp = fake_tools / "slirp4netns"
    fake_slirp.write_text(
        "#!/bin/sh\nprintf '%s\\n' 'intentional slirp runtime failure' >&2\nexit 42\n",
        encoding="utf-8",
    )
    fake_slirp.chmod(0o755)

    env = {
        **project.env,
        "PATH": str(fake_tools) + os.pathsep + project.env["PATH"],
    }
    stdout, stderr, _rc = _run(
        [project.zaigr_bin, "misc", "check"],
        cwd=project.cwd,
        env=env,
        timeout=90,
    )
    output = stdout + stderr

    assert "intentional slirp runtime failure" not in output
    assert any("slirp4netns" in line.lower() and "1.3.4" in line for line in output.splitlines())
    assert not (project.home / ".zaigr" / "store").exists()


@pytest.mark.timeout(90)
def test_vm_start_aggregates_network_prerequisites_before_initializing_project(
    project, test_root
):
    """A missing host tool report is complete and precedes project creation."""
    zaigr = project.zaigr_bin
    empty_path = _empty_path(test_root)
    stdout, stderr, rc = _run(
        [zaigr, "project", "vm", "start"],
        cwd=project.cwd,
        env={**project.env, "PATH": str(empty_path)},
        input="y\n",
        timeout=60,
    )

    assert rc != 0, err_msg(stdout, stderr)
    _assert_aggregate_host_preflight(stdout + stderr, "project VM start")
    assert not (project.home / ".zaigr" / "store").exists()
    assert not list((project.home / ".zaigr").glob("*.qcow2"))


@pytest.mark.timeout(480)
def test_rebuild_preflight_failure_preserves_existing_image_and_applied_setup(
    project, setup_factory, test_root
):
    """A host prerequisite failure leaves an existing project usable unchanged."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    setup_factory(
        setup_name="host-preflight-preserve",
        script_content="printf 'setup-present\n' > /etc/zaigr-host-preflight-preserve",
    )

    run(f"{zaigr} project vm start", input="y\n", timeout=180)
    run(
        f"{zaigr} project setup run host-preflight-preserve",
        input="y\n",
        timeout=180,
    )
    run(f"{zaigr} project vm stop", timeout=60)

    store = project.store_dir
    images = sorted(store.glob("*.qcow2"))
    assert len(images) == 1, images
    image_before = _sha256(images[0])
    applied_path = store / "applied-setups.json"
    applied_before = json.loads(applied_path.read_text(encoding="utf-8"))
    assert [entry["name"] for entry in applied_before] == [
        "host-preflight-preserve"
    ]

    empty_path = _empty_path(test_root)
    stdout, stderr, rc = _run(
        [zaigr, "project", "rebuild"],
        cwd=project.cwd,
        env={**project.env, "PATH": str(empty_path)},
        timeout=60,
    )
    assert rc != 0, err_msg(stdout, stderr)
    _assert_aggregate_host_preflight(stdout + stderr, "project rebuild")

    images_after = sorted(store.glob("*.qcow2"))
    assert images_after == images
    assert _sha256(images[0]) == image_before
    assert json.loads(applied_path.read_text(encoding="utf-8")) == applied_before

    run(f"{zaigr} project vm start", timeout=180)
    marker = run(
        f"{zaigr} project vm exec -- cat /etc/zaigr-host-preflight-preserve",
        timeout=20,
    )
    assert marker.strip() == "setup-present"


@pytest.mark.timeout(360)
def test_running_vm_survives_batch_rebuild_preflight_and_reuses_without_qemu(
    project, test_root
):
    """Missing build tools block batch mutation but allow a live VM to be reused."""
    zaigr = project.zaigr_bin
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    run(f"{zaigr} project vm start", input="y\n", timeout=180)

    restricted_path = _path_with_real_tools(
        test_root,
        (
            "qemu-system-x86_64", "qemu-img", "debugfs", "e2fsck",
            "resize2fs", "dumpe2fs", "true",
        ),
    )
    restricted_env = {**project.env, "PATH": str(restricted_path)}

    reused = run(
        [zaigr, "project", "vm", "start"],
        env=restricted_env,
        timeout=90,
    )
    assert "already running" in reused.lower()

    stdout, stderr, rc = _run(
        [zaigr, "global", "projects", "rebuild", "--all", "--yes"],
        env=restricted_env,
        timeout=120,
    )
    assert rc != 0, err_msg(stdout, stderr)
    output = stdout + stderr
    assert "qemu-system-x86_64" in output

    guest = run(
        [zaigr, "project", "vm", "exec", "--", "cat", "/etc/os-release"],
        env=restricted_env,
        timeout=30,
    )
    assert "PRETTY_NAME=" in guest


def _ubuntu_guidance(output):
    lines = output.splitlines()
    start = next(index for index, line in enumerate(lines) if line.strip() == "Ubuntu setup")
    end = next(
        index
        for index, line in enumerate(lines[start:], start)
        if line.strip().startswith(
            "https://documentation.ubuntu.com/release-notes/24.04/#unprivileged-user-namespace-restrictions"
        )
    )
    return "\n".join(line.strip() for line in lines[start : end + 1])


@pytest.mark.timeout(720)
def test_namespace_policy_guidance_matches_and_vm_networking_needs_no_host_ssh_tools(
    project, test_root
):
    """Networking and VM commands work without host SSH, setpriv, or unshare."""
    zaigr = project.zaigr_bin.resolve()
    commands_without_unshare = _path_without_unshare(test_root)
    assert not (commands_without_unshare / "unshare").exists()
    assert not (commands_without_unshare / "slirp4netns").exists()
    assert not (commands_without_unshare / "ssh").exists()
    assert not (commands_without_unshare / "ssh-keygen").exists()
    assert not (commands_without_unshare / "setpriv").exists()
    assert shutil.which("ssh", path=str(commands_without_unshare)) is None
    assert shutil.which("ssh-keygen", path=str(commands_without_unshare)) is None
    no_unshare_env = {**project.env, "PATH": str(commands_without_unshare)}

    stdout, stderr, rc = _run(
        [str(zaigr), "misc", "check"], cwd=project.cwd, env=no_unshare_env, timeout=90
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert "Bundled slirp4netns version:" in stdout
    assert "7/7 checks passed" in stdout
    assert "disposable host namespace, TAP, nftables controller and slirp start/stop probe passed" in stdout

    stdout, stderr, rc = _run(
        [str(zaigr), "project", "vm", "start"],
        cwd=project.cwd,
        env=no_unshare_env,
        input="y\n",
        timeout=240,
    )
    assert rc == 0, err_msg(stdout, stderr)
    stdout, stderr, rc = _run(
        [str(zaigr), "project", "vm", "exec", "--", "printf", "network-ready"],
        cwd=project.cwd,
        env=no_unshare_env,
        timeout=30,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert stdout == "network-ready"
    stdout, stderr, rc = _run(
        [str(zaigr), "project", "vm", "stop"], cwd=project.cwd, env=no_unshare_env, timeout=90
    )
    assert rc == 0, err_msg(stdout, stderr)

    os_release = test_root / "ubuntu-os-release"
    os_release.write_text(
        'ID=ubuntu\nID_LIKE=debian\nPRETTY_NAME="Ubuntu 24.04 LTS"\nVERSION_ID="24.04"\n',
        encoding="utf-8",
    )
    kernel_dir = test_root / "restricted-kernel"
    kernel_dir.mkdir()
    (kernel_dir / "apparmor_restrict_unprivileged_userns").write_text("1\n", encoding="ascii")
    scope_fixture = Path(__file__).with_name("host_preflight_scope.py")

    misc_stdout, misc_stderr, misc_rc = _run(
        [
            os.sys.executable,
            str(scope_fixture),
            str(os_release),
            str(kernel_dir),
            "--",
            str(zaigr),
            "misc",
            "check",
        ],
        cwd=project.cwd,
        env=project.env,
        timeout=90,
    )
    assert misc_rc != 0, err_msg(misc_stdout, misc_stderr)
    misc_output = misc_stdout + misc_stderr
    assert "virtiofs sandbox" in misc_output
    assert "Zaigr user/network namespace probe" in misc_output
    assert "Operation not permitted" in misc_output
    assert misc_output.count("Ubuntu setup") == 1

    start_stdout, start_stderr, start_rc = _run(
        [
            os.sys.executable,
            str(scope_fixture),
            str(os_release),
            str(kernel_dir),
            "--",
            str(zaigr),
            "project",
            "vm",
            "start",
        ],
        cwd=project.cwd,
        env=project.env,
        input="y\n",
        timeout=90,
    )
    assert start_rc != 0, err_msg(start_stdout, start_stderr)
    start_output = start_stdout + start_stderr
    assert "Zaigr user/network namespace probe" not in start_output
    assert "Host context:" not in start_output

    rebuild_stdout, rebuild_stderr, rebuild_rc = _run(
        [
            os.sys.executable,
            str(scope_fixture),
            str(os_release),
            str(kernel_dir),
            "--",
            str(zaigr),
            "project",
            "rebuild",
        ],
        cwd=project.cwd,
        env=project.env,
        timeout=90,
    )
    assert rebuild_rc != 0, err_msg(rebuild_stdout, rebuild_stderr)
    rebuild_output = rebuild_stdout + rebuild_stderr
    assert "Zaigr user/network namespace probe" not in rebuild_output
    assert "Host context:" not in rebuild_output

    expected_guidance = _ubuntu_guidance(misc_output)
    assert _ubuntu_guidance(start_output) == expected_guidance
    assert _ubuntu_guidance(rebuild_output) == expected_guidance
    assert "Ubuntu's system-wide restriction stays enabled." in expected_guidance
    for output in (misc_output, start_output, rebuild_output):
        assert "Install missing packages:" not in output
        assert "Host-enforced networking needs these tools on the host" not in output
