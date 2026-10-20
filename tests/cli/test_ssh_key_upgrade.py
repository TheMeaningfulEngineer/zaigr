"""CLI coverage for upgrading existing protected SSH key state."""

import hashlib
import os
import stat
from functools import partial

import pytest

from ..conftest import err_msg
from ..conftest import run as _run


def _checked_run(cmd, **kwargs):
    stdout, stderr, rc = _run(cmd, **kwargs)
    assert rc == 0, err_msg(stdout, stderr)
    return stdout


def _key_snapshot(key_dir):
    paths = [
        key_dir / "root-ssh.key",
        key_dir / "root-ssh.key.pub",
        key_dir / "user-ssh.key",
        key_dir / "user-ssh.key.pub",
    ]
    return {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}


@pytest.mark.timeout(420)
@pytest.mark.parametrize(
    ("label", "directory_mode"),
    [("group-writable", 0o775), ("world-writable", 0o777)],
)
def test_rebuild_repairs_writable_zaigr_directory_and_preserves_existing_keys(
    project, setup_factory, label, directory_mode
):
    """Rebuild repairs unsafe directory write bits without replacing SSH keys."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    key_dir = project.home / ".zaigr"

    setup_factory(
        setup_name="ssh-key-upgrade",
        script_content="printf 'replayed\n' > /etc/zaigr-ssh-key-upgrade",
    )
    run(f"{zaigr} project vm start", input="y\n", timeout=180)
    run(f"{zaigr} project setup run ssh-key-upgrade", input="y\n", timeout=180)
    run(f"{zaigr} project vm stop", timeout=60)

    keys_before = _key_snapshot(key_dir)
    key_dir.chmod(directory_mode)
    assert stat.S_IMODE(key_dir.stat().st_mode) == directory_mode

    rebuilt = run(f"{zaigr} project rebuild", timeout=300)
    assert "Rebuilt project image from applied setups" in rebuilt
    assert stat.S_IMODE(key_dir.stat().st_mode) & 0o022 == 0
    assert _key_snapshot(key_dir) == keys_before

    run(f"{zaigr} project vm start", timeout=180)
    replayed = run(
        f"{zaigr} project vm exec -- cat /etc/zaigr-ssh-key-upgrade",
        timeout=20,
    )
    assert replayed.strip() == "replayed"


@pytest.mark.timeout(300)
def test_vm_start_still_refuses_unsafe_existing_private_key_permissions(project):
    """Directory migration does not relax the private key's owner-only mode."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    key_dir = project.home / ".zaigr"
    private_key = key_dir / "root-ssh.key"

    run(f"{zaigr} project vm start", input="y\n", timeout=180)
    run(f"{zaigr} project vm stop", timeout=60)
    original_mode = stat.S_IMODE(private_key.stat().st_mode)
    private_key.chmod(0o644)

    try:
        stdout, stderr, rc = _run(
            f"{zaigr} project vm start",
            cwd=project.cwd,
            env=project.env,
            timeout=60,
        )
    finally:
        private_key.chmod(original_mode)
    assert rc != 0, err_msg(stdout, stderr)
    assert "no group/other permissions" in (stdout + stderr)


@pytest.mark.timeout(300)
def test_vm_start_refuses_key_and_lock_aliases_and_orphan_public_symlink(project):
    """Key and lock opens reject aliases without modifying their targets."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    key_dir = project.home / ".zaigr"
    private_key = key_dir / "root-ssh.key"

    run(f"{zaigr} project vm start", input="y\n", timeout=180)
    run(f"{zaigr} project vm stop", timeout=60)

    key_symlink = project.cwd / "root-key-target"
    private_key_bytes = private_key.read_bytes()
    private_key.rename(key_symlink)
    private_key.symlink_to(key_symlink)
    try:
        stdout, stderr, rc = _run(
            f"{zaigr} project vm start",
            cwd=project.cwd,
            env=project.env,
            timeout=60,
        )
    finally:
        private_key.unlink()
        key_symlink.rename(private_key)
    assert rc != 0, err_msg(stdout, stderr)
    assert "without following symlinks" in (stdout + stderr)
    assert private_key.read_bytes() == private_key_bytes

    linked_key = project.cwd / "linked-root-ssh.key"
    os.link(private_key, linked_key)
    try:
        stdout, stderr, rc = _run(
            f"{zaigr} project vm start",
            cwd=project.cwd,
            env=project.env,
            timeout=60,
        )
    finally:
        linked_key.unlink(missing_ok=True)
    assert rc != 0, err_msg(stdout, stderr)
    assert "single-link" in (stdout + stderr)

    lock_path = key_dir / "root-ssh.key.lock"
    lock_path.unlink(missing_ok=True)
    lock_target = project.cwd / "ssh-key-lock-target"
    lock_target.write_text("outside lock target\n", encoding="utf-8")
    lock_path.symlink_to(lock_target)
    try:
        stdout, stderr, rc = _run(
            f"{zaigr} project vm start",
            cwd=project.cwd,
            env=project.env,
            timeout=60,
        )
    finally:
        lock_path.unlink(missing_ok=True)
    assert rc != 0, err_msg(stdout, stderr)
    assert "without following symlinks" in (stdout + stderr)
    assert lock_target.read_text(encoding="utf-8") == "outside lock target\n"

    public_key = key_dir / "root-ssh.key.pub"
    public_target = project.cwd / "root-public-key-target"
    private_target = project.cwd / "root-private-key-target"
    private_key.rename(private_target)
    public_key.rename(public_target)
    public_key_bytes = public_target.read_bytes()
    public_key.symlink_to(public_target)
    try:
        stdout, stderr, rc = _run(
            f"{zaigr} project vm start",
            cwd=project.cwd,
            env=project.env,
            timeout=60,
        )
    finally:
        public_key.unlink(missing_ok=True)
        public_target.rename(public_key)
        private_target.rename(private_key)
    assert rc != 0, err_msg(stdout, stderr)
    assert "exists without its private key; refusing to overwrite or follow it" in (
        stdout + stderr
    )
    assert public_key.read_bytes() == public_key_bytes


@pytest.mark.timeout(300)
def test_vm_start_refuses_symlinked_zaigr_directory_without_touching_target(project):
    """An alias for ~/.zaigr remains invalid even if its target is writable."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    key_dir = project.home / ".zaigr"

    run(f"{zaigr} project vm start", input="y\n", timeout=180)
    run(f"{zaigr} project vm stop", timeout=60)
    target_mode = stat.S_IMODE(key_dir.stat().st_mode)
    target = project.home / ".zaigr-real"
    key_dir.rename(target)
    target.chmod(0o775)
    key_dir.symlink_to(target.name, target_is_directory=True)

    try:
        stdout, stderr, rc = _run(
            f"{zaigr} project vm start",
            cwd=project.cwd,
            env=project.env,
            timeout=60,
        )
        target_mode_after_refusal = stat.S_IMODE(target.stat().st_mode)
    finally:
        key_dir.unlink()
        target.rename(key_dir)
        key_dir.chmod(target_mode)

    assert rc != 0, err_msg(stdout, stderr)
    assert "symlink" in (stdout + stderr).lower() or "canonical" in (
        stdout + stderr
    ).lower()
    assert target_mode_after_refusal == 0o775
    assert stat.S_IMODE(key_dir.stat().st_mode) == target_mode
