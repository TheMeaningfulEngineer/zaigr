"""Public VM coverage for the two virtiofs shares."""

import os
from functools import partial

import pytest

from ..conftest import err_msg
from ..conftest import run as _run


def _checked_run(command, **kwargs):
    stdout, stderr, code = _run(command, **kwargs)
    assert code == 0, err_msg(stdout, stderr)
    return stdout


@pytest.mark.timeout(300)
def test_both_shares_mount_and_guest_user_root_write_as_caller(project):
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    run(f"{zaigr} project vm start", input="y\n", timeout=180)
    mounts = run(
        f"{zaigr} project vm exec -- findmnt -n -o FSTYPE /home/user/workspace",
        timeout=20,
    )
    assert mounts.strip() == "virtiofs"

    for shared in (project.cwd, project.store_dir / "agent-state"):
        private = shared / "host-private"
        private.write_text("host-secret\n")
        private.chmod(0o600)
    assert run(f"{zaigr} project vm exec -- cat /home/user/workspace/host-private", timeout=20) == "host-secret\n"
    assert run(f"{zaigr} project vm exec -- cat /home/user/.zaigr-agent-state/host-private", timeout=20) == "host-secret\n"
    run(f"{zaigr} project vm exec -- tee /home/user/workspace/host-private", input="guest-update\n", timeout=20)
    run(f"{zaigr} project vm exec -- tee /home/user/.zaigr-agent-state/host-private", input="guest-update\n", timeout=20)
    for shared in (project.cwd, project.store_dir / "agent-state"):
        assert (shared / "host-private").read_text() == "guest-update\n"
    mounts = run(
        f"{zaigr} project vm exec -- findmnt -n -o FSTYPE /home/user/.zaigr-agent-state",
        timeout=20,
    )
    assert mounts.strip() == "virtiofs"

    run(f"{zaigr} project vm exec -- touch /home/user/workspace/user-write", timeout=20)
    run(f"{zaigr} project vm exec -- chmod 600 /home/user/workspace/user-write", timeout=20)
    run(f"{zaigr} project vm exec -- touch /home/user/.zaigr-agent-state/user-write", timeout=20)
    run(f"{zaigr} project vm exec -- chmod 600 /home/user/.zaigr-agent-state/user-write", timeout=20)
    run(f"{zaigr} project vm exec --root -- touch /home/user/workspace/root-write", input="y\n", timeout=20)
    run(f"{zaigr} project vm exec --root -- chmod 600 /home/user/workspace/root-write", input="y\n", timeout=20)
    run(f"{zaigr} project vm exec --root -- touch /home/user/.zaigr-agent-state/root-write", input="y\n", timeout=20)
    run(f"{zaigr} project vm exec --root -- chmod 600 /home/user/.zaigr-agent-state/root-write", input="y\n", timeout=20)
    for shared in (project.cwd, project.store_dir / "agent-state"):
        for name in ("user-write", "root-write"):
            stat = (shared / name).stat()
            assert (stat.st_uid, stat.st_gid, stat.st_mode & 0o777) == (
                os.geteuid(), os.getegid(), 0o600
            )
