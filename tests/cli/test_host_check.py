"""Host checks exercise the real bundled daemon without creating a project VM."""

import os

from ..conftest import err_msg, run


def test_host_check_probes_sandbox_without_project_state(zaigr_bin, zaigr_home, test_root):
    workspace = test_root / "workspace"
    workspace.mkdir()
    canary = workspace / "keep"
    canary.write_text("unchanged\n")
    # VM socket checks must work even when TMPDIR is unusable.
    tmpdir = test_root / "not-a-directory"
    tmpdir.write_text("keep\n")
    env = {**os.environ, "TMPDIR": str(tmpdir)}

    stdout, stderr, rc = run([zaigr_bin, "misc", "check"], cwd=workspace, env=env)
    assert rc == 0, err_msg(stdout, stderr)
    assert stdout.startswith("Host: ")
    assert "(kernel " in stdout
    assert "QEMU virtiofs support" in stdout
    assert "host tools" in stdout
    assert "virtiofs sandbox" in stdout
    assert "answered a vhost-user request" in stdout
    assert "5/5 checks passed" in stdout
    assert list(workspace.iterdir()) == [canary]
    assert canary.read_text() == "unchanged\n"
    assert not (zaigr_home / ".zaigr/store").exists()
    assert not list((zaigr_home / ".zaigr").glob("*.qcow2"))

    processes, stderr, rc = run(["ps", "-eo", "args="])
    assert rc == 0, err_msg(processes, stderr)
    assert str(zaigr_home / ".zaigr/virtiofsd-") not in processes


def test_host_check_reports_missing_tools_and_still_probes_sandbox(zaigr_bin, zaigr_home, test_root):
    empty_path = test_root / "empty-bin"
    empty_path.mkdir()
    stdout, stderr, rc = run(
        [zaigr_bin, "misc", "check"],
        env={**os.environ, "PATH": str(empty_path)},
    )
    assert rc == 1, err_msg(stdout, stderr)
    assert "qemu-system-x86_64 not found in PATH" in stdout
    assert "missing host tools: ssh, ssh-keygen" in stdout
    assert "install qemu-utils, openssh-client and e2fsprogs" in stdout
    # No newuidmap/newgidmap helpers are needed for the production mapping.
    assert "answered a vhost-user request" in stdout
    assert "3/5 checks passed" in stdout
    assert not (zaigr_home / ".zaigr/store").exists()
