"""Admission rules for broad maintenance networking."""

import shlex

import pexpect
import pytest

from tests.conftest import err_msg, run, spawn_interactive


@pytest.mark.parametrize("runtime", ["docker", "k3s"])
def test_applied_root_runtime_blocks_maintenance_setup_and_capture(project, setup_factory, runtime):
    """A recorded Docker or k3s setup keeps every attached maintenance path closed."""
    zaigr = project.zaigr_bin
    env = project.env
    env.update({"ZAIGR_VM_RAM": "512", "ZAIGR_VM_CPU": "1", "ZAIGR_DISK_SIZE": "8G"})
    setup_factory(runtime, f"printf '{runtime} setup applied\\n' > /etc/zaigr-{runtime}-admission")

    if runtime == "k3s":
        # Build a real custom global base, then let project initialization copy
        # its applied setup provenance into this project's image history.
        stdout, stderr, rc = run(
            [zaigr, "global", "base-image", "setup", "run", runtime],
            cwd=project.cwd.parent.parent, env=env, timeout=180,
        )
        assert rc == 0, err_msg(stdout, stderr)
    else:
        # Docker is applied locally while the project's VM is stopped.
        stdout, stderr, rc = run(
            [zaigr, "project", "vm", "start"], cwd=project.cwd, env=env,
            input="y\n", timeout=180,
        )
        assert rc == 0, err_msg(stdout, stderr)
        stdout, stderr, rc = run(
            [zaigr, "project", "vm", "stop"], cwd=project.cwd, env=env,
            timeout=60,
        )
        assert rc == 0, err_msg(stdout, stderr)
        stdout, stderr, rc = run(
            [zaigr, "project", "setup", "run", runtime], cwd=project.cwd, env=env,
            timeout=180,
        )
        assert rc == 0, err_msg(stdout, stderr)
        assert "Setup applied to stopped project image" in stdout

    stdout, stderr, rc = run(
        [zaigr, "project", "vm", "start"], cwd=project.cwd, env=env,
        input="y\n", timeout=180,
    )
    assert rc == 0, err_msg(stdout, stderr)
    applied = run(
        [zaigr, "project", "setup", "list", "--applied"],
        cwd=project.cwd, env=env,
    )
    assert applied[2] == 0, err_msg(applied[0], applied[1])
    assert runtime in applied[0]
    stdout, stderr, rc = run(
        [zaigr, "project", "vm", "exec", "--", "test", "-f", f"/etc/zaigr-{runtime}-admission"],
        cwd=project.cwd, env=env, timeout=20,
    )
    assert rc == 0, err_msg(stdout, stderr)

    stdout, stderr, rc = run(
        [zaigr, "shell", "--root", "--full-network"], cwd=project.cwd, env=env,
        input="y\n", timeout=30,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert f"root-equivalent runtime setup(s): {runtime}" in stdout + stderr

    setup_factory("safe-probe", "printf 'unexpected\\n' > /tmp/zaigr-safe-probe-ran")
    stdout, stderr, rc = run(
        [zaigr, "project", "setup", "run", "safe-probe"], cwd=project.cwd, env=env,
        timeout=30,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert "project image contains root-equivalent runtime setup(s)" in stdout + stderr
    stdout, stderr, rc = run(
        [zaigr, "project", "setup", "capture", "start"], cwd=project.cwd, env=env,
        input="y\n", timeout=30,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert "project image contains root-equivalent runtime setup(s)" in stdout + stderr

    stdout, stderr, rc = run(
        [zaigr, "project", "vm", "exec", "--", "test", "!", "-e", "/tmp/zaigr-safe-probe-ran"],
        cwd=project.cwd, env=env, timeout=20,
    )
    assert rc == 0, err_msg(stdout, stderr)
    stdout, stderr, rc = run(
        [zaigr, "project", "firewall", "show"], cwd=project.cwd, env=env,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert "maintenance sessions: 0" in stdout

    stdout, stderr, rc = run(
        [zaigr, "project", "vm", "stop"], cwd=project.cwd, env=env, timeout=60,
    )
    assert rc == 0, err_msg(stdout, stderr)
    stdout, stderr, rc = run(
        [zaigr, "project", "rebuild"], cwd=project.cwd, env=env,
        input="y\n", timeout=240,
    )
    assert rc == 0, err_msg(stdout, stderr)
    stdout, stderr, rc = run(
        [zaigr, "project", "vm", "start"], cwd=project.cwd, env=env,
        input="y\n", timeout=180,
    )
    assert rc == 0, err_msg(stdout, stderr)
    stdout, stderr, rc = run(
        [zaigr, "shell", "--root", "--full-network"], cwd=project.cwd, env=env,
        input="y\n", timeout=30,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert f"root-equivalent runtime setup(s): {runtime}" in stdout + stderr


def test_failed_attached_setup_leaves_marker_that_blocks_later_maintenance(
    project, setup_factory, request
):
    """Only a successful fresh rebuild clears failure lockout and partial writes."""
    zaigr = project.zaigr_bin
    env = project.env
    env.update({"ZAIGR_VM_RAM": "512", "ZAIGR_VM_CPU": "1", "ZAIGR_DISK_SIZE": "8G"})
    rebuild_mode = project.cwd / "failure-rebuild-mode"
    rebuild_mode.write_text("succeed\n", encoding="utf-8")
    setup_factory(
        "rebuild-probe",
        "printf 'v1\\n' > /etc/zaigr-rebuild-probe-version",
    )
    stdout, stderr, rc = run(
        [zaigr, "project", "vm", "start"], cwd=project.cwd, env=env,
        input="y\n", timeout=180,
    )
    assert rc == 0, err_msg(stdout, stderr)
    stdout, stderr, rc = run(
        [zaigr, "project", "setup", "run", "rebuild-probe"],
        cwd=project.cwd, env=env, timeout=120,
    )
    assert rc == 0, err_msg(stdout, stderr)

    setup_factory("failure-probe", "printf 'partial\\n' > /etc/zaigr-failure-probe\nexit 19")
    stdout, stderr, rc = run(
        [zaigr, "project", "setup", "run", "failure-probe"], cwd=project.cwd,
        env=env, timeout=60,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert (project.store_dir / "setup-failed-once").is_file()
    stdout, stderr, rc = run(
        [zaigr, "project", "vm", "exec", "--", "test", "-f", "/etc/zaigr-failure-probe"],
        cwd=project.cwd, env=env, timeout=20,
    )
    assert rc == 0, err_msg(stdout, stderr)

    stdout, stderr, rc = run(
        [zaigr, "shell", "--root", "--full-network"], cwd=project.cwd, env=env,
        input="y\n", timeout=30,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert "setup failed or was interrupted" in stdout + stderr
    refusal = stdout + stderr
    assert "Stop the VM and run `zaigr project rebuild`" in refusal
    assert "zaigr project clean" in refusal
    assert "partial image changes that are absent from setup records" in refusal
    stdout, stderr, rc = run(
        [zaigr, "project", "firewall", "show"], cwd=project.cwd, env=env,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert "maintenance sessions: 0" in stdout

    stdout, stderr, rc = run(
        [zaigr, "project", "vm", "stop"], cwd=project.cwd, env=env, timeout=60,
    )
    assert rc == 0, err_msg(stdout, stderr)
    setup_factory(
        "rebuild-probe",
        "if [ \"$(cat /home/user/workspace/failure-rebuild-mode)\" != succeed ]; then\n"
        "  printf 'failed rebuild write\\n' > /etc/zaigr-failed-rebuild-partial\n"
        "  exit 29\n"
        "fi\n"
        "printf 'v2\\n' > /etc/zaigr-rebuild-probe-version",
    )
    rebuild_mode.write_text("fail\n", encoding="utf-8")
    stdout, stderr, rc = run(
        [zaigr, "project", "rebuild"], cwd=project.cwd, env=env,
        input="a\n", timeout=180,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert "Rebuild setup failed: rebuild-probe" in stdout + stderr
    assert "project rebuild aborted after setup rebuild-probe failed" in stdout + stderr
    assert (project.store_dir / "setup-failed-once").is_file()

    stdout, stderr, rc = run(
        [zaigr, "project", "vm", "start"], cwd=project.cwd, env=env,
        input="y\n", timeout=180,
    )
    assert rc == 0, err_msg(stdout, stderr)
    stdout, stderr, rc = run(
        [zaigr, "project", "vm", "exec", "--", "test", "-f", "/etc/zaigr-failure-probe"],
        cwd=project.cwd, env=env, timeout=20,
    )
    assert rc == 0, err_msg(stdout, stderr)
    stdout, stderr, rc = run(
        [zaigr, "project", "vm", "exec", "--", "cat", "/etc/zaigr-rebuild-probe-version"],
        cwd=project.cwd, env=env, timeout=20,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert stdout.strip() == "v1"
    stdout, stderr, rc = run(
        [zaigr, "project", "vm", "exec", "--", "test", "!", "-e", "/etc/zaigr-failed-rebuild-partial"],
        cwd=project.cwd, env=env, timeout=20,
    )
    assert rc == 0, err_msg(stdout, stderr)
    stdout, stderr, rc = run(
        [zaigr, "shell", "--root", "--full-network"], cwd=project.cwd, env=env,
        input="y\n", timeout=30,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert "setup failed or was interrupted" in stdout + stderr

    stdout, stderr, rc = run(
        [zaigr, "project", "vm", "stop"], cwd=project.cwd, env=env, timeout=60,
    )
    assert rc == 0, err_msg(stdout, stderr)
    rebuild_mode.write_text("succeed\n", encoding="utf-8")
    stdout, stderr, rc = run(
        [zaigr, "project", "rebuild"], cwd=project.cwd, env=env,
        input="y\n", timeout=180,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert not (project.store_dir / "setup-failed-once").exists()

    stdout, stderr, rc = run(
        [zaigr, "project", "vm", "start"], cwd=project.cwd, env=env,
        input="y\n", timeout=180,
    )
    assert rc == 0, err_msg(stdout, stderr)
    stdout, stderr, rc = run(
        [zaigr, "project", "vm", "exec", "--", "test", "!", "-e", "/etc/zaigr-failure-probe", "-a", "!", "-e", "/etc/zaigr-failed-rebuild-partial"],
        cwd=project.cwd, env=env, timeout=20,
    )
    assert rc == 0, err_msg(stdout, stderr)
    stdout, stderr, rc = run(
        [zaigr, "project", "vm", "exec", "--", "cat", "/etc/zaigr-rebuild-probe-version"],
        cwd=project.cwd, env=env, timeout=20,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert stdout.strip() == "v2"

    shell = spawn_interactive(
        f"{shlex.quote(str(zaigr))} shell --root --full-network",
        cwd=project.cwd, env=env, timeout=45,
    )
    request.addfinalizer(lambda: shell.close(force=True) if shell.isalive() else None)
    shell.expect(r"Accessing this VM as root automatically marks the project image dirty\.")
    shell.expect(r"Continue with root shell\? \[y/N\]")
    shell.sendline("y")
    shell.expect(r"WARNING: --full-network gives this root shell")
    shell.expect(r"root@[^:]+:.*# ")
    shell.sendline("printf '\\n%s\\n' REBUILT_MAINTENANCE_OK")
    shell.expect(r"\r\nREBUILT_MAINTENANCE_OK\r\n")
    shell.expect(r"root@[^:]+:.*# ")
    shell.sendline("exit")
    shell.expect(pexpect.EOF)
    shell.close()
    assert shell.exitstatus == 0


@pytest.mark.parametrize("runtime", ["docker", "k3s"])
def test_attached_root_runtime_setup_is_rejected_before_execution(project, setup_factory, runtime):
    """A clean live VM cannot install root-equivalent runtimes over its tunnel."""
    zaigr = project.zaigr_bin
    env = project.env
    env.update({"ZAIGR_VM_RAM": "512", "ZAIGR_VM_CPU": "1", "ZAIGR_DISK_SIZE": "8G"})
    marker = f"/tmp/zaigr-{runtime}-must-not-run"
    setup_factory(runtime, f"printf 'unexpected\\n' > {marker}")

    stdout, stderr, rc = run(
        [zaigr, "project", "vm", "start"], cwd=project.cwd, env=env,
        input="y\n", timeout=180,
    )
    assert rc == 0, err_msg(stdout, stderr)
    stdout, stderr, rc = run(
        [zaigr, "project", "setup", "run", runtime], cwd=project.cwd,
        env=env, timeout=30,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert "root-equivalent runtime" in stdout + stderr
    stdout, stderr, rc = run(
        [zaigr, "project", "vm", "exec", "--", "test", "!", "-e", marker],
        cwd=project.cwd, env=env, timeout=20,
    )
    assert rc == 0, err_msg(stdout, stderr)
    stdout, stderr, rc = run(
        [zaigr, "project", "firewall", "show"], cwd=project.cwd, env=env,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert "maintenance sessions: 0" in stdout
