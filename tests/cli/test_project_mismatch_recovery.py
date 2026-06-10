"""CLI tests for project image mismatch recovery."""

from functools import partial
import os
from pathlib import Path
import re

import pexpect
import pytest

from ..conftest import err_msg, run as _run, spawn_interactive

run = _run


def _checked_run(cmd, **kwargs):
    stdout, stderr, rc = _run(cmd, **kwargs)
    assert rc == 0, err_msg(stdout, stderr)
    return stdout


def _project_image_name_from_status(output):
    match = re.search(
        r"^project-image: (?:\(missing; expected )?(image-[^\s)]+\.qcow2)",
        output,
        re.MULTILINE,
    )
    assert match, output
    return match.group(1)


def _base_rootfs_version_from_command(zaigr_bin, cwd, env):
    stdout, stderr, rc = _run(
        [str(zaigr_bin), "misc", "full-version"],
        cwd=cwd,
        env=env,
        timeout=10,
    )
    assert rc == 0, err_msg(stdout, stderr)
    match = re.search(r"^base-image: (.+)$", stdout, re.MULTILINE)
    assert match, stdout
    return match.group(1)


def _base_rootfs_version(project):
    return _base_rootfs_version_from_command(project.zaigr_bin, project.cwd, project.env)


def _write_synthetic_project_store(project, committed=None, dirty=False):
    store_dir = project.store_dir
    store_dir.mkdir(parents=True, exist_ok=True)
    (store_dir / "project-path").write_text(f"{project.cwd}\n", encoding="utf-8")
    (store_dir / "config").write_text("disk=100G\n", encoding="utf-8")
    (store_dir / "ram").write_text("512\n", encoding="utf-8")
    (store_dir / "cpus").write_text("1\n", encoding="utf-8")

    committed_dir = store_dir / "committed"
    committed_dir.mkdir(exist_ok=True)
    for index, (name, content) in enumerate(committed or [], start=1):
        (committed_dir / f"{index:03d}-{name}.sh").write_bytes(content)

    if dirty:
        (store_dir / "project-image-dirty").write_text(
            "image=image-dirty.qcow2\n"
            "reason=root-shell\n"
            "source=zaigr shell --root\n"
            "time=2026-05-28T00:00:00Z\n",
            encoding="utf-8",
        )
    return store_dir


def _synthetic_project_store_for_path(zaigr_bin, cwd, env):
    stdout, stderr, rc = _run(
        [str(zaigr_bin), "misc", "test-helpers", "project-store-dir"],
        cwd=cwd,
        env=env,
        timeout=10,
    )
    assert rc == 0, err_msg(stdout, stderr)
    store_dir = Path(stdout.strip())
    store_dir.mkdir(parents=True, exist_ok=True)
    (store_dir / "project-path").write_text(f"{cwd}\n", encoding="utf-8")
    (store_dir / "config").write_text("disk=1G\n", encoding="utf-8")
    return store_dir


@pytest.mark.timeout(180)
def test_shell_preset_missing_project_image_reports_rebuildable_image_problem(
    project, setup_factory
):
    """Missing committed project images are reported directly, not as failed setup cleanup."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    setup_factory(
        setup_name="missing-image-local",
        script_content="printf 'codex-v1\\n' > /etc/zaigr-mismatch-recovery",
    )
    setup_factory.preset(
        name="missing-image-preset",
        run="printf 'preset-ran\\n'",
        setups=["missing-image-local"],
    )
    run(
        f"{zaigr} project setup run missing-image-local",
        input="y\n",
        timeout=120,
    )
    stdout, stderr, rc = _run(
        f"{zaigr} project vm stop",
        cwd=project.cwd,
        env=project.env,
        timeout=60,
    )
    if rc != 0:
        assert "project VM is not running" in stdout + stderr, err_msg(stdout, stderr)

    status = run(
        f"{zaigr} project status",
        timeout=10,
    )
    expected_image = _project_image_name_from_status(status)
    (project.store_dir / expected_image).unlink()

    stdout, stderr, rc = _run(
        f"{zaigr} shell --preset missing-image-preset",
        cwd=project.cwd,
        env=project.env,
        input="\n",
        timeout=30,
    )

    assert rc != 0
    combined = stdout + stderr
    assert "warning: the project image cannot be found." in combined
    assert f"expected image: {expected_image}" in combined
    assert "remove failed setups" not in combined
    assert "You can rebuild the project image or inspect project status." in combined
    assert "Action [" not in combined


@pytest.mark.timeout(180)
def test_project_status_explains_missing_expected_project_image(project, setup_factory):
    """`project status` uses the same concrete missing-image language as startup recovery."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    setup_factory(
        setup_name="status-missing-image",
        script_content="printf 'status-image\\n' > /etc/zaigr-missing-image",
    )
    run(
        f"{zaigr} project setup run status-missing-image",
        input="y\n",
        timeout=120,
    )
    stdout, stderr, rc = _run(
        f"{zaigr} project vm stop",
        cwd=project.cwd,
        env=project.env,
        timeout=60,
    )
    if rc != 0:
        assert "project VM is not running" in stdout + stderr, err_msg(stdout, stderr)

    status = run(
        f"{zaigr} project status",
        timeout=10,
    )
    expected_image = _project_image_name_from_status(status)
    (project.store_dir / expected_image).unlink()

    stdout, stderr, rc = _run(
        f"{zaigr} project status",
        cwd=project.cwd,
        env=project.env,
        timeout=10,
    )

    assert rc == 0, err_msg(stdout, stderr)
    assert "warning: the project image cannot be found." in stdout
    assert f"expected image: {expected_image}" in stdout
    assert "You can rebuild the project image or inspect project status." in stdout
    assert "remove failed setups" not in stdout + stderr


def test_project_status_accepts_stored_wrapper_when_source_body_and_firewall_match(
    project, setup_factory
):
    """A stored wrapper is compatible when source body and firewall entries match."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    setup_name = "source-stable-wrapper"
    setup_factory(
        setup_name=setup_name,
        script_content="printf 'source stable setup\\n'",
        firewall=["stable.example.test"],
    )
    setup_dir = project.home / ".zaigr" / "setups" / setup_name
    setup_script = (setup_dir / "setup.script").read_text(encoding="utf-8")
    stored_wrapper_payload = (
        "# generated firewall wrapper from an older zaigr version\n"
        "stable.example.test\n"
        + setup_script
    ).encode()

    store_dir = _write_synthetic_project_store(
        project,
        committed=[(setup_name, stored_wrapper_payload)],
    )
    status = run(
        f"{zaigr} project status",
        timeout=10,
    )
    expected_image = _project_image_name_from_status(status)
    (store_dir / expected_image).write_bytes(b"compatible image placeholder\n")

    stdout, stderr, rc = _run(
        f"{zaigr} project status",
        cwd=project.cwd,
        env=project.env,
        timeout=10,
    )

    combined = stdout + stderr
    assert rc == 0, err_msg(stdout, stderr)
    assert f'warning: setup "{setup_name}" has changed.' not in combined
    assert "available version:" not in combined
    assert "recorded version:" not in combined
    assert "committed to project image (1):" in stdout
    assert setup_name in stdout


@pytest.mark.timeout(240)
def test_shell_preset_reports_setup_version_mismatch_before_applying(
    project, setup_factory
):
    """A changed setup already committed to the image is diagnosed before it is applied."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    setup_factory(
        setup_name="version-mismatch-local",
        script_content="printf 'SETUP_V1_APPLIED\\n' > /etc/zaigr-setup-version",
    )
    setup_factory.preset(
        name="version-mismatch-preset",
        run="printf 'PRESET_RAN\\n'",
        setups=["version-mismatch-local"],
    )
    run(
        f"{zaigr} project setup run version-mismatch-local",
        input="y\n",
        timeout=120,
    )
    stdout, stderr, rc = _run(
        f"{zaigr} project vm stop",
        cwd=project.cwd,
        env=project.env,
        timeout=60,
    )
    if rc != 0:
        assert "project VM is not running" in stdout + stderr, err_msg(stdout, stderr)

    setup_factory(
        setup_name="version-mismatch-local",
        script_content="printf 'SETUP_V2_APPLIED\\n' > /etc/zaigr-setup-version",
    )

    stdout, stderr, rc = _run(
        f"{zaigr} shell --preset version-mismatch-preset",
        cwd=project.cwd,
        env=project.env,
        input="\n",
        timeout=120,
    )

    assert rc != 0
    combined = stdout + stderr
    assert 'warning: setup "version-mismatch-local" has changed.' in combined
    assert re.search(r"recorded version: [0-9a-f]{7}", combined)
    assert re.search(r"available version: [0-9a-f]{12}", combined)
    assert "SETUP_V2_APPLIED" not in combined
    assert "You can keep using the recorded version, rebuild with the latest setup versions, or inspect project status." in combined
    assert "Action [" not in combined

    status = run(
        f"{zaigr} project status",
        timeout=10,
    )
    assert "committed to project image (1):" in status
    output = run(
        f"{zaigr} project setup show --committed",
        timeout=10,
    )
    assert "SETUP_V1_APPLIED" in output
    assert "SETUP_V2_APPLIED" not in output


def test_project_status_missing_image_uses_concrete_recovery_wording(project):
    """`project status` reports a missing expected image with concise product wording."""
    run = partial(_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    setup_script = b"printf 'codex setup v1\\n'\n"
    _write_synthetic_project_store(project, committed=[("missing-dirty-local", setup_script)], dirty=True)

    stdout, stderr, rc = run(
        f"{zaigr} project status",
        timeout=10,
    )

    combined = stdout + stderr
    assert rc == 0, err_msg(stdout, stderr)
    expected_image = _project_image_name_from_status(stdout)
    assert "warning: the project image cannot be found." in combined
    assert f"expected image: {expected_image}" in combined
    assert "Your current image has unsaved changes from zaigr shell --root." in combined
    assert "Those changes will be lost if you rebuild." in combined
    assert "remove failed setups" not in combined


@pytest.mark.timeout(60)
def test_shell_missing_image_prompt_defaults_to_cancel(project):
    """`zaigr shell` offers only safe recovery actions for a missing project image."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    setup_script = b"printf 'codex setup v1\\n'\n"
    _write_synthetic_project_store(project, committed=[("missing-dirty-local", setup_script)], dirty=True)
    status = run(
        f"{zaigr} project status",
        timeout=10,
    )
    expected_image = _project_image_name_from_status(status)

    shell = spawn_interactive(
        f"{zaigr} shell",
        cwd=project.cwd,
        env=project.env,
        timeout=20,
    )
    try:
        shell.expect(r"warning: the project image cannot be found\.")
        shell.expect(re.escape(f"expected image: {expected_image}"))
        shell.expect(r"Your current image has unsaved changes from zaigr shell --root\.")
        shell.expect(r"Those changes will be lost if you rebuild\.")
        shell.expect(r"\[r\] rebuild\s+Rebuild the project image")
        shell.expect(r"\[s\] status\s+Show project status")
        shell.expect(r"\[c\] cancel\s+Leave project unchanged")
        shell.expect(r"\[Enter\] cancel")
        shell.expect(r"Action \[r/s/c\]:")
        shell.sendline("")
        shell.expect(pexpect.EOF)
    finally:
        shell.close(force=True)

    output = shell.transcript.getvalue()
    assert "[k] keep" not in output


@pytest.mark.timeout(60)
def test_shell_base_image_mismatch_uses_concrete_recovery_prompt(project):
    """`zaigr shell` names base-image mismatches with concrete recovery wording."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    setup_script = b"printf 'base mismatch setup\\n'\n"
    store_dir = _write_synthetic_project_store(project, committed=[("base-check", setup_script)])
    recorded_base = "038cdad"
    available_base = _base_rootfs_version(project)
    (store_dir / "base-image-version").write_text(f"{recorded_base}\n", encoding="utf-8")
    status = run(
        f"{zaigr} project status",
        timeout=10,
    )
    expected_image = _project_image_name_from_status(status)
    (store_dir / expected_image).write_bytes(b"old base image placeholder\n")

    shell = spawn_interactive(
        f"{zaigr} shell",
        cwd=project.cwd,
        env=project.env,
        timeout=20,
    )
    try:
        shell.expect(r"warning: detected a mismatch in the base image versions\.")
        shell.expect(re.escape(f"recorded base image: {recorded_base}"))
        shell.expect(re.escape(f"available base image: {available_base}"))
        shell.expect(r"This can happen after updating zaigr\.")
        shell.expect(r"\[r\] rebuild\s+Rebuild the project image")
        shell.expect(r"\[s\] status\s+Show project status")
        shell.expect(r"\[c\] cancel\s+Leave project unchanged")
        shell.expect(r"\[Enter\] cancel")
        shell.expect(r"Action \[r/s/c\]:")
        shell.sendline("")
        shell.expect(pexpect.EOF)
    finally:
        shell.close(force=True)


@pytest.mark.timeout(240)
def test_shell_base_image_mismatch_running_vm_warns_rebuild_closes_shells(project):
    """`zaigr shell` warns before offering a rebuild that will close active shells."""
    first_shell = spawn_interactive(
        f"{project.zaigr_bin} shell",
        cwd=project.cwd,
        env=project.env,
        timeout=180,
    )
    second_shell = None
    try:
        first_shell.expect(r"Initialize project and continue\? \[y/N\]")
        first_shell.sendline("y")
        first_shell.expect(r"user@[^:]+:.*[$] ")

        (project.store_dir / "base-image-version").write_text(
            "oldbase\n", encoding="utf-8"
        )
        available_base = _base_rootfs_version(project)

        second_shell = spawn_interactive(
            f"{project.zaigr_bin} shell",
            cwd=project.cwd,
            env=project.env,
            timeout=20,
        )
        second_shell.expect(r"warning: detected a mismatch in the base image versions\.")
        second_shell.expect(r"recorded base image: oldbase")
        second_shell.expect(re.escape(f"available base image: {available_base}"))
        second_shell.expect(
            r"warning: rebuilding will stop the running project VM and close any open shells connected to it\."
        )
        second_shell.expect(
            r"\[r\] rebuild\s+Stop the running VM and rebuild the project image"
        )
        second_shell.expect(r"\[k\] keep\s+Continue with the current image")
        second_shell.expect(r"\[s\] status\s+Show project status")
        second_shell.expect(r"\[c\] cancel\s+Leave project unchanged")
        second_shell.expect(r"\[Enter\] cancel")
        second_shell.expect(r"Action \[r/k/s/c\]:")
        second_shell.sendline("")
        second_shell.expect(pexpect.EOF)
    finally:
        if second_shell is not None:
            second_shell.close(force=True)
        first_shell.sendline("exit")
        first_shell.expect(r"\Z", timeout=30)
        first_shell.close(force=True)


@pytest.mark.timeout(120)
def test_project_rebuild_updates_base_image_without_deleting_store(zaigr_bin, tmp_path):
    """`zaigr project rebuild` refreshes the project image from current base metadata."""
    home = tmp_path / "home"
    cwd = tmp_path / "project"
    cwd.mkdir()
    env = os.environ.copy()
    env["HOME"] = str(home)
    run = partial(_checked_run, cwd=cwd, env=env)
    store_dir = _synthetic_project_store_for_path(zaigr_bin, cwd, env)
    (store_dir / "committed").mkdir()
    (store_dir / "base-image-version").write_text("oldbase\n", encoding="utf-8")

    stdout = run(
        [str(zaigr_bin), "project", "rebuild"],
        timeout=120,
    )

    available_base = _base_rootfs_version_from_command(zaigr_bin, cwd, env)
    assert "Rebuilt project image from committed state" in stdout
    assert f"Recorded base image version: {available_base}" in stdout
    assert store_dir.is_dir()
    assert (store_dir / "committed").is_dir()
    assert (store_dir / "config").read_text(encoding="utf-8") == "disk=1G\n"
    assert (store_dir / "base-image-version").read_text(encoding="utf-8") == f"{available_base}\n"
    assert list(store_dir.glob("image-*.qcow2"))


def test_project_rebuild_refuses_dirty_project_image_without_force(zaigr_bin, tmp_path):
    """`zaigr project rebuild` does not silently discard dirty image state."""
    home = tmp_path / "home"
    cwd = tmp_path / "project"
    cwd.mkdir()
    env = os.environ.copy()
    env["HOME"] = str(home)
    run = partial(_run, cwd=cwd, env=env)
    store_dir = _synthetic_project_store_for_path(zaigr_bin, cwd, env)
    (store_dir / "project-image-dirty").write_text(
        "image=image-dirty.qcow2\n"
        "reason=root-shell\n"
        "source=zaigr shell --root\n"
        "time=2026-05-28T00:00:00Z\n",
        encoding="utf-8",
    )
    (store_dir / "base-image-version").write_text("oldbase\n", encoding="utf-8")

    stdout, stderr, rc = run(
        [str(zaigr_bin), "project", "rebuild"],
        timeout=30,
    )

    assert rc != 0
    combined = stdout + stderr
    assert "project image has unsaved changes from zaigr shell --root" in combined
    assert "rerun with --force to rebuild anyway" in combined
    assert (store_dir / "base-image-version").read_text(encoding="utf-8") == "oldbase\n"


@pytest.mark.timeout(60)
def test_shell_setup_version_mismatch_prompt_includes_keep(project, setup_factory):
    """`zaigr shell --preset` warns before applying a changed setup."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    recorded_script = b"printf 'codex setup v1\\n'\n"
    _write_synthetic_project_store(project, committed=[("codex", recorded_script)])
    status = run(
        f"{zaigr} project status",
        timeout=10,
    )
    expected_image = _project_image_name_from_status(status)
    (project.store_dir / expected_image).write_bytes(b"compatible image placeholder\n")
    setup_factory(
        setup_name="codex",
        script_content="printf 'codex setup v2\\n'",
    )
    setup_factory.preset(
        name="codex",
        run="true",
        setups=["codex"],
    )

    shell = spawn_interactive(
        f"{zaigr} shell --preset codex",
        cwd=project.cwd,
        env=project.env,
        timeout=20,
    )
    try:
        shell.expect(r'warning: setup "codex" has changed\.')
        shell.expect(r"recorded version: [0-9a-f]+")
        shell.expect(r"available version: [0-9a-f]+")
        shell.expect(r"\[r\] rebuild\s+Rebuild with latest setup versions")
        shell.expect(r"\[k\] keep\s+Continue with the current image")
        shell.expect(r"\[s\] status\s+Show project status")
        shell.expect(r"\[c\] cancel\s+Leave project unchanged")
        shell.expect(r"\[Enter\] cancel")
        shell.expect(r"Action \[r/k/s/c\]:")
        shell.sendline("")
        shell.expect(pexpect.EOF)
    finally:
        shell.close(force=True)

    output = shell.transcript.getvalue()
    assert "Applying setup: codex" not in output


@pytest.mark.timeout(300)
def test_shell_setup_version_mismatch_rebuilds_with_latest_setup(project, setup_factory):
    """Choosing rebuild for a changed setup updates committed setup state."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    setup_factory(
        setup_name="latest-local",
        script_content="printf 'SETUP_V1_APPLIED\\n' > /etc/zaigr-setup-version",
    )
    setup_factory.preset(
        name="latest-preset",
        run="cat /etc/zaigr-setup-version",
        setups=["latest-local"],
    )
    run(
        f"{zaigr} project setup run latest-local",
        input="y\n",
        timeout=120,
    )
    stdout, stderr, rc = _run(
        f"{zaigr} project vm stop",
        cwd=project.cwd,
        env=project.env,
        timeout=60,
    )
    if rc != 0:
        assert "project VM is not running" in stdout + stderr, err_msg(stdout, stderr)

    setup_factory(
        setup_name="latest-local",
        script_content="printf 'SETUP_V2_APPLIED\\n' > /etc/zaigr-setup-version",
    )

    shell = spawn_interactive(
        f"{zaigr} shell --preset latest-preset",
        cwd=project.cwd,
        env=project.env,
        timeout=240,
    )
    try:
        shell.expect(r'warning: setup "latest-local" has changed\.')
        shell.expect(r"\[r\] rebuild\s+Rebuild with latest setup versions")
        shell.expect(r"Action \[r/k/s/c\]:")
        shell.sendline("r")
        shell.expect(r"SETUP_V2_APPLIED", timeout=240)
        shell.expect(pexpect.EOF, timeout=60)
    finally:
        shell.close(force=True)

    stdout, stderr, rc = _run(
        f"{zaigr} shell --preset latest-preset",
        cwd=project.cwd,
        env=project.env,
        timeout=120,
    )

    combined = stdout + stderr
    assert rc == 0, err_msg(stdout, stderr)
    assert 'warning: setup "latest-local" has changed.' not in combined
    assert "available version:" not in combined
    assert "SETUP_V2_APPLIED" in combined


@pytest.mark.timeout(420)
def test_project_vm_start_rebuild_recovers_after_force_rerun_duplicate_setup(
    project, setup_factory
):
    """Choosing rebuild after `setup run --force` updates the committed setup image."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    setup_factory(
        setup_name="dup-marker",
        script_content=(
            "printf 'DUP_MARKER_V1_RAN\\n'\n"
            "printf 'v1\\n' > /etc/zaigr-dup-marker"
        ),
    )

    first = run(
        f"{zaigr} project setup run dup-marker",
        input="y\n",
        timeout=120,
    )
    assert "DUP_MARKER_V1_RAN" in first

    stdout, stderr, rc = _run(
        f"{zaigr} project vm stop --abrupt",
        cwd=project.cwd,
        env=project.env,
        timeout=60,
    )
    if rc != 0:
        assert "project VM is not running" in stdout + stderr, err_msg(stdout, stderr)

    forced = run(
        f"{zaigr} project setup run --force dup-marker",
        timeout=120,
    )
    assert "DUP_MARKER_V1_RAN" in forced

    setup_factory(
        setup_name="dup-marker",
        script_content=(
            "printf 'DUP_MARKER_V2_RAN\\n'\n"
            "printf 'v2\\n' > /etc/zaigr-dup-marker"
        ),
    )

    start = spawn_interactive(
        f"{zaigr} project vm start",
        cwd=project.cwd,
        env=project.env,
        timeout=240,
    )
    try:
        start.expect(r'warning: setup "dup-marker" has changed\.', timeout=120)
        start.expect(r"\[r\] rebuild\s+Rebuild with latest setup versions")
        start.expect(r"Action \[r/k/s/c\]:")
        start.sendline("r")
        start.expect(pexpect.EOF, timeout=240)
    finally:
        start.close(force=True)

    assert start.exitstatus == 0, start.transcript.getvalue()

    marker = run(
        f"{zaigr} project vm exec -- cat /etc/zaigr-dup-marker",
        timeout=30,
    )
    assert marker.strip() == "v2"
