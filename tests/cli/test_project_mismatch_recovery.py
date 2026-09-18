"""Acceptance tests for direct project overlays, setup failure, and rebuilds."""

import hashlib
import json
import os
from functools import partial
from pathlib import Path

import pytest

from ..conftest import err_msg
from ..conftest import run as _run

FAILURE_NOTE = "This VM had a failed setup once."


def _checked_run(cmd, **kwargs):
    stdout, stderr, rc = _run(cmd, **kwargs)
    assert rc == 0, err_msg(stdout, stderr)
    return stdout


def _setup_entry(output, setup_name):
    entries = [
        line.strip()
        for line in output.splitlines()
        if setup_name in line and not line.strip().endswith(":")
    ]
    assert len(entries) == 1, output
    return entries[0]


def _project_image(project):
    images = sorted(
        path
        for path in project.store_dir.glob("*.qcow2")
        if not path.name.endswith(".wip")
    )
    assert len(images) == 1, images
    return images[0]


def _file_digest(path):
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tree_snapshot(root):
    snapshot = {}
    for path in [root, *sorted(root.rglob("*"))]:
        relative = "." if path == root else str(path.relative_to(root))
        mode = path.lstat().st_mode & 0o777
        if path.is_symlink():
            snapshot[relative] = ("symlink", mode, str(path.readlink()))
        elif path.is_dir():
            snapshot[relative] = ("directory", mode)
        else:
            snapshot[relative] = ("file", mode, path.stat().st_size, _file_digest(path))
    return snapshot


@pytest.mark.timeout(300)
def test_failed_new_setup_version_keeps_old_applied_record_and_partial_changes(
    project, setup_factory
):
    """A failed new version leaves its writes but does not replace the old record."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    setup_factory(
        setup_name="direct-failure",
        script_content="printf 'v1\\n' > /etc/zaigr-direct-failure-version",
    )
    run(
        f"{zaigr} project setup run direct-failure",
        input="y\n",
        timeout=180,
    )

    before = run(f"{zaigr} project setup list --applied", timeout=10)
    old_entry = _setup_entry(before, "direct-failure")
    stored_before = json.loads(
        (project.store_dir / "applied-setups.json").read_text(encoding="utf-8")
    )
    assert len(stored_before) == 1
    assert set(stored_before[0]) == {"name", "version"}
    assert stored_before[0]["name"] == "direct-failure"

    retry_mode = project.cwd / "direct-failure-mode"
    retry_mode.write_text("fail\n", encoding="utf-8")
    setup_factory(
        setup_name="direct-failure",
        script_content=(
            "printf 'partial-v2\\n' > /etc/zaigr-direct-failure-partial\n"
            "if [ \"$(cat /home/user/workspace/direct-failure-mode)\" != succeed ]; then\n"
            "  printf 'v2 failed after writing\\n' >&2\n"
            "  exit 23\n"
            "fi\n"
            "printf 'v2\\n' > /etc/zaigr-direct-failure-version"
        ),
    )
    stdout, stderr, rc = _run(
        f"{zaigr} project setup run direct-failure",
        cwd=project.cwd,
        env=project.env,
        timeout=120,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert "direct-failure" in stdout + stderr

    run(f"{zaigr} project vm start", timeout=180)
    partial_effect = run(
        f"{zaigr} project vm exec -- cat /etc/zaigr-direct-failure-partial",
        timeout=20,
    )
    assert partial_effect.strip() == "partial-v2"

    after = run(f"{zaigr} project setup list", timeout=10)
    assert "applied (1):" in after
    assert _setup_entry(after, "direct-failure") == old_entry
    assert "awaiting" not in after.lower()
    assert "pending" not in after.lower()
    assert "failed setups" not in after.lower()
    assert "failed (" not in after.lower()
    assert json.loads(
        (project.store_dir / "applied-setups.json").read_text(encoding="utf-8")
    ) == stored_before

    status = run(f"{zaigr} project status", timeout=10)
    assert status.count(FAILURE_NOTE) == 1
    assert status.lower().count("failed setup") == 1
    assert "failed setups" not in status.lower()
    assert "failed (" not in status.lower()
    assert "failed:" not in status.lower()
    assert "awaiting" not in status.lower()
    assert "pending" not in status.lower()
    assert not (project.store_dir / "awaiting-commit").exists()
    assert not (project.store_dir / "failed").exists()

    retry_mode.write_text("succeed\n", encoding="utf-8")
    run(
        f"{zaigr} project setup run direct-failure",
        timeout=120,
    )

    current = run(f"{zaigr} project setup list --applied", timeout=10)
    assert "applied (1):" in current
    assert _setup_entry(current, "direct-failure") != old_entry
    status = run(f"{zaigr} project status", timeout=10)
    assert status.count(FAILURE_NOTE) == 1


@pytest.mark.timeout(240)
def test_failed_forced_rerun_removes_the_exact_applied_identity(
    project, setup_factory
):
    """Failure of a forced identical version removes that applied identity."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    mode = project.cwd / "force-failure-mode"
    mode.write_text("succeed\n", encoding="utf-8")
    setup_factory(
        setup_name="force-failure",
        script_content=(
            "if [ \"$(cat /home/user/workspace/force-failure-mode)\" = succeed ]; then\n"
            "  printf 'initial-success\\n' > /etc/zaigr-force-failure-success\n"
            "  exit 0\n"
            "fi\n"
            "printf 'distinct-failed-attempt\\n' > /etc/zaigr-force-failure-attempt\n"
            "exit 29"
        ),
    )

    run(
        f"{zaigr} project setup run force-failure",
        input="y\n",
        timeout=180,
    )
    mode.write_text("fail\n", encoding="utf-8")

    stdout, stderr, rc = _run(
        f"{zaigr} project setup run --force force-failure",
        cwd=project.cwd,
        env=project.env,
        timeout=120,
    )
    assert rc != 0, err_msg(stdout, stderr)

    applied = run(f"{zaigr} project setup list --applied", timeout=10)
    assert "applied (0):" in applied
    assert "force-failure" not in applied
    run(f"{zaigr} project vm start", timeout=180)
    failed_attempt = run(
        f"{zaigr} project vm exec -- cat /etc/zaigr-force-failure-attempt",
        timeout=20,
    )
    assert failed_attempt.strip() == "distinct-failed-attempt"
    run(
        f"{zaigr} project vm exec -- test -f /etc/zaigr-force-failure-success",
        timeout=20,
    )
    status = run(f"{zaigr} project status", timeout=10)
    assert status.count(FAILURE_NOTE) == 1


@pytest.mark.timeout(240)
def test_pre_execution_error_changes_no_setup_state(project):
    """An error before guest execution creates no applied record or failure note."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    run(f"{zaigr} project vm start", input="y\n", timeout=180)
    stdout, stderr, rc = _run(
        f"{zaigr} project setup run definition-that-does-not-exist",
        cwd=project.cwd,
        env=project.env,
        timeout=30,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert "not found" in (stdout + stderr).lower()

    applied = run(f"{zaigr} project setup list --applied", timeout=10)
    assert "applied (0):" in applied
    status = run(f"{zaigr} project status", timeout=10)
    assert FAILURE_NOTE not in status


@pytest.mark.timeout(240)
def test_guest_kill_is_not_reported_as_setup_timeout(project, setup_factory):
    """A guest-side SIGKILL before the deadline is reported as a kill, not a timeout."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    setup_factory(
        setup_name="guest-kill",
        script_content="bash -c 'kill -KILL $$'",
    )

    stdout, stderr, rc = _run(
        f"{zaigr} project setup run guest-kill",
        cwd=project.cwd,
        env=project.env,
        input="y\n",
        timeout=180,
    )
    assert rc != 0, err_msg(stdout, stderr)
    output = stdout + stderr
    assert "exited with status 137 before the 30m0s timeout elapsed" in output
    assert "setup execution timed out" not in output

    applied = run(f"{zaigr} project setup list --applied", timeout=10)
    assert "applied (0):" in applied
    status = run(f"{zaigr} project status", timeout=10)
    assert status.count(FAILURE_NOTE) == 1


@pytest.mark.timeout(360)
def test_setup_applied_to_stopped_project_leaves_it_stopped(project, setup_factory):
    """Setup work may transiently boot a stopped project but preserves stopped state."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    setup_factory(
        setup_name="stopped-direct-apply",
        script_content="printf 'stopped-ok\\n' > /etc/zaigr-stopped-direct-apply",
    )

    run(f"{zaigr} project vm start", input="y\n", timeout=180)
    run(f"{zaigr} project vm stop", timeout=60)
    run(
        f"{zaigr} project setup run stopped-direct-apply",
        timeout=180,
    )

    status = run(f"{zaigr} project status", timeout=10)
    assert "status: not running" in status
    assert "applied (1):" in status

    run(f"{zaigr} project vm start", timeout=180)
    marker = run(
        f"{zaigr} project vm exec -- cat /etc/zaigr-stopped-direct-apply",
        timeout=20,
    )
    assert marker.strip() == "stopped-ok"


@pytest.mark.timeout(480)
def test_rebuild_uses_current_setup_version_and_clean_clears_all_state(
    project, setup_factory
):
    """Rebuild replays current definitions; clean removes their state and warning."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    full_version = run(f"{zaigr} misc full-version", timeout=10)
    base_versions = [
        line.removeprefix("base-image: ")
        for line in full_version.splitlines()
        if line.startswith("base-image: ")
    ]
    assert len(base_versions) == 1
    current_base_version = base_versions[0]
    setup_factory(
        setup_name="rebuild-current",
        script_content=(
            "printf 'v1\\n' > /etc/zaigr-rebuild-current\n"
            "printf 'obsolete\\n' > /etc/zaigr-rebuild-obsolete"
        ),
    )
    setup_factory(
        setup_name="rebuild-warning",
        script_content=(
            "printf 'warning-partial\\n' > /etc/zaigr-rebuild-warning\n"
            "exit 31"
        ),
    )

    run(
        f"{zaigr} project setup run rebuild-current",
        input="y\n",
        timeout=180,
    )
    stdout, stderr, rc = _run(
        f"{zaigr} project setup run rebuild-warning",
        cwd=project.cwd,
        env=project.env,
        timeout=120,
    )
    assert rc != 0, err_msg(stdout, stderr)
    run(f"{zaigr} project vm stop", timeout=60)

    before = run(f"{zaigr} project setup list --applied", timeout=10)
    old_entry = _setup_entry(before, "rebuild-current")
    old_version = json.loads(
        (project.store_dir / "applied-setups.json").read_text(encoding="utf-8")
    )[0]["version"]
    setup_factory(
        setup_name="rebuild-current",
        script_content="printf 'v2\\n' > /etc/zaigr-rebuild-current",
    )
    (project.store_dir / "base-image-version").write_text(
        "previous-rebuild-base\n", encoding="utf-8"
    )

    rebuilt = run(
        f"{zaigr} project rebuild",
        timeout=240,
    )
    assert "The following setups will be applied with a newer version:" in rebuilt
    assert "rebuild-current" in rebuilt

    after = run(f"{zaigr} project setup list --applied", timeout=10)
    assert "applied (1):" in after
    assert _setup_entry(after, "rebuild-current") != old_entry
    new_version = json.loads(
        (project.store_dir / "applied-setups.json").read_text(encoding="utf-8")
    )[0]["version"]
    assert old_version != new_version
    assert old_version in rebuilt
    assert new_version in rebuilt
    assert (project.store_dir / "base-image-version").read_text(
        encoding="utf-8"
    ).strip() == current_base_version
    status = run(f"{zaigr} project status", timeout=10)
    assert "status: not running" in status
    assert status.count(FAILURE_NOTE) == 1

    rebuilt_image = _project_image(project)
    info_text, stderr, rc = _run(
        ["qemu-img", "info", "--output=json", rebuilt_image],
        cwd=project.cwd,
        env=project.env,
        timeout=30,
    )
    assert rc == 0, err_msg(info_text, stderr)
    rebuilt_info = json.loads(info_text)
    shared_base = Path(rebuilt_info["full-backing-filename"]).resolve()
    assert shared_base.name == "base.qcow2"
    base_info_text, stderr, rc = _run(
        ["qemu-img", "info", "--output=json", shared_base],
        cwd=project.cwd,
        env=project.env,
        timeout=30,
    )
    assert rc == 0, err_msg(base_info_text, stderr)
    assert "backing-filename" not in json.loads(base_info_text)
    assert len(list(project.store_dir.glob("*.qcow2"))) == 1
    assert not (project.store_dir / ".project.qcow2.transaction-old").exists()
    assert not list(project.store_dir.glob("*.wip"))

    run(f"{zaigr} project vm start", timeout=180)
    current = run(
        f"{zaigr} project vm exec -- cat /etc/zaigr-rebuild-current",
        timeout=20,
    )
    assert current.strip() == "v2"
    run(
        f"{zaigr} project vm exec -- "
        "test ! -e /etc/zaigr-rebuild-obsolete "
        "-a ! -e /etc/zaigr-rebuild-warning",
        timeout=20,
    )
    run(f"{zaigr} project vm stop", timeout=60)

    superseded_image = _project_image(project)
    with superseded_image.open("rb") as superseded_handle:
        superseded_stat = os.fstat(superseded_handle.fileno())
        (project.store_dir / "base-image-version").write_text(
            "previous-clean-base\n", encoding="utf-8"
        )
        run(f"{zaigr} project clean", timeout=180)
        status = run(f"{zaigr} project status", timeout=10)
        assert "applied (0):" in status
        assert FAILURE_NOTE not in status
        assert (project.store_dir / "base-image-version").read_text(
            encoding="utf-8"
        ).strip() == current_base_version

        clean_image = _project_image(project)
        assert clean_image.stat().st_ino != superseded_stat.st_ino
        superseded_links = [
            path
            for path in project.store_dir.rglob("*")
            if path.is_file()
            and path.stat().st_dev == superseded_stat.st_dev
            and path.stat().st_ino == superseded_stat.st_ino
        ]
        assert not superseded_links, superseded_links
    info_text, stderr, rc = _run(
        ["qemu-img", "info", "--output=json", clean_image],
        cwd=project.cwd,
        env=project.env,
        timeout=30,
    )
    assert rc == 0, err_msg(info_text, stderr)
    clean_info = json.loads(info_text)
    assert Path(clean_info["full-backing-filename"]).resolve() == shared_base
    assert len(list(project.store_dir.glob("*.qcow2"))) == 1
    assert not (project.store_dir / ".project.qcow2.transaction-old").exists()
    assert not list(project.store_dir.glob("*.wip"))

    run(f"{zaigr} project vm start", timeout=180)
    run(
        f"{zaigr} project vm exec -- test ! -e /etc/zaigr-rebuild-current",
        timeout=20,
    )


@pytest.mark.timeout(480)
def test_new_setup_firewall_rules_accumulate_directly_but_rebuild_uses_current_rules(
    project, setup_factory
):
    """Direct updates retain old access; rebuild retains only the current definition."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    setup_factory(
        setup_name="firewall-version",
        script_content="printf 'firewall-v1\\n'",
        firewall=["pypi.org"],
    )

    run(
        f"{zaigr} project setup run firewall-version",
        input="y\n",
        timeout=180,
    )
    run(f"{zaigr} project vm start", timeout=180)
    run(
        f"{zaigr} project vm exec -- curl -4 -fsS -o /dev/null "
        "--connect-timeout 5 --max-time 10 https://pypi.org",
        timeout=30,
    )

    setup_factory(
        setup_name="firewall-version",
        script_content="printf 'firewall-v2\\n'",
        firewall=["github.com"],
    )
    run(
        f"{zaigr} project setup run firewall-version",
        timeout=120,
    )
    run(
        f"{zaigr} project vm exec -- curl -4 -fsS -o /dev/null "
        "--connect-timeout 5 --max-time 10 https://pypi.org",
        timeout=30,
    )
    run(
        f"{zaigr} project vm exec -- curl -4 -fsS -o /dev/null "
        "--connect-timeout 5 --max-time 10 https://github.com",
        timeout=30,
    )

    run(f"{zaigr} project vm stop", timeout=60)
    run(f"{zaigr} project rebuild", timeout=240)
    run(f"{zaigr} project vm start", timeout=180)
    run(
        f"{zaigr} project vm exec -- curl -4 -fsS -o /dev/null "
        "--connect-timeout 5 --max-time 10 https://github.com",
        timeout=30,
    )

    stdout, stderr, rc = _run(
        f"{zaigr} project vm exec -- curl -4 -fsS -o /dev/null "
        "--connect-timeout 3 --max-time 5 https://pypi.org",
        cwd=project.cwd,
        env=project.env,
        timeout=20,
    )
    assert rc == 28, err_msg(stdout, stderr)


@pytest.mark.timeout(600)
def test_failed_rebuild_abort_is_transactional_and_remove_restarts_clean(
    project, setup_factory
):
    """A failed setup stops replay and leaves every authoritative input unchanged."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    mode = project.cwd / "rebuild-failure-mode"
    mode.write_text("succeed\n", encoding="utf-8")
    later_mode = project.cwd / "rebuild-later-mode"
    later_mode.write_text("initial\n", encoding="utf-8")
    later_ran = project.cwd / "rebuild-later-ran"
    setup_factory(
        setup_name="rebuild-10-failure",
        script_content=(
            "printf 'original\\n' > /etc/zaigr-rebuild-failure\n"
            "failure_mode=$(cat /home/user/workspace/rebuild-failure-mode)\n"
            "if [ \"$failure_mode\" = fail ]; then\n"
            "  printf 'candidate-corruption\\n' > "
            "/home/user/.zaigr-agent-state/rebuild-transaction/credential.txt\n"
            "fi\n"
            "test \"$failure_mode\" = succeed"
        ),
        firewall=["pypi.org"],
    )
    setup_factory(
        setup_name="rebuild-20-later",
        script_content=(
            "mode=$(cat /home/user/workspace/rebuild-later-mode)\n"
            "printf '%s\\n' \"$mode\" > /etc/zaigr-rebuild-later\n"
            "if [ \"$mode\" = rebuild ]; then\n"
            "  printf 'later-ran\\n' > /home/user/workspace/rebuild-later-ran\n"
            "fi"
        ),
        firewall=["github.com"],
    )

    run(
        f"{zaigr} project setup run rebuild-10-failure rebuild-20-later",
        input="y\n",
        timeout=180,
    )
    run(
        f"{zaigr} project vm exec -- curl -4 -fsS -o /dev/null "
        "--connect-timeout 5 --max-time 10 https://pypi.org",
        timeout=30,
    )
    run(
        f"{zaigr} project vm exec -- curl -4 -fsS -o /dev/null "
        "--connect-timeout 5 --max-time 10 https://github.com",
        timeout=30,
    )
    run(
        f"{zaigr} project vm exec -- mkdir -p "
        "/home/user/.zaigr-agent-state/rebuild-transaction",
        timeout=20,
    )
    run(
        f"{zaigr} project vm exec -- tee "
        "/home/user/.zaigr-agent-state/rebuild-transaction/credential.txt",
        input="original-agent-state\n",
        timeout=20,
    )
    run(f"{zaigr} project vm stop", timeout=60)
    original_image = _project_image(project)
    original_stat = original_image.stat()
    original_digest = _file_digest(original_image)
    recorded_base = (project.store_dir / "base-image-version").read_bytes()
    agent_state_snapshot = _tree_snapshot(project.store_dir / "agent-state")
    mode.write_text("fail\n", encoding="utf-8")
    later_mode.write_text("rebuild\n", encoding="utf-8")

    stdout, stderr, rc = _run(
        f"{zaigr} project rebuild",
        cwd=project.cwd,
        env=project.env,
        input="a\n",
        timeout=240,
    )
    combined = stdout + stderr
    assert rc != 0, err_msg(stdout, stderr)
    assert "rebuild-10-failure" in combined
    assert "abort" in combined.lower()
    assert "remove" in combined.lower()
    after_abort = _project_image(project).stat()
    assert after_abort.st_ino == original_stat.st_ino
    assert after_abort.st_size == original_stat.st_size
    assert after_abort.st_mtime_ns == original_stat.st_mtime_ns
    assert _file_digest(_project_image(project)) == original_digest
    assert (project.store_dir / "base-image-version").read_bytes() == recorded_base
    assert _tree_snapshot(project.store_dir / "agent-state") == agent_state_snapshot
    assert not later_ran.exists()
    assert not list(project.store_dir.glob("*wip*"))

    applied = run(f"{zaigr} project setup list --applied", timeout=10)
    assert "applied (2):" in applied
    assert "rebuild-10-failure" in applied
    assert "rebuild-20-later" in applied
    status = run(f"{zaigr} project status", timeout=10)
    assert FAILURE_NOTE not in status

    run(f"{zaigr} project vm start", timeout=180)
    original = run(
        f"{zaigr} project vm exec -- cat /etc/zaigr-rebuild-failure",
        timeout=20,
    )
    assert original.strip() == "original"
    later = run(
        f"{zaigr} project vm exec -- cat /etc/zaigr-rebuild-later",
        timeout=20,
    )
    assert later.strip() == "initial"
    run(
        f"{zaigr} project vm exec -- curl -4 -fsS -o /dev/null "
        "--connect-timeout 5 --max-time 10 https://pypi.org",
        timeout=30,
    )
    run(
        f"{zaigr} project vm exec -- curl -4 -fsS -o /dev/null "
        "--connect-timeout 5 --max-time 10 https://github.com",
        timeout=30,
    )
    run(f"{zaigr} project vm stop", timeout=60)

    rebuilt = run(
        f"{zaigr} project rebuild",
        input="r\n",
        timeout=240,
    )
    assert "rebuild-10-failure" in rebuilt
    assert _project_image(project).stat().st_ino != original_stat.st_ino
    assert len(list(project.store_dir.glob("*.qcow2"))) == 1
    assert later_ran.read_text(encoding="utf-8") == "later-ran\n"
    assert _tree_snapshot(project.store_dir / "agent-state") == agent_state_snapshot

    applied = run(f"{zaigr} project setup list --applied", timeout=10)
    assert "applied (1):" in applied
    assert "rebuild-10-failure" not in applied
    assert "rebuild-20-later" in applied
    run(f"{zaigr} project vm start", timeout=180)
    run(
        f"{zaigr} project vm exec -- test ! -e /etc/zaigr-rebuild-failure",
        timeout=20,
    )
    later = run(
        f"{zaigr} project vm exec -- cat /etc/zaigr-rebuild-later",
        timeout=20,
    )
    assert later.strip() == "rebuild"


@pytest.mark.timeout(720)
def test_rebuild_missing_definitions_lists_all_and_commits_removal_only_on_success(
    project, setup_factory
):
    """Missing setup preflight can abort unchanged or remove all missing names."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    survivor_mode = project.cwd / "missing-survivor-mode"
    survivor_mode.write_text("succeed\n", encoding="utf-8")
    for name in ("missing-alpha", "missing-beta"):
        setup_factory(
            setup_name=name,
            script_content=f"printf '{name}\\n' > /etc/zaigr-{name}",
        )
    setup_factory(
        setup_name="missing-survivor",
        script_content=(
            "printf 'survivor-ran\\n' > /etc/zaigr-missing-survivor\n"
            "test \"$(cat /home/user/workspace/missing-survivor-mode)\" = succeed"
        ),
    )

    run(
        f"{zaigr} project setup run missing-alpha missing-beta missing-survivor",
        input="y\n",
        timeout=300,
    )
    run(f"{zaigr} project vm stop", timeout=60)
    original_image = _project_image(project)
    original_inode = original_image.stat().st_ino
    survivor_mode.write_text("fail\n", encoding="utf-8")
    for name in ("missing-alpha", "missing-beta"):
        setup_dir = project.home / ".zaigr" / "setups" / name
        for path in setup_dir.iterdir():
            path.unlink()
        setup_dir.rmdir()

    stdout, stderr, rc = _run(
        f"{zaigr} project rebuild",
        cwd=project.cwd,
        env=project.env,
        input="a\n",
        timeout=60,
    )
    combined = stdout + stderr
    assert rc != 0, err_msg(stdout, stderr)
    assert "missing-alpha" in combined
    assert "missing-beta" in combined
    assert _project_image(project).stat().st_ino == original_inode

    applied = run(f"{zaigr} project setup list --applied", timeout=10)
    assert "applied (3):" in applied
    assert "missing-alpha" in applied
    assert "missing-beta" in applied
    assert "missing-survivor" in applied
    status = run(f"{zaigr} project status", timeout=10)
    assert FAILURE_NOTE not in status

    stdout, stderr, rc = _run(
        f"{zaigr} project rebuild",
        cwd=project.cwd,
        env=project.env,
        input="r\na\n",
        timeout=240,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert "missing-survivor" in stdout + stderr
    assert _project_image(project).stat().st_ino == original_inode

    applied = run(f"{zaigr} project setup list --applied", timeout=10)
    assert "applied (3):" in applied
    assert "missing-alpha" in applied
    assert "missing-beta" in applied
    assert "missing-survivor" in applied
    status = run(f"{zaigr} project status", timeout=10)
    assert FAILURE_NOTE not in status

    survivor_mode.write_text("succeed\n", encoding="utf-8")
    run(f"{zaigr} project rebuild", input="r\n", timeout=240)
    applied = run(f"{zaigr} project setup list --applied", timeout=10)
    assert "applied (1):" in applied
    assert "missing-alpha" not in applied
    assert "missing-beta" not in applied
    assert "missing-survivor" in applied
    assert _project_image(project).stat().st_ino != original_inode


@pytest.mark.timeout(420)
def test_failed_clean_rolls_back_image_metadata_permissions_and_guest_state(
    project, setup_factory
):
    """A metadata publication error restores the complete current project state."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    setup_factory(
        setup_name="clean-rollback",
        script_content="printf 'preserved\\n' > /etc/zaigr-clean-rollback",
    )

    run(
        f"{zaigr} project setup run clean-rollback",
        input="y\n",
        timeout=180,
    )
    run(f"{zaigr} project vm stop", timeout=60)

    image = _project_image(project)
    original_stat = image.stat()
    original_digest = _file_digest(image)
    base_version = project.store_dir / "base-image-version"
    base_version.chmod(0o444)
    before = _tree_snapshot(project.store_dir)

    stdout, stderr, rc = _run(
        f"{zaigr} project clean",
        cwd=project.cwd,
        env=project.env,
        timeout=180,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert "clean project transaction" in (stdout + stderr).lower()
    assert "permission denied" in (stdout + stderr).lower()

    rolled_back = _project_image(project)
    assert rolled_back.stat().st_ino == original_stat.st_ino
    assert rolled_back.stat().st_size == original_stat.st_size
    assert _file_digest(rolled_back) == original_digest
    assert _tree_snapshot(project.store_dir) == before
    assert not (project.store_dir / ".project.qcow2.transaction-old").exists()
    assert not list(project.store_dir.glob("*.wip"))

    base_version.chmod(0o644)
    status = run(f"{zaigr} project status", timeout=10)
    assert "applied (1):" in status
    assert "clean-rollback" in status
    run(f"{zaigr} project vm start", timeout=180)
    marker = run(
        f"{zaigr} project vm exec -- cat /etc/zaigr-clean-rollback",
        timeout=20,
    )
    assert marker.strip() == "preserved"


@pytest.mark.timeout(480)
def test_outdated_base_image_is_reported_and_rebuilt_from_applied_state(
    project, setup_factory
):
    """An older recorded base blocks boot and points to the recoverable rebuild."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    setup_factory(
        setup_name="outdated-base-image",
        script_content="printf 'rebuilt\n' > /etc/zaigr-outdated-base-image",
    )

    run(
        f"{zaigr} project setup run outdated-base-image",
        input="y\n",
        timeout=180,
    )

    base_version_path = project.store_dir / "base-image-version"
    required_base = base_version_path.read_text(encoding="utf-8").strip()
    # This has the same shape as metadata written by a previous Zaigr binary.
    previous_base = required_base[:-1] + ("0" if required_base[-1] != "0" else "1")
    base_version_path.write_text(f"{previous_base}\n", encoding="utf-8")

    status = run(f"{zaigr} project status", timeout=10)
    assert "warning: the project base image is outdated." in status
    assert f"project base image: {previous_base}" in status
    assert f"required base image: {required_base}" in status
    assert "Stop the project VM if it is running" in status
    assert "zaigr project rebuild" in status

    stdout, stderr, rc = _run(
        f"{zaigr} project vm start",
        cwd=project.cwd,
        env=project.env,
        timeout=30,
    )
    assert rc != 0, err_msg(stdout, stderr)
    combined = stdout + stderr
    assert "project base image is outdated" in combined
    assert f"project base image: {previous_base}" in combined
    assert f"required base image: {required_base}" in combined
    assert "Stop the project VM if it is running" in combined
    assert "zaigr project rebuild" in combined

    stdout, stderr, rc = _run(
        f"{zaigr} project vm exec -- true",
        cwd=project.cwd,
        env=project.env,
        timeout=10,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert "project base image is outdated" in (stdout + stderr)
    assert "zaigr project rebuild" in (stdout + stderr)

    stdout, stderr, rc = _run(
        f"{zaigr} project setup capture start",
        cwd=project.cwd,
        env=project.env,
        timeout=10,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert "project base image is outdated" in (stdout + stderr)
    assert "zaigr project rebuild" in (stdout + stderr)

    stdout, stderr, rc = _run(
        f"{zaigr} project setup run outdated-base-image",
        cwd=project.cwd,
        env=project.env,
        timeout=30,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert "project base image is outdated" in (stdout + stderr)
    assert "zaigr project rebuild" in (stdout + stderr)

    run(f"{zaigr} project vm stop", timeout=60)
    stdout, stderr, rc = _run(
        f"{zaigr} project vm start",
        cwd=project.cwd,
        env=project.env,
        timeout=30,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert "project base image is outdated" in (stdout + stderr)
    assert "zaigr project rebuild" in (stdout + stderr)

    run(f"{zaigr} project rebuild", timeout=240)
    assert base_version_path.read_text(encoding="utf-8").strip() == required_base
    run(f"{zaigr} project vm start", timeout=180)
    marker = run(
        f"{zaigr} project vm exec -- cat /etc/zaigr-outdated-base-image",
        timeout=20,
    )
    assert marker.strip() == "rebuilt"


@pytest.mark.timeout(420)
def test_missing_current_project_image_is_reported_and_rebuilt_from_applied_state(
    project, setup_factory
):
    """A missing authoritative image is explicit and recoverable by rebuild."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    setup_factory(
        setup_name="missing-current-image",
        script_content="printf 'rebuilt\\n' > /etc/zaigr-missing-current-image",
    )

    run(
        f"{zaigr} project setup run missing-current-image",
        input="y\n",
        timeout=180,
    )
    run(f"{zaigr} project vm stop", timeout=60)
    _project_image(project).unlink()

    status = run(f"{zaigr} project status", timeout=10)
    assert "warning: the project image cannot be found." in status
    assert "expected image: project.qcow2" in status
    assert "rebuild" in status.lower()

    stdout, stderr, rc = _run(
        f"{zaigr} project vm start",
        cwd=project.cwd,
        env=project.env,
        timeout=30,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert "project image cannot be found" in (stdout + stderr).lower()

    run(f"{zaigr} project rebuild", timeout=240)
    recovered_image = _project_image(project)
    info_text, stderr, rc = _run(
        ["qemu-img", "info", "--output=json", recovered_image],
        cwd=project.cwd,
        env=project.env,
        timeout=30,
    )
    assert rc == 0, err_msg(info_text, stderr)
    assert Path(json.loads(info_text)["full-backing-filename"]).name == "base.qcow2"
    assert not (project.store_dir / ".project.qcow2.transaction-old").exists()

    run(f"{zaigr} project vm start", timeout=180)
    marker = run(
        f"{zaigr} project vm exec -- cat /etc/zaigr-missing-current-image",
        timeout=20,
    )
    assert marker.strip() == "rebuilt"


@pytest.mark.timeout(480)
def test_root_exec_marks_image_dirty_and_rebuild_requires_explicit_force(
    project, setup_factory
):
    """Root exec dirtiness blocks rebuild until force discards ad-hoc changes."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    setup_factory(
        setup_name="dirty-rebuild",
        script_content="printf 'from-setup\\n' > /etc/zaigr-dirty-rebuild-setup",
    )

    run(
        f"{zaigr} project setup run dirty-rebuild",
        input="y\n",
        timeout=180,
    )
    status = run(f"{zaigr} project status", timeout=10)
    assert "project-image-dirty:" not in status

    root_exec = run(
        [
            zaigr,
            "project",
            "vm",
            "exec",
            "--root",
            "--",
            "tee",
            "/etc/zaigr-root-exec-dirty",
        ],
        input="y\nad-hoc-root-write\n",
        timeout=30,
    )
    assert "ad-hoc-root-write" in root_exec
    run(
        f"{zaigr} project vm exec --root -- sync",
        input="y\n",
        timeout=30,
    )
    status = run(f"{zaigr} project status", timeout=10)
    assert "project-image-dirty: yes (root-exec," in status

    run(f"{zaigr} project vm stop", timeout=60)
    original_image = _project_image(project)
    original_stat = original_image.stat()
    stdout, stderr, rc = _run(
        f"{zaigr} project rebuild",
        cwd=project.cwd,
        env=project.env,
        timeout=30,
    )
    assert rc != 0, err_msg(stdout, stderr)
    combined = stdout + stderr
    assert "has changes made with zaigr project vm exec --root" in combined
    assert "Zaigr cannot recover these changes or determine what they are." in combined
    assert "A rebuild will not include them." in combined
    assert "Rerun with --force to rebuild" in combined
    assert "unsaved changes" not in combined
    assert _project_image(project).stat().st_ino == original_stat.st_ino

    run(f"{zaigr} project vm start", timeout=180)
    ad_hoc = run(
        f"{zaigr} project vm exec -- cat /etc/zaigr-root-exec-dirty",
        timeout=20,
    )
    assert ad_hoc.strip() == "ad-hoc-root-write"
    run(f"{zaigr} project vm stop", timeout=60)

    run(f"{zaigr} project rebuild --force", timeout=240)
    assert _project_image(project).stat().st_ino != original_stat.st_ino
    status = run(f"{zaigr} project status", timeout=10)
    assert "project-image-dirty:" not in status
    assert "applied (1):" in status

    run(f"{zaigr} project vm start", timeout=180)
    setup_effect = run(
        f"{zaigr} project vm exec -- cat /etc/zaigr-dirty-rebuild-setup",
        timeout=20,
    )
    assert setup_effect.strip() == "from-setup"
    run(
        f"{zaigr} project vm exec -- test ! -e /etc/zaigr-root-exec-dirty",
        timeout=20,
    )


@pytest.mark.timeout(300)
def test_project_overlay_smaller_than_default_has_requested_size_and_boots(
    project_factory,
):
    """A configured 8G project remains a bootable direct overlay."""
    project = project_factory("topology-small")
    env = project.env
    env["ZAIGR_DISK_SIZE"] = "8G"

    stdout, stderr, rc = _run(
        f"{project.zaigr_bin} project vm start",
        cwd=project.cwd,
        env=env,
        input="y\n",
        timeout=180,
    )
    assert rc == 0, err_msg(stdout, stderr)
    stdout, stderr, rc = _run(
        f"{project.zaigr_bin} project vm exec -- test -d /etc",
        cwd=project.cwd,
        env=env,
        timeout=20,
    )
    assert rc == 0, err_msg(stdout, stderr)
    stdout, stderr, rc = _run(
        f"{project.zaigr_bin} project vm stop",
        cwd=project.cwd,
        env=env,
        timeout=60,
    )
    assert rc == 0, err_msg(stdout, stderr)

    image = _project_image(project)
    info_text, stderr, rc = _run(
        ["qemu-img", "info", "--output=json", image],
        cwd=project.cwd,
        env=env,
        timeout=30,
    )
    assert rc == 0, err_msg(info_text, stderr)
    info = json.loads(info_text)
    assert info["virtual-size"] == 8 * 1024**3
    assert Path(info["full-backing-filename"]).name == "base.qcow2"


@pytest.mark.timeout(480)
def test_projects_share_immutable_sized_bases_and_keep_writes_project_local(
    project_factory, setup_factory
):
    """Project overlays use reusable sized bases while writes remain project-local."""
    project_a = project_factory("topology-alpha")
    project_b = project_factory("topology-beta")
    env_a = project_a.env
    env_b = project_b.env
    env_a["ZAIGR_DISK_SIZE"] = "100G"
    env_b["ZAIGR_DISK_SIZE"] = "120G"

    stdout, stderr, rc = _run(
        f"{project_a.zaigr_bin} project vm start",
        cwd=project_a.cwd,
        env=env_a,
        input="y\n",
        timeout=180,
    )
    assert rc == 0, err_msg(stdout, stderr)
    stdout, stderr, rc = _run(
        f"{project_a.zaigr_bin} project vm stop",
        cwd=project_a.cwd,
        env=env_a,
        timeout=60,
    )
    assert rc == 0, err_msg(stdout, stderr)

    image_a = _project_image(project_a)
    info_text, stderr, rc = _run(
        ["qemu-img", "info", "--output=json", image_a],
        cwd=project_a.cwd,
        env=env_a,
        timeout=30,
    )
    assert rc == 0, err_msg(info_text, stderr)
    info_a = json.loads(info_text)
    base_a = Path(info_a["full-backing-filename"]).resolve()
    assert info_a["format"] == "qcow2"
    assert info_a["virtual-size"] == 100 * 1024**3
    assert base_a.is_file()

    base_info_text, stderr, rc = _run(
        ["qemu-img", "info", "--output=json", base_a],
        cwd=project_a.cwd,
        env=env_a,
        timeout=30,
    )
    assert rc == 0, err_msg(base_info_text, stderr)
    base_info = json.loads(base_info_text)
    assert "backing-filename" not in base_info
    base_digest = _file_digest(base_a)

    stdout, stderr, rc = _run(
        f"{project_b.zaigr_bin} project vm start",
        cwd=project_b.cwd,
        env=env_b,
        input="y\n",
        timeout=180,
    )
    assert rc == 0, err_msg(stdout, stderr)
    stdout, stderr, rc = _run(
        f"{project_b.zaigr_bin} project vm stop",
        cwd=project_b.cwd,
        env=env_b,
        timeout=60,
    )
    assert rc == 0, err_msg(stdout, stderr)

    image_b = _project_image(project_b)
    info_text, stderr, rc = _run(
        ["qemu-img", "info", "--output=json", image_b],
        cwd=project_b.cwd,
        env=env_b,
        timeout=30,
    )
    assert rc == 0, err_msg(info_text, stderr)
    info_b = json.loads(info_text)
    base_b = Path(info_b["full-backing-filename"]).resolve()
    assert info_b["virtual-size"] == 120 * 1024**3
    assert base_b != base_a
    base_b_info_text, stderr, rc = _run(
        ["qemu-img", "info", "--output=json", base_b],
        cwd=project_b.cwd,
        env=env_b,
        timeout=30,
    )
    assert rc == 0, err_msg(base_b_info_text, stderr)
    base_b_info = json.loads(base_b_info_text)
    assert base_b_info["virtual-size"] == 120 * 1024**3
    assert "backing-filename" not in base_b_info
    assert _file_digest(base_a) == base_digest

    setup_factory(
        setup_name="topology-isolation",
        script_content="printf 'alpha-only\\n' > /etc/zaigr-topology-isolation",
    )
    stdout, stderr, rc = _run(
        f"{project_a.zaigr_bin} project setup run topology-isolation",
        cwd=project_a.cwd,
        env=env_a,
        timeout=180,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert _file_digest(base_a) == base_digest

    image_a_after_setup = _project_image(project_a)
    info_text, stderr, rc = _run(
        ["qemu-img", "info", "--output=json", image_a_after_setup],
        cwd=project_a.cwd,
        env=env_a,
        timeout=30,
    )
    assert rc == 0, err_msg(info_text, stderr)
    info_a_after_setup = json.loads(info_text)
    assert Path(info_a_after_setup["full-backing-filename"]).resolve() == base_a
    assert info_a_after_setup["backing-filename"] != str(image_a)
    assert info_a_after_setup["backing-filename"] != str(image_b)

    stdout, stderr, rc = _run(
        f"{project_b.zaigr_bin} project vm start",
        cwd=project_b.cwd,
        env=env_b,
        timeout=180,
    )
    assert rc == 0, err_msg(stdout, stderr)
    stdout, stderr, rc = _run(
        f"{project_b.zaigr_bin} project vm exec -- "
        "test ! -e /etc/zaigr-topology-isolation",
        cwd=project_b.cwd,
        env=env_b,
        timeout=20,
    )
    assert rc == 0, err_msg(stdout, stderr)

    assert len(list(project_a.store_dir.glob("*.qcow2"))) == 1
    assert len(list(project_b.store_dir.glob("*.qcow2"))) == 1
    assert info_a["full-backing-filename"] != str(image_b)
    assert info_b["full-backing-filename"] != str(image_a)


@pytest.mark.timeout(420)
def test_legacy_store_can_be_rebuilt_or_explicitly_cleaned_or_deleted(
    project_factory, setup_factory
):
    """Rebuild migrates recoverable state without booting the legacy image."""
    legacy_clean = project_factory("legacy-clean")
    store = legacy_clean.store_dir
    store.mkdir(parents=True)
    # These files reproduce the standalone-image and awaiting-state store layout.
    (store / "project-path").write_text(f"{legacy_clean.cwd}\n", encoding="utf-8")
    (store / "config").write_text("disk=100G\n", encoding="utf-8")
    (store / "base-image-version").write_text("legacy-base\n", encoding="utf-8")
    (store / "setup-failed-once").write_text("1\n", encoding="utf-8")
    setup_factory(
        setup_name="legacy-first",
        script_content="printf 'first\\n' > /etc/zaigr-legacy-first",
    )
    setup_factory(
        setup_name="legacy-second",
        script_content=(
            "test \"$(cat /etc/zaigr-legacy-first)\" = first\n"
            "printf 'rebuilt\\n' > /etc/zaigr-legacy-rebuild"
        ),
    )
    committed = store / "committed"
    committed.mkdir()
    (committed / "001-legacy-first.sh").write_text(
        "printf 'previous first payload\\n'",
        encoding="utf-8",
    )
    (committed / "002-legacy-second.sh").write_text(
        "printf 'previous second payload\\n'",
        encoding="utf-8",
    )
    awaiting = store / "awaiting-commit"
    awaiting.mkdir()
    (awaiting / "001-legacy.sh").write_text("printf legacy\n", encoding="utf-8")
    agent_state = store / "agent-state"
    preset_state = agent_state / "legacy-preset" / "nested"
    preset_state.mkdir(parents=True)
    (preset_state / "credentials.json").write_text(
        '{"token":"legacy-secret"}\n',
        encoding="utf-8",
    )
    (agent_state / "legacy-preset" / ".hidden-state").write_text(
        "hidden legacy state\n",
        encoding="utf-8",
    )
    (agent_state / "legacy-preset" / "credentials-link").symlink_to(
        "nested/credentials.json"
    )
    agent_state_snapshot = _tree_snapshot(agent_state)
    legacy_image = store / "image-legacy.qcow2"
    stdout, stderr, rc = _run(
        ["qemu-img", "create", "-f", "qcow2", legacy_image, "1G"],
        cwd=legacy_clean.cwd,
        env=legacy_clean.env,
        timeout=30,
    )
    assert rc == 0, err_msg(stdout, stderr)
    legacy_snapshot = _tree_snapshot(store)

    for args in (
        "project status",
        "project setup list",
        "project setup run legacy-setup",
        "project vm start",
    ):
        stdout, stderr, rc = _run(
            f"{legacy_clean.zaigr_bin} {args}",
            cwd=legacy_clean.cwd,
            env=legacy_clean.env,
            timeout=30,
        )
        assert rc != 0, err_msg(stdout, stderr)
        assert "legacy" in (stdout + stderr).lower() or "incompatible" in (
            stdout + stderr
        ).lower()
        assert "initialize project" not in (stdout + stderr).lower()
        assert _tree_snapshot(store) == legacy_snapshot

    rebuilt = _checked_run(
        f"{legacy_clean.zaigr_bin} project rebuild",
        cwd=legacy_clean.cwd,
        env=legacy_clean.env,
        timeout=240,
    )
    assert "Replaced incompatible legacy project store" in rebuilt
    assert not legacy_image.exists()
    assert not awaiting.exists()
    assert (store / "image-format").read_text(encoding="utf-8").strip() == "direct-base-v1"
    assert (store / "setup-failed-once").read_text(encoding="utf-8") == "1\n"
    assert _tree_snapshot(agent_state) == agent_state_snapshot

    _checked_run(
        f"{legacy_clean.zaigr_bin} project vm start",
        cwd=legacy_clean.cwd,
        env=legacy_clean.env,
        timeout=180,
    )
    rebuilt_marker = _checked_run(
        f"{legacy_clean.zaigr_bin} project vm exec -- cat /etc/zaigr-legacy-rebuild",
        cwd=legacy_clean.cwd,
        env=legacy_clean.env,
        timeout=20,
    )
    assert rebuilt_marker.strip() == "rebuilt"
    preserved_state = _checked_run(
        f"{legacy_clean.zaigr_bin} project vm exec -- cat "
        "/home/user/.zaigr-agent-state/legacy-preset/credentials-link",
        cwd=legacy_clean.cwd,
        env=legacy_clean.env,
        timeout=20,
    )
    assert preserved_state == '{"token":"legacy-secret"}\n'
    legacy_clean = project_factory("legacy-clean-only")
    store = legacy_clean.store_dir
    store.mkdir(parents=True)
    (store / "project-path").write_text(f"{legacy_clean.cwd}\n", encoding="utf-8")
    (store / "config").write_text("disk=100G\n", encoding="utf-8")
    legacy_image = store / "image-legacy.qcow2"
    stdout, stderr, rc = _run(
        ["qemu-img", "create", "-f", "qcow2", legacy_image, "1G"],
        cwd=legacy_clean.cwd,
        env=legacy_clean.env,
        timeout=30,
    )
    assert rc == 0, err_msg(stdout, stderr)

    clean_only_snapshot = _tree_snapshot(store)
    stdout, stderr, rc = _run(
        f"{legacy_clean.zaigr_bin} project rebuild",
        cwd=legacy_clean.cwd,
        env=legacy_clean.env,
        timeout=30,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert "no recoverable applied setups" in stdout + stderr
    assert _tree_snapshot(store) == clean_only_snapshot

    stdout, stderr, rc = _run(
        f"{legacy_clean.zaigr_bin} project clean",
        cwd=legacy_clean.cwd,
        env=legacy_clean.env,
        timeout=120,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert not legacy_image.exists()
    assert not awaiting.exists()
    clean_image = _project_image(legacy_clean)
    assert clean_image.name == "project.qcow2"
    assert len(list(store.glob("*.qcow2"))) == 1
    assert not (store / ".project.qcow2.transaction-old").exists()
    assert not list(store.glob("*.wip"))

    info_text, stderr, rc = _run(
        ["qemu-img", "info", "--output=json", clean_image],
        cwd=legacy_clean.cwd,
        env=legacy_clean.env,
        timeout=30,
    )
    assert rc == 0, err_msg(info_text, stderr)
    clean_info = json.loads(info_text)
    shared_base = Path(clean_info["full-backing-filename"]).resolve()
    assert shared_base.name == "base.qcow2"
    base_info_text, stderr, rc = _run(
        ["qemu-img", "info", "--output=json", shared_base],
        cwd=legacy_clean.cwd,
        env=legacy_clean.env,
        timeout=30,
    )
    assert rc == 0, err_msg(base_info_text, stderr)
    assert "backing-filename" not in json.loads(base_info_text)

    status = _checked_run(
        f"{legacy_clean.zaigr_bin} project status",
        cwd=legacy_clean.cwd,
        env=legacy_clean.env,
        timeout=10,
    )
    assert "applied (0):" in status

    _checked_run(
        f"{legacy_clean.zaigr_bin} project vm start",
        cwd=legacy_clean.cwd,
        env=legacy_clean.env,
        timeout=180,
    )
    _checked_run(
        f"{legacy_clean.zaigr_bin} project vm exec -- test -d /etc",
        cwd=legacy_clean.cwd,
        env=legacy_clean.env,
        timeout=20,
    )

    legacy_delete = project_factory("legacy-delete")
    delete_store = legacy_delete.store_dir
    delete_store.mkdir(parents=True)
    (delete_store / "project-path").write_text(
        f"{legacy_delete.cwd}\n", encoding="utf-8"
    )
    (delete_store / "image-old.img").write_text("legacy\n", encoding="utf-8")

    stdout, stderr, rc = _run(
        f"{legacy_delete.zaigr_bin} project delete --force",
        cwd=legacy_delete.cwd,
        env=legacy_delete.env,
        timeout=30,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert not delete_store.exists()
