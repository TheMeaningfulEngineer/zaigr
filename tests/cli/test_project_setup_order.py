"""CLI regressions for preserving applied setup order during rebuild."""

import json
import re

import pexpect
import pytest

from ..conftest import err_msg, spawn_interactive
from ..conftest import run as _run

ROOT_PROMPT = r"root@[^:]+:.*# "


def _checked_run(project, command, input=None, timeout=120):
    """Run a project command and assert that it succeeds."""
    stdout, stderr, rc = _run(
        f"{project.zaigr_bin} {command}",
        cwd=project.cwd,
        env=project.env,
        input=input,
        timeout=timeout,
    )
    assert rc == 0, err_msg(stdout, stderr)
    return stdout


def _write_prerequisite(project):
    """Write a local setup that provides the capture prerequisite."""
    setup_dir = project.cwd / ".zaigr" / "setups" / "zz-prerequisite"
    setup_dir.mkdir(parents=True, exist_ok=True)
    (setup_dir / "setup.script").write_text(
        r"""#!/bin/bash
set -eu
printf '#!/bin/sh\nprintf "order-ok\\n"\n' > /usr/local/bin/zaigr-order-probe
chmod 0755 /usr/local/bin/zaigr-order-probe
""",
        encoding="utf-8",
    )
    (setup_dir / "setup.firewall").write_text("", encoding="utf-8")


def _write_setup(project, name, script):
    """Write a local setup definition for a CLI acceptance scenario."""
    setup_dir = project.cwd / ".zaigr" / "setups" / name
    setup_dir.mkdir(parents=True, exist_ok=True)
    (setup_dir / "setup.script").write_text(script, encoding="utf-8")
    (setup_dir / "setup.firewall").write_text("", encoding="utf-8")


@pytest.mark.timeout(600)
def test_capture_rebuild_replays_after_its_prerequisite(project):
    """A captured setup must replay after the setup that provides its command."""
    _write_prerequisite(project)
    _checked_run(
        project,
        "project setup run zz-prerequisite",
        input="y\ny\n",
        timeout=180,
    )
    _checked_run(project, "project vm stop", timeout=60)

    capture = spawn_interactive(
        f"{project.zaigr_bin} project setup capture start",
        cwd=project.cwd,
        env=project.env,
        timeout=240,
    )
    try:
        capture.expect(ROOT_PROMPT, timeout=180)
        capture.sendline("zaigr-order-probe > /etc/zaigr-order-result")
        capture.expect(ROOT_PROMPT, timeout=60)
        capture.sendline("exit")
        capture.expect(pexpect.EOF, timeout=60)
    finally:
        if capture.isalive():
            capture.sendline("exit")
            capture.expect(pexpect.EOF, timeout=60)
        capture.close()

    review = _checked_run(project, "project setup capture review", timeout=30)
    assert "zaigr-order-probe > /etc/zaigr-order-result" in review

    accepted = _checked_run(
        project,
        "project setup capture accept",
        timeout=120,
    )
    assert "accepted setup capture" in accepted.lower()
    match = re.search(r"Updated setup definition: (.+)", accepted)
    assert match is not None
    recipe = project.cwd / match.group(1)
    assert "zaigr-order-probe > /etc/zaigr-order-result" in (
        recipe / "setup.script"
    ).read_text(encoding="utf-8")

    stdout, stderr, rc = _run(
        f"{project.zaigr_bin} project rebuild --force",
        cwd=project.cwd,
        env=project.env,
        input="a\n",
        timeout=360,
    )
    assert rc == 0, err_msg(stdout, stderr)

    _checked_run(project, "project vm start", input="y\n", timeout=180)
    result = _checked_run(
        project,
        "project vm exec -- cat /etc/zaigr-order-result",
        timeout=60,
    )
    assert result.strip() == "order-ok"

    _checked_run(project, "project vm stop", timeout=60)
    _checked_run(project, "project rebuild --force", input="a\n", timeout=360)
    _checked_run(project, "project vm start", timeout=180)
    result = _checked_run(
        project,
        "project vm exec -- cat /etc/zaigr-order-result",
        timeout=60,
    )
    assert result.strip() == "order-ok"


@pytest.mark.timeout(600)
def test_attached_capture_rebuilds_after_its_prerequisite(project):
    """A capture attached to a running VM retains its setup order on replay."""
    _write_prerequisite(project)
    _checked_run(
        project,
        "project setup run zz-prerequisite",
        input="y\ny\n",
        timeout=180,
    )

    capture = spawn_interactive(
        f"{project.zaigr_bin} project setup capture start",
        cwd=project.cwd,
        env=project.env,
        timeout=240,
    )
    try:
        capture.expect(r"A project VM is already running\.", timeout=60)
        capture.expect(r"Discarding the capture will not undo changes made in that VM\.")
        capture.expect(r"Continue\? \[y/N\]")
        capture.sendline("y")
        capture.expect(ROOT_PROMPT, timeout=60)
        capture.sendline("zaigr-order-probe > /etc/zaigr-order-result")
        capture.expect(ROOT_PROMPT, timeout=60)
        capture.sendline("exit")
        capture.expect(pexpect.EOF, timeout=60)
    finally:
        if capture.isalive():
            capture.sendline("exit")
            capture.expect(pexpect.EOF, timeout=60)
        capture.close()

    review = _checked_run(project, "project setup capture review", timeout=30)
    assert "zaigr-order-probe > /etc/zaigr-order-result" in review
    accepted = _checked_run(project, "project setup capture accept", timeout=120)
    assert "accepted setup capture" in accepted.lower()
    match = re.search(r"Updated setup definition: (.+)", accepted)
    assert match is not None
    recipe = project.cwd / match.group(1)
    assert "zaigr-order-probe > /etc/zaigr-order-result" in (
        recipe / "setup.script"
    ).read_text(encoding="utf-8")

    _checked_run(project, "project vm stop", timeout=60)
    _checked_run(project, "project rebuild --force", input="a\n", timeout=360)
    _checked_run(project, "project vm start", timeout=180)
    result = _checked_run(
        project,
        "project vm exec -- cat /etc/zaigr-order-result",
        timeout=60,
    )
    assert result.strip() == "order-ok"


@pytest.mark.timeout(600)
def test_global_rebuild_replays_capture_after_its_prerequisite(project):
    """Global project rebuild uses the persisted order of applied setups."""
    _write_prerequisite(project)
    _checked_run(
        project,
        "project setup run zz-prerequisite",
        input="y\ny\n",
        timeout=180,
    )
    _checked_run(project, "project vm stop", timeout=60)

    capture = spawn_interactive(
        f"{project.zaigr_bin} project setup capture start",
        cwd=project.cwd,
        env=project.env,
        timeout=240,
    )
    try:
        capture.expect(ROOT_PROMPT, timeout=180)
        capture.sendline("zaigr-order-probe > /etc/zaigr-order-result")
        capture.expect(ROOT_PROMPT, timeout=60)
        capture.sendline("exit")
        capture.expect(pexpect.EOF, timeout=60)
    finally:
        if capture.isalive():
            capture.sendline("exit")
            capture.expect(pexpect.EOF, timeout=60)
        capture.close()

    review = _checked_run(project, "project setup capture review", timeout=30)
    assert "zaigr-order-probe > /etc/zaigr-order-result" in review
    _checked_run(project, "project setup capture accept", timeout=120)

    stdout = _checked_run(
        project,
        f"global projects rebuild {project.cwd.name} --force --yes",
        timeout=360,
    )
    assert project.cwd.name in stdout
    assert "Rebuilt: 1" in stdout
    assert "Skipped: 0" in stdout
    _checked_run(project, "project vm start", timeout=180)
    result = _checked_run(
        project,
        "project vm exec -- cat /etc/zaigr-order-result",
        timeout=60,
    )
    assert result.strip() == "order-ok"


@pytest.mark.timeout(600)
def test_reverse_alphabetical_setups_replay_in_application_order(project):
    """Ordinary setups retain their application order regardless of names."""
    _write_prerequisite(project)
    _checked_run(
        project,
        "project setup run zz-prerequisite",
        input="y\ny\n",
        timeout=180,
    )
    _write_setup(
        project,
        "aa-consumer",
        "#!/bin/bash\nset -eu\nzaigr-order-probe > /etc/zaigr-consumer-result\n",
    )
    _checked_run(
        project,
        "project setup run aa-consumer",
        input="y\n",
        timeout=180,
    )
    _checked_run(
        project,
        "project setup run zz-prerequisite --force",
        input="y\n",
        timeout=180,
    )

    _checked_run(project, "project vm stop", timeout=60)
    _checked_run(project, "project rebuild --force", input="a\n", timeout=360)
    _checked_run(project, "project vm start", timeout=180)
    result = _checked_run(
        project,
        "project vm exec -- cat /etc/zaigr-consumer-result",
        timeout=60,
    )
    assert result.strip() == "order-ok"


@pytest.mark.timeout(600)
def test_same_name_global_and_local_setups_keep_both_scopes(project, setup_factory):
    """Rebuild replays global and local records with the same setup name."""
    setup_factory(
        setup_name="same-scope-order",
        script_content="printf 'global-result\\n' > /etc/zaigr-global-result",
        firewall="",
    )
    _checked_run(
        project,
        "project setup run same-scope-order",
        input="y\ny\n",
        timeout=180,
    )

    _write_setup(
        project,
        "same-scope-order",
        "#!/bin/bash\nset -eu\nprintf 'local-result\\n' > /etc/zaigr-local-result\n",
    )
    _checked_run(
        project,
        "project setup run same-scope-order",
        input="y\n",
        timeout=180,
    )

    _checked_run(project, "project vm stop", timeout=60)
    _checked_run(project, "project rebuild --force", timeout=360)
    _checked_run(project, "project vm start", timeout=180)
    global_result = _checked_run(
        project,
        "project vm exec -- cat /etc/zaigr-global-result",
        timeout=60,
    )
    local_result = _checked_run(
        project,
        "project vm exec -- cat /etc/zaigr-local-result",
        timeout=60,
    )
    assert global_result.strip() == "global-result"
    assert local_result.strip() == "local-result"


@pytest.mark.timeout(600)
def test_legacy_sorted_metadata_stays_ordered_and_new_setup_appends(project):
    """Keep an existing sorted sequence and append new records without guessing chronology."""
    _write_setup(
        project,
        "aaa-existing",
        "#!/bin/bash\nset -eu\nprintf 'existing\\n' > /etc/zaigr-existing\n",
    )
    _write_setup(
        project,
        "zz-existing",
        "#!/bin/bash\nset -eu\nprintf 'tail\\n' > /etc/zaigr-tail\n",
    )
    _checked_run(
        project,
        "project setup run aaa-existing zz-existing",
        input="y\ny\n",
        timeout=180,
    )

    applied_path = project.store_dir / "applied-setups.json"
    existing = json.loads(applied_path.read_text(encoding="utf-8"))
    assert [record["name"] for record in existing] == ["aaa-existing", "zz-existing"]

    _checked_run(
        project,
        "project setup run aaa-existing --force",
        input="y\n",
        timeout=180,
    )
    rerun = json.loads(applied_path.read_text(encoding="utf-8"))
    assert [record["name"] for record in rerun] == ["aaa-existing", "zz-existing"]
    applied_list = _checked_run(project, "project setup list --applied", timeout=30)
    assert applied_list.count("aaa-existing") == 1

    _write_setup(
        project,
        "000-new",
        "#!/bin/bash\nset -eu\nprintf 'new\\n' > /etc/zaigr-new\n",
    )
    _checked_run(
        project,
        "project setup run 000-new",
        input="y\n",
        timeout=180,
    )
    appended = json.loads(applied_path.read_text(encoding="utf-8"))
    assert [record["name"] for record in appended] == [
        "aaa-existing",
        "zz-existing",
        "000-new",
    ]
