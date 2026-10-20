"""Project isolation choices are explicit and survive ordinary project workflows."""

import os
from functools import partial
from pathlib import Path

from tests.conftest import err_msg, run


def checked(command, **kwargs):
    """Run a visible command with transcript capture and require success."""
    stdout, stderr, rc = run(command, **kwargs)
    assert rc == 0, err_msg(stdout, stderr)
    return stdout


def test_sandbox_namespace_is_required_and_legacy_none_fails_before_start(project_factory):
    """The public setting rejects none and an old saved none setting starts no VM."""
    project = project_factory("namespace-required")
    other = project_factory("default-choice")
    cli = str(project.zaigr_bin)
    user = partial(checked, cwd=project.cwd, env=project.env, timeout=180)
    user([cli, "project", "vm", "start"], input="y\n")
    assert "virtiofs-sandbox=namespace" in user([cli, "project", "vm", "show-config"])
    stdout, stderr, rc = run(
        [cli, "project", "vm", "set-config", "--virtiofs-sandbox", "invalid"],
        cwd=project.cwd, env=project.env,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert "virtiofs-sandbox=namespace" in user([cli, "project", "vm", "show-config"])
    user([cli, "project", "vm", "stop"])
    stdout, stderr, rc = run(
        [cli, "project", "vm", "set-config", "--virtiofs-sandbox", "none"],
        cwd=project.cwd, env=project.env,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert "--virtiofs-sandbox none is unsupported" in stdout + stderr
    assert "host-enforced VM networking requires the namespace file-sharing sandbox" in stdout + stderr
    assert "zaigr misc check" in stdout + stderr
    assert "virtiofs-sandbox=namespace" in user([cli, "project", "vm", "show-config"])

    # Legacy metadata is the only way an older installation could have saved
    # this unsupported choice; exercise its public startup behavior directly.
    project.store_dir.joinpath("virtiofs-sandbox").write_text("none\n", encoding="utf-8")
    stdout, stderr, rc = run([cli, "project", "vm", "start"], cwd=project.cwd, env=project.env, timeout=60)
    assert rc != 0, err_msg(stdout, stderr)
    assert "saved project setting is virtiofs-sandbox=none" in stdout + stderr
    assert "Booting VM" not in stdout
    assert not project.store_dir.joinpath("vm-supervisor.json").exists()

    user([cli, "project", "vm", "set-config", "--virtiofs-sandbox", "namespace"])
    user([cli, "project", "vm", "start"], input="y\n", timeout=180)
    user([cli, "project", "vm", "stop"])

    checked([cli, "project", "vm", "start"], cwd=other.cwd, env=other.env, input="y\n", timeout=180)
    shown = checked([cli, "project", "vm", "show-config"], cwd=other.cwd, env=other.env)
    assert "virtiofs-sandbox=namespace" in shown


def test_apparmor_profile_targets_zaigr_and_cached_daemon(zaigr_bin, zaigr_home):
    """Generation covers the exact Zaigr and daemon paths without a global unshare rule."""
    profile = checked([zaigr_bin, "misc", "apparmor-profile"])
    daemons = [path for path in (zaigr_home / ".zaigr").glob("virtiofsd-*") if path.is_file() and os.access(path, os.X_OK)]
    assert len(daemons) == 1
    zaigr = Path(zaigr_bin).resolve()
    daemon = daemons[0].resolve()
    assert f'profile zaigr "{zaigr}" flags=(unconfined)' in profile
    assert f'profile zaigr-virtiofsd "{daemon}" flags=(unconfined)' in profile
    assert profile.count("userns,") == 2
    assert "Same-user code may replace files at these paths" in profile
    assert "/usr/bin/unshare" not in profile
    assert "unshare" not in profile
    assert not (zaigr_home / ".zaigr/store").exists()
