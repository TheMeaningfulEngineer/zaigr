"""Project isolation choices are explicit and survive ordinary project workflows."""

import os
from functools import partial

from tests.conftest import err_msg, run


def checked(command, **kwargs):
    """Run a visible command with transcript capture and require success."""
    stdout, stderr, rc = run(command, **kwargs)
    assert rc == 0, err_msg(stdout, stderr)
    return stdout


def test_sandbox_preference_is_per_project_and_survives_clean(project_factory):
    """Explicit unsafe mode serves files, persists through clean, and can be reversed."""
    project = project_factory("unsafe-choice")
    other = project_factory("default-choice")
    cli = str(project.zaigr_bin)
    user = partial(checked, cwd=project.cwd, env=project.env, timeout=180)
    user([cli, "project", "vm", "start"], input="y\n")
    assert "virtiofs-sandbox=namespace" in user([cli, "project", "vm", "show-config"])
    user([cli, "project", "vm", "stop"])
    stdout, stderr, rc = run(
        [cli, "project", "vm", "set-config", "--virtiofs-sandbox", "invalid"],
        cwd=project.cwd, env=project.env,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert "virtiofs-sandbox=namespace" in user([cli, "project", "vm", "show-config"])
    user([cli, "project", "vm", "set-config", "--virtiofs-sandbox", "none"])
    stdout, stderr, rc = run([cli, "project", "vm", "start"], cwd=project.cwd, env=project.env, timeout=180)
    assert rc == 0, err_msg(stdout, stderr)
    assert "WARNING: Without the file-sharing sandbox" in stderr
    user([cli, "project", "vm", "exec", "--", "tee", "/home/user/workspace/canary"], input="workspace\n")
    user([cli, "project", "vm", "exec", "--root", "--", "tee", "/home/user/.zaigr-agent-state/policy-canary"], input="y\nstate\n")
    assert (project.cwd / "canary").read_text() == "workspace\n"
    user([cli, "project", "vm", "stop"])
    user([cli, "project", "clean"])
    assert "virtiofs-sandbox=none" in user([cli, "project", "vm", "show-config"])
    user([cli, "project", "vm", "set-config", "--virtiofs-sandbox", "namespace"])
    user([cli, "project", "vm", "start"])
    assert user([cli, "project", "vm", "exec", "--", "cat", "/home/user/.zaigr-agent-state/policy-canary"]) == "state\n"
    user([cli, "project", "vm", "stop"])
    user([cli, "project", "vm", "set-config", "--virtiofs-sandbox", "none"])
    checked([cli, "project", "vm", "start"], cwd=other.cwd, env=other.env, input="y\n", timeout=180)
    shown = checked([cli, "project", "vm", "show-config"], cwd=other.cwd, env=other.env)
    assert "virtiofs-sandbox=namespace" in shown


def test_apparmor_profile_targets_cached_daemon_only(zaigr_bin, zaigr_home):
    """Generation emits reviewable policy without loading it or initializing a project."""
    profile = checked([zaigr_bin, "misc", "apparmor-profile"])
    daemons = [path for path in (zaigr_home / ".zaigr").glob("virtiofsd-*") if path.is_file() and os.access(path, os.X_OK)]
    assert len(daemons) == 1
    assert f'profile zaigr-virtiofsd "{daemons[0]}" flags=(unconfined)' in profile
    assert "userns," in profile
    assert "user-writable" in profile
    assert not (zaigr_home / ".zaigr/store").exists()
