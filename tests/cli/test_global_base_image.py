"""Public CLI acceptance tests for the customizable global default image.

The probe is deliberately a tiny installed executable, not an agent package.
Each installer execution changes its random ID and increments its on-image count.
No assertions depend on the new feature's private image or manifest layout.
"""

import re
import signal
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from uuid import UUID

import pexpect
import pytest

from ..conftest import err_msg, spawn_interactive
from ..conftest import run as _run


@pytest.fixture(autouse=True)
def small_vm_resources(monkeypatch):
    """Keep these tiny installers economical when the CLI suite runs in parallel."""
    monkeypatch.setenv("ZAIGR_VM_RAM", "512")
    monkeypatch.setenv("ZAIGR_VM_CPU", "1")


@pytest.fixture
def probe_script():
    """Small installation fixture whose observable identity detects replay."""
    return r"""
mkdir -p /opt/zaigr-base-probe
count=0
if [ -f /opt/zaigr-base-probe/count ]; then
    count=$(cat /opt/zaigr-base-probe/count)
fi
printf '%s\n' "$((count + 1))" > /opt/zaigr-base-probe/count
cat /proc/sys/kernel/random/uuid > /opt/zaigr-base-probe/id
printf 'v1\n' > /opt/zaigr-base-probe/release
printf '#!/bin/sh\ncat /opt/zaigr-base-probe/id /opt/zaigr-base-probe/count /opt/zaigr-base-probe/release\n' > /usr/local/bin/base-probe
chmod 0755 /usr/local/bin/base-probe
printf 'BASE_PROBE_INSTALL_EXECUTED\n'
"""


def _checked_run(cmd, **kwargs):
    """Run a visible CLI command and require success."""
    stdout, stderr, rc = _run(cmd, **kwargs)
    assert rc == 0, err_msg(stdout, stderr)
    return stdout


def _assert_probe(output, count, release="v1"):
    """Validate probe output and return its installation ID."""
    lines = output.strip().splitlines()
    assert len(lines) == 3, output
    assert str(UUID(lines[0])) == lines[0], output
    assert lines[1:] == [str(count), release], output
    return lines[0]


def test_global_base_image_help_status_and_reset_without_project(
    zaigr_bin, zaigr_home, tmp_path, setup_factory
):
    """Inspection and reset work in an empty directory without initializing it."""
    run = partial(_checked_run, cwd=tmp_path)
    zaigr = zaigr_bin
    setup_factory("unapplied-probe", "exit 92")

    help_text = run(f"{zaigr} global --help", timeout=10)
    assert "base-image" in help_text
    help_text = run(f"{zaigr} global base-image --help", timeout=10)
    for command in ("status", "reset", "setup"):
        assert command in help_text
    assert "rollback" not in help_text
    help_text = run(f"{zaigr} global base-image setup run --help", timeout=10)
    for flag in ("--force", "--ram", "--cpu"):
        assert flag in help_text
    project_help = run(f"{zaigr} project --help", timeout=10)
    assert "--base-image" not in project_help

    before_projects = run(f"{zaigr} global projects list --full-paths", timeout=10)
    status = run(f"{zaigr} global base-image status", timeout=10)
    assert "factory" in status.lower()
    assert "unapplied-probe" not in status
    versions = run(f"{zaigr} misc full-version", timeout=10)
    runtime = next(
        line.removeprefix("base-image: ")
        for line in versions.splitlines()
        if line.startswith("base-image: ")
    )
    assert runtime in status

    run(f"{zaigr} global base-image reset", timeout=10)
    run(f"{zaigr} global base-image reset", timeout=10)
    assert "factory" in run(f"{zaigr} global base-image status", timeout=10).lower()
    assert (
        run(f"{zaigr} global projects list --full-paths", timeout=10)
        == before_projects
    )
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "arguments, diagnostic",
    [
        ("", r"(argument|name|setup)"),
        ("preflight missing-global-setup", r"missing-global-setup"),
        ("preflight preflight", r"(duplicate|more than once|repeated)"),
        ("preflight --ram invalid", r"(ram|memory)"),
        ("preflight --cpu 0", r"cpu"),
    ],
)
def test_global_base_image_rejects_invalid_batch_before_execution(
    zaigr_bin, zaigr_home, tmp_path, setup_factory, arguments, diagnostic
):
    """Name/resource preflight never runs an earlier otherwise valid installer."""
    setup_factory("preflight", "printf 'PREFLIGHT_SCRIPT_EXECUTED\\n'\nexit 93")
    stdout, stderr, rc = _run(
        f"{zaigr_bin} global base-image setup run {arguments}",
        cwd=tmp_path,
        timeout=20,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert re.search(diagnostic, stdout + stderr, re.IGNORECASE), err_msg(
        stdout, stderr
    )
    assert "PREFLIGHT_SCRIPT_EXECUTED" not in stdout + stderr
    status = _checked_run(f"{zaigr_bin} global base-image status", cwd=tmp_path)
    assert "factory" in status.lower()
    assert "preflight" not in status
    assert list(tmp_path.iterdir()) == []


@pytest.mark.timeout(600)
def test_global_installation_is_reused_by_sizes_presets_and_project_force(
    project_factory, setup_factory, probe_script, tmp_path
):
    """8G/default-100G projects and a preset share one actual installation."""
    small = project_factory("small")
    default = project_factory("default")
    later = project_factory("later")
    zaigr = small.zaigr_bin
    global_run = partial(_checked_run, cwd=tmp_path, env=small.env)
    small_env = small.env
    small_env["ZAIGR_DISK_SIZE"] = "8G"
    default_env = default.env
    default_env.pop("ZAIGR_DISK_SIZE", None)
    run_small = partial(_checked_run, cwd=small.cwd, env=small_env)
    run_default = partial(_checked_run, cwd=default.cwd, env=default_env)
    run_later = partial(_checked_run, cwd=later.cwd, env=later.env)
    setup_factory(
        "base-probe",
        probe_script
        + "\ngetconf _NPROCESSORS_ONLN > /etc/base-build-cpus\n"
        + "awk '/MemTotal/ {print $2}' /proc/meminfo > /etc/base-build-memory-kb\n",
    )
    setup_factory.preset(
        "probe-preset", "base-probe > preset-probe.txt", ["base-probe"]
    )

    installed = global_run(
        f"{zaigr} global base-image setup run base-probe --ram 768 --cpu 2",
        timeout=180,
    )
    assert "BASE_PROBE_INSTALL_EXECUTED" in installed
    global_status = global_run(f"{zaigr} global base-image status", timeout=10)
    assert "custom" in global_status.lower()
    assert "base-probe" in global_status

    run_small(f"{zaigr} project vm start", input="y\n", timeout=180)
    small_probe = run_small(f"{zaigr} project vm exec -- base-probe", timeout=20)
    installation_id = _assert_probe(small_probe, 1)
    assert (
        run_small(
            f"{zaigr} project vm exec -- cat /etc/base-build-cpus", timeout=20
        ).strip()
        == "2"
    )
    build_memory = run_small(
        f"{zaigr} project vm exec -- cat /etc/base-build-memory-kb", timeout=20
    )
    assert 650 * 1024 < int(build_memory) <= 768 * 1024
    capacity = run_small(
        f"{zaigr} project vm exec -- df -B1 --output=size /", timeout=20
    )
    assert 7 * 1024**3 < int(capacity.splitlines()[-1]) <= 8 * 1024**3
    applied = run_small(f"{zaigr} project setup list --applied", timeout=10)
    assert "base-probe" in applied

    run_default(f"{zaigr} project vm start", input="y\n", timeout=180)
    default_probe = run_default(f"{zaigr} project vm exec -- base-probe", timeout=20)
    assert default_probe == small_probe
    capacity = run_default(
        f"{zaigr} project vm exec -- df -B1 --output=size /", timeout=20
    )
    assert 90 * 1024**3 < int(capacity.splitlines()[-1]) <= 100 * 1024**3
    run_default(f"{zaigr} shell --preset probe-preset", timeout=60)
    assert (default.cwd / "preset-probe.txt").read_text(encoding="utf-8") == small_probe
    assert (
        run_default(f"{zaigr} project vm exec -- base-probe", timeout=20) == small_probe
    )

    skipped = run_small(f"{zaigr} project setup run base-probe", timeout=30)
    assert "BASE_PROBE_INSTALL_EXECUTED" not in skipped
    assert (
        run_small(f"{zaigr} project vm exec -- base-probe", timeout=20) == small_probe
    )
    run_small(f"{zaigr} project setup run base-probe --force", timeout=120)
    forced = run_small(f"{zaigr} project vm exec -- base-probe", timeout=20)
    assert _assert_probe(forced, 2) != installation_id
    assert (
        run_default(f"{zaigr} project vm exec -- base-probe", timeout=20) == small_probe
    )
    status_after_force = global_run(f"{zaigr} global base-image status", timeout=10)
    assert (
        next(line for line in global_status.splitlines() if "base-probe" in line)
        in status_after_force
    )

    run_later(f"{zaigr} project vm start", input="y\n", timeout=180)
    assert (
        run_later(f"{zaigr} project vm exec -- base-probe", timeout=20) == small_probe
    )
    assert list(tmp_path.iterdir()) == []


@pytest.mark.timeout(1200)
def test_global_updates_and_reset_preserve_existing_projects(
    project_factory, setup_factory, probe_script, tmp_path
):
    """Updates accumulate, force/source edits rerun, and old images remain pinned."""
    factory = project_factory("before-customization")
    revision_a = project_factory("revision-a")
    revision_b = project_factory("revision-b")
    revision_c = project_factory("revision-c")
    reset_project = project_factory("after-reset")
    zaigr = factory.zaigr_bin
    run = partial(_checked_run, env=factory.env)
    global_run = partial(run, cwd=tmp_path)
    setup_factory("base-probe", probe_script)
    setup_factory("base-extra", "printf 'extra\\n' > /etc/base-extra")
    (factory.cwd / "workspace.txt").write_text("factory-workspace\n", encoding="utf-8")

    run(f"{zaigr} project vm start", cwd=factory.cwd, input="y\n", timeout=180)
    run(
        f"{zaigr} project vm exec -- tee /home/user/factory-content",
        cwd=factory.cwd,
        input="factory-content\n",
        timeout=20,
    )
    run(f"{zaigr} project vm stop", cwd=factory.cwd, timeout=60)

    global_run(f"{zaigr} global base-image setup run base-probe", timeout=180)
    status_a = global_run(f"{zaigr} global base-image status", timeout=10)
    run(f"{zaigr} project vm start", cwd=revision_a.cwd, input="y\n", timeout=180)
    probe_a = run(
        f"{zaigr} project vm exec -- base-probe", cwd=revision_a.cwd, timeout=20
    )
    id_a = _assert_probe(probe_a, 1)
    run(
        f"{zaigr} project vm exec -- mkdir -p /home/user/.zaigr-agent-state/probe",
        cwd=revision_a.cwd,
        timeout=20,
    )
    run(
        f"{zaigr} project vm exec -- tee /home/user/.zaigr-agent-state/probe/credential",
        cwd=revision_a.cwd,
        input="revision-a-credential\n",
        timeout=20,
    )

    global_run(f"{zaigr} global base-image setup run base-extra", timeout=180)
    skipped = global_run(f"{zaigr} global base-image setup run base-probe", timeout=30)
    assert "BASE_PROBE_INSTALL_EXECUTED" not in skipped
    global_run(f"{zaigr} global base-image setup run base-probe --force", timeout=180)
    run(f"{zaigr} project vm start", cwd=revision_b.cwd, input="y\n", timeout=180)
    probe_b = run(
        f"{zaigr} project vm exec -- base-probe", cwd=revision_b.cwd, timeout=20
    )
    id_b = _assert_probe(probe_b, 2)
    assert id_b != id_a
    assert (
        run(
            f"{zaigr} project vm exec -- cat /etc/base-extra",
            cwd=revision_b.cwd,
            timeout=20,
        ).strip()
        == "extra"
    )

    setup_factory(
        "base-probe",
        probe_script + "\nprintf 'v2\\n' > /opt/zaigr-base-probe/release\n",
    )
    global_run(f"{zaigr} global base-image setup run base-probe", timeout=180)
    status_c = global_run(f"{zaigr} global base-image status", timeout=10)
    # Compare the public applied entry, without reimplementing source hashing.
    entry_a = next(line for line in status_a.splitlines() if "base-probe" in line)
    entry_c = next(line for line in status_c.splitlines() if "base-probe" in line)
    assert entry_c != entry_a
    run(f"{zaigr} project vm start", cwd=revision_c.cwd, input="y\n", timeout=180)
    probe_c = run(
        f"{zaigr} project vm exec -- base-probe", cwd=revision_c.cwd, timeout=20
    )
    assert _assert_probe(probe_c, 3, "v2") not in (id_a, id_b)
    assert (
        run(
            f"{zaigr} project vm exec -- cat /etc/base-extra",
            cwd=revision_c.cwd,
            timeout=20,
        ).strip()
        == "extra"
    )
    assert (
        run(f"{zaigr} project vm exec -- base-probe", cwd=revision_a.cwd, timeout=20)
        == probe_a
    )

    global_run(f"{zaigr} global base-image reset", timeout=30)
    global_run(f"{zaigr} global base-image reset", timeout=30)
    status = global_run(f"{zaigr} global base-image status", timeout=10)
    assert "factory" in status.lower()
    assert "base-probe" not in status
    assert "base-extra" not in status
    assert (
        run(f"{zaigr} project vm exec -- base-probe", cwd=revision_a.cwd, timeout=20)
        == probe_a
    )
    run(f"{zaigr} project vm stop", cwd=revision_a.cwd, timeout=60)
    run(f"{zaigr} project vm start", cwd=revision_a.cwd, timeout=180)
    assert (
        run(f"{zaigr} project vm exec -- base-probe", cwd=revision_a.cwd, timeout=20)
        == probe_a
    )
    assert (
        run(
            f"{zaigr} project vm exec -- cat /home/user/.zaigr-agent-state/probe/credential",
            cwd=revision_a.cwd,
            timeout=20,
        ).strip()
        == "revision-a-credential"
    )
    run(f"{zaigr} project vm start", cwd=factory.cwd, timeout=180)
    assert (
        run(
            f"{zaigr} project vm exec -- cat /home/user/factory-content",
            cwd=factory.cwd,
            timeout=20,
        ).strip()
        == "factory-content"
    )
    assert (factory.cwd / "workspace.txt").read_text(
        encoding="utf-8"
    ) == "factory-workspace\n"
    run(
        f"{zaigr} project vm exec -- test ! -e /usr/local/bin/base-probe",
        cwd=factory.cwd,
        timeout=20,
    )

    run(f"{zaigr} project vm start", cwd=reset_project.cwd, input="y\n", timeout=180)
    run(
        f"{zaigr} project vm exec -- test ! -e /usr/local/bin/base-probe",
        cwd=reset_project.cwd,
        timeout=20,
    )
    run(
        f"{zaigr} project vm exec -- test ! -e /etc/base-extra",
        cwd=reset_project.cwd,
        timeout=20,
    )
    assert "base-probe" not in run(
        f"{zaigr} project setup list --applied", cwd=reset_project.cwd, timeout=10
    )
    global_run(f"{zaigr} global base-image setup run base-probe", timeout=180)
    run(f"{zaigr} project vm stop", cwd=reset_project.cwd, timeout=60)
    run(f"{zaigr} project clean", cwd=reset_project.cwd, timeout=180)
    run(f"{zaigr} project vm start", cwd=reset_project.cwd, timeout=180)
    recustomized = run(
        f"{zaigr} project vm exec -- base-probe", cwd=reset_project.cwd, timeout=20
    )
    assert _assert_probe(recustomized, 1, "v2") not in (id_a, id_b)


def _stable_project_listing(output):
    """Extract project fields without live disk usage.

    Args:
        output: Output from global projects list --full-paths.

    Returns:
        Project paths, statuses, CPU counts, RAM sizes, and IDs in display order.
    """
    lines = output.splitlines()
    assert lines and lines[0].split() == [
        "PROJECT", "STATUS", "CPU", "RAM", "DISK", "USED", "ID"
    ]
    projects = []
    for line in lines[1:]:
        if not line.strip():
            break
        path, status, cpu, ram, _disk_used, project_id = line.rsplit(maxsplit=5)
        projects.append((path, status, cpu, ram, project_id))
    return projects


@pytest.mark.timeout(900)
def test_global_batch_failure_is_transactional_and_recoverable(
    project_factory, setup_factory, probe_script, tmp_path
):
    """A failed later step cannot publish earlier writes or overwrite the last base."""
    prior = project_factory("prior")
    after_failure = project_factory("after-failure")
    recovered = project_factory("recovered")
    zaigr = prior.zaigr_bin
    run = partial(_checked_run, env=prior.env)
    global_run = partial(run, cwd=tmp_path)
    setup_factory("base-probe", probe_script)
    setup_factory("first-failure", "printf 'partial\\n' > /etc/first-failure\nexit 41")
    setup_factory(
        "z-batch-first",
        "printf 'first\\n' > /etc/batch-order\nprintf 'partial\\n' > /etc/batch-partial",
    )
    setup_factory(
        "a-batch-second",
        "test \"$(cat /etc/batch-order)\" = first\nprintf 'second\\n' >> /etc/batch-order\nexit 42",
    )

    stdout, stderr, rc = _run(
        f"{zaigr} global base-image setup run first-failure",
        cwd=tmp_path,
        env=prior.env,
        timeout=180,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert "first-failure" in stdout + stderr
    assert (
        "factory" in global_run(f"{zaigr} global base-image status", timeout=10).lower()
    )
    global_run(f"{zaigr} global base-image setup run base-probe", timeout=180)
    successful_status = global_run(f"{zaigr} global base-image status", timeout=10)
    run(f"{zaigr} project vm start", cwd=prior.cwd, input="y\n", timeout=180)
    original = run(f"{zaigr} project vm exec -- base-probe", cwd=prior.cwd, timeout=20)
    _assert_probe(original, 1)
    projects_before = _stable_project_listing(
        global_run(f"{zaigr} global projects list --full-paths", timeout=10)
    )

    stdout, stderr, rc = _run(
        f"{zaigr} global base-image setup run z-batch-first a-batch-second",
        cwd=tmp_path,
        env=prior.env,
        timeout=180,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert "a-batch-second" in stdout + stderr
    failed_status = global_run(f"{zaigr} global base-image status", timeout=10)
    assert (
        next(line for line in successful_status.splitlines() if "base-probe" in line)
        in failed_status
    )
    assert "z-batch-first" not in failed_status
    assert "a-batch-second" not in failed_status
    assert (
        _stable_project_listing(
            global_run(f"{zaigr} global projects list --full-paths", timeout=10)
        )
        == projects_before
    )
    run(f"{zaigr} project vm start", cwd=after_failure.cwd, input="y\n", timeout=180)
    assert (
        run(f"{zaigr} project vm exec -- base-probe", cwd=after_failure.cwd, timeout=20)
        == original
    )
    for path in ("/etc/first-failure", "/etc/batch-order", "/etc/batch-partial"):
        run(
            f"{zaigr} project vm exec -- test ! -e {path}",
            cwd=after_failure.cwd,
            timeout=20,
        )
    applied = run(
        f"{zaigr} project setup list --applied", cwd=after_failure.cwd, timeout=10
    )
    assert "base-probe" in applied
    assert "z-batch-first" not in applied
    assert "a-batch-second" not in applied

    setup_factory(
        "a-batch-second",
        "test \"$(cat /etc/batch-order)\" = first\nprintf 'second\\n' >> /etc/batch-order",
    )
    global_run(
        f"{zaigr} global base-image setup run z-batch-first a-batch-second", timeout=180
    )
    run(f"{zaigr} project vm start", cwd=recovered.cwd, input="y\n", timeout=180)
    assert (
        run(
            f"{zaigr} project vm exec -- cat /etc/batch-order",
            cwd=recovered.cwd,
            timeout=20,
        )
        == "first\nsecond\n"
    )
    assert (
        run(f"{zaigr} project vm exec -- base-probe", cwd=recovered.cwd, timeout=20)
        == original
    )
    applied = run(
        f"{zaigr} project setup list --applied", cwd=recovered.cwd, timeout=10
    )
    assert "z-batch-first" in applied
    assert "a-batch-second" in applied


@pytest.mark.timeout(900)
def test_rebuild_and_clean_adopt_current_base_without_replaying_inherited_setups(
    project, setup_factory, probe_script, tmp_path
):
    """Refresh retains explicit setup intent and agent state, while clean drops additions."""
    zaigr = project.zaigr_bin
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    global_run = partial(_checked_run, cwd=tmp_path, env=project.env)
    setup_factory("base-probe", probe_script)
    setup_factory("base-extra", "printf 'current-base\\n' > /etc/base-extra")
    local = project.cwd / ".zaigr" / "setups" / "project-addition"
    local.mkdir(parents=True)
    (local / "setup.script").write_text(
        "#!/bin/bash\nset -eu\n"
        "cat /opt/zaigr-base-probe/id > /etc/project-addition-base-id\n"
        "printf 'explicit-local\\n' > /etc/project-addition\n",
        encoding="utf-8",
    )
    workspace = project.cwd / "workspace.txt"
    workspace.write_text("workspace-preserved\n", encoding="utf-8")

    global_run(f"{zaigr} global base-image setup run base-probe", timeout=180)
    run(f"{zaigr} project vm start", input="y\n", timeout=180)
    original = run(f"{zaigr} project vm exec -- base-probe", timeout=20)
    _assert_probe(original, 1)
    run(f"{zaigr} project setup run project-addition", timeout=120)
    run(
        f"{zaigr} project vm exec -- mkdir -p /home/user/.zaigr-agent-state/refresh",
        timeout=20,
    )
    run(
        f"{zaigr} project vm exec -- tee /home/user/.zaigr-agent-state/refresh/credential",
        input="refresh-credential\n",
        timeout=20,
    )
    run(f"{zaigr} project vm stop", timeout=60)

    global_run(
        f"{zaigr} global base-image setup run base-extra base-probe --force",
        timeout=180,
    )
    rebuilt = run(f"{zaigr} project rebuild", timeout=240)
    assert "BASE_PROBE_INSTALL_EXECUTED" not in rebuilt
    run(f"{zaigr} project vm start", timeout=180)
    refreshed = run(f"{zaigr} project vm exec -- base-probe", timeout=20)
    refreshed_id = _assert_probe(refreshed, 2)
    assert refreshed_id != original.splitlines()[0]
    assert (
        run(
            f"{zaigr} project vm exec -- cat /etc/project-addition-base-id", timeout=20
        ).strip()
        == refreshed_id
    )
    assert (
        run(f"{zaigr} project vm exec -- cat /etc/project-addition", timeout=20).strip()
        == "explicit-local"
    )
    assert (
        run(f"{zaigr} project vm exec -- cat /etc/base-extra", timeout=20).strip()
        == "current-base"
    )
    assert (
        run(
            f"{zaigr} project vm exec -- cat /home/user/.zaigr-agent-state/refresh/credential",
            timeout=20,
        ).strip()
        == "refresh-credential"
    )

    run(f"{zaigr} project vm stop", timeout=60)
    run(f"{zaigr} project clean", timeout=180)
    run(f"{zaigr} project vm start", timeout=180)
    assert run(f"{zaigr} project vm exec -- base-probe", timeout=20) == refreshed
    run(f"{zaigr} project vm exec -- test ! -e /etc/project-addition", timeout=20)
    assert (
        run(f"{zaigr} project vm exec -- cat /etc/base-extra", timeout=20).strip()
        == "current-base"
    )
    applied = run(f"{zaigr} project setup list --applied", timeout=10)
    assert "base-probe" in applied
    assert "base-extra" in applied
    assert "project-addition" not in applied
    assert workspace.read_text(encoding="utf-8") == "workspace-preserved\n"

    global_run(f"{zaigr} global base-image reset", timeout=30)
    run(f"{zaigr} project vm stop", timeout=60)
    rebuilt = run(f"{zaigr} project rebuild", timeout=240)
    assert "BASE_PROBE_INSTALL_EXECUTED" not in rebuilt
    run(f"{zaigr} project vm start", timeout=180)
    run(f"{zaigr} project vm exec -- test ! -e /usr/local/bin/base-probe", timeout=20)
    run(f"{zaigr} project vm exec -- test ! -e /etc/base-extra", timeout=20)
    applied = run(f"{zaigr} project setup list --applied", timeout=10)
    assert "base-probe" not in applied
    assert "base-extra" not in applied
    assert "project-addition" not in applied


@pytest.mark.timeout(600)
def test_global_build_uses_global_definitions_and_isolates_workspace_and_agent_state(
    project_factory, setup_factory
):
    """A global build inside a project cannot see its local setup or mounted state."""
    caller = project_factory("caller")
    inherited = project_factory("inherited")
    zaigr = caller.zaigr_bin
    run = partial(_checked_run, cwd=caller.cwd, env=caller.env)
    run_inherited = partial(_checked_run, cwd=inherited.cwd, env=inherited.env)
    workspace_secret = caller.cwd / "caller-secret"
    workspace_secret.write_text("caller-workspace-secret\n", encoding="utf-8")
    local = caller.cwd / ".zaigr" / "setups"
    (local / "scope-probe").mkdir(parents=True)
    (local / "scope-probe" / "setup.script").write_text(
        "#!/bin/bash\nset -eu\nprintf 'local\\n' > /etc/local-scope-probe\n",
        encoding="utf-8",
    )
    (local / "local-only").mkdir()
    (local / "local-only" / "setup.script").write_text(
        "#!/bin/bash\nprintf 'LOCAL_ONLY_EXECUTED\\n'\n", encoding="utf-8"
    )
    setup_factory(
        "scope-probe",
        r"""
test ! -e /home/user/workspace/caller-secret
test ! -e /home/user/.zaigr-agent-state/scope/credential
mkdir -p /home/user/.zaigr-agent-state/scope
printf 'staging-state\n' > /home/user/.zaigr-agent-state/scope/build-only
printf 'staging-workspace\n' > /home/user/workspace/build-only
printf 'global\n' > /etc/global-scope-probe
""",
    )

    run(f"{zaigr} project vm start", input="y\n", timeout=180)
    run(
        f"{zaigr} project vm exec -- mkdir -p /home/user/.zaigr-agent-state/scope",
        timeout=20,
    )
    run(
        f"{zaigr} project vm exec -- tee /home/user/.zaigr-agent-state/scope/credential",
        input="caller-agent-secret\n",
        timeout=20,
    )
    applied_before = run(f"{zaigr} project setup list --applied", timeout=10)
    projects_before = _stable_project_listing(
        run(f"{zaigr} global projects list --full-paths", timeout=10)
    )
    stdout, stderr, rc = _run(
        f"{zaigr} global base-image setup run local-only",
        cwd=caller.cwd,
        env=caller.env,
        timeout=20,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert "local-only" in stdout + stderr
    assert "LOCAL_ONLY_EXECUTED" not in stdout + stderr

    run(f"{zaigr} global base-image setup run scope-probe", timeout=180)
    assert run(f"{zaigr} project setup list --applied", timeout=10) == applied_before
    assert (
        _stable_project_listing(
            run(f"{zaigr} global projects list --full-paths", timeout=10)
        )
        == projects_before
    )
    assert workspace_secret.read_text(encoding="utf-8") == "caller-workspace-secret\n"
    assert not (caller.cwd / "build-only").exists()
    assert (
        run(
            f"{zaigr} project vm exec -- cat /home/user/.zaigr-agent-state/scope/credential",
            timeout=20,
        ).strip()
        == "caller-agent-secret"
    )
    run(
        f"{zaigr} project vm exec -- test ! -e /home/user/.zaigr-agent-state/scope/build-only",
        timeout=20,
    )
    run(f"{zaigr} project vm exec -- test ! -e /etc/global-scope-probe", timeout=20)

    # The second project also has a same-name local setup, created before init.
    inherited_local = inherited.cwd / ".zaigr" / "setups" / "scope-probe"
    inherited_local.mkdir(parents=True)
    (inherited_local / "setup.script").write_text(
        (local / "scope-probe" / "setup.script").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    run_inherited(f"{zaigr} project vm start", input="y\n", timeout=180)
    assert (
        run_inherited(
            f"{zaigr} project vm exec -- cat /etc/global-scope-probe", timeout=20
        ).strip()
        == "global"
    )
    run_inherited(
        f"{zaigr} project vm exec -- test ! -e /etc/local-scope-probe", timeout=20
    )
    run_inherited(
        f"{zaigr} project vm exec -- test ! -e /home/user/.zaigr-agent-state/scope/build-only",
        timeout=20,
    )
    run_inherited(f"{zaigr} project setup run scope-probe", timeout=120)
    assert (
        run_inherited(
            f"{zaigr} project vm exec -- cat /etc/local-scope-probe", timeout=20
        ).strip()
        == "local"
    )
    assert (
        run_inherited(
            f"{zaigr} project vm exec -- cat /etc/global-scope-probe", timeout=20
        ).strip()
        == "global"
    )
    applied = run_inherited(f"{zaigr} project setup list --applied", timeout=10)
    assert "[Project local] scope-probe" in applied


@pytest.mark.timeout(600)
def test_inherited_firewall_allows_only_successful_rules_and_reset_restores_factory(
    project_factory, setup_factory, tmp_path
):
    """Actual requests detect missing inherited rules and leaked setup network access."""
    customized = project_factory("network-customized")
    factory = project_factory("network-factory")
    zaigr = customized.zaigr_bin
    run = partial(_checked_run, cwd=customized.cwd, env=customized.env)
    global_run = partial(_checked_run, cwd=tmp_path, env=customized.env)
    run_factory = partial(_checked_run, cwd=factory.cwd, env=factory.env)
    setup_factory(
        "network-base",
        "curl -4 -fsS -o /dev/null --connect-timeout 5 --max-time 15 https://pypi.org\n"
        "curl -4 -fsS -o /dev/null --connect-timeout 5 --max-time 15 https://github.com",
        firewall=["pypi.org"],
    )
    setup_factory(
        "network-failure",
        "curl -4 -fsS -o /dev/null --connect-timeout 5 --max-time 15 https://github.com\n"
        "printf 'FAILED_SETUP_NETWORK_SUCCEEDED\\n'\nexit 43",
        firewall=["github.com"],
    )

    # Reachability controls distinguish a firewall denial from a dead endpoint.
    global_run(
        "curl -4 -fsS -o /dev/null --connect-timeout 5 --max-time 15 https://pypi.org",
        timeout=20,
    )
    global_run(
        "curl -4 -fsS -o /dev/null --connect-timeout 5 --max-time 15 https://github.com",
        timeout=20,
    )
    global_run(f"{zaigr} global base-image setup run network-base", timeout=180)
    stdout, stderr, rc = _run(
        f"{zaigr} global base-image setup run network-failure",
        cwd=tmp_path,
        env=customized.env,
        timeout=180,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert "network-failure" in stdout + stderr
    assert "FAILED_SETUP_NETWORK_SUCCEEDED" in stdout
    run(f"{zaigr} project vm start", input="y\n", timeout=180)
    run(
        f"{zaigr} project vm exec -- curl -4 -fsS -o /dev/null --connect-timeout 5 --max-time 15 https://pypi.org",
        timeout=20,
    )
    stdout, stderr, rc = _run(
        f"{zaigr} project vm exec -- curl -4 -fsS -o /dev/null --connect-timeout 3 --max-time 8 https://github.com",
        cwd=customized.cwd,
        env=customized.env,
        timeout=20,
    )
    assert rc != 0, err_msg(stdout, stderr)
    applied = run(f"{zaigr} project setup list --applied", timeout=10)
    assert "network-base" in applied
    assert "network-failure" not in applied

    global_run(f"{zaigr} global base-image reset", timeout=30)
    run_factory(f"{zaigr} project vm start", input="y\n", timeout=180)
    stdout, stderr, rc = _run(
        f"{zaigr} project vm exec -- curl -4 -fsS -o /dev/null --connect-timeout 3 --max-time 8 https://pypi.org",
        cwd=factory.cwd,
        env=factory.env,
        timeout=20,
    )
    assert rc != 0, err_msg(stdout, stderr)
    run(
        f"{zaigr} project vm exec -- curl -4 -fsS -o /dev/null --connect-timeout 5 --max-time 15 https://pypi.org",
        timeout=20,
    )
    run_factory(f"{zaigr} project vm exec -- printf 'FACTORY_EXEC_OK\\n'", timeout=20)


@pytest.mark.timeout(600)
def test_handled_interruption_preserves_last_base_and_allows_recovery(
    project_factory, setup_factory, probe_script, tmp_path
):
    """SIGTERM after a staged write never publishes it or poisons the next update."""
    prior = project_factory("interruption-prior")
    recovered = project_factory("interruption-recovered")
    zaigr = prior.zaigr_bin
    run = partial(_checked_run, env=prior.env)
    global_run = partial(run, cwd=tmp_path)
    setup_factory("base-probe", probe_script)
    setup_factory(
        "after-interruption", "printf 'recovered\\n' > /etc/after-interruption"
    )
    setup_factory(
        "interrupt-me",
        "printf 'partial\\n' > /etc/interrupted-partial\n"
        "printf 'GLOBAL_INTERRUPTION_READY\\n'\nsleep 300\n",
    )
    global_run(f"{zaigr} global base-image setup run base-probe", timeout=180)
    run(f"{zaigr} project vm start", cwd=prior.cwd, input="y\n", timeout=180)
    original = run(f"{zaigr} project vm exec -- base-probe", cwd=prior.cwd, timeout=20)
    status_before = global_run(f"{zaigr} global base-image status", timeout=10)
    projects_before = _stable_project_listing(
        global_run(f"{zaigr} global projects list --full-paths", timeout=10)
    )

    update = spawn_interactive(
        f"{zaigr} global base-image setup run interrupt-me",
        cwd=tmp_path,
        env=prior.env,
        timeout=180,
    )
    try:
        update.expect_exact("GLOBAL_INTERRUPTION_READY", timeout=120)
        assert (
            _stable_project_listing(
                global_run(f"{zaigr} global projects list --full-paths", timeout=10)
            )
            == projects_before
        )
        # Signalling the live CLI is the behavior under test, and is transcripted.
        global_run(["kill", f"-{signal.SIGTERM.value}", str(update.pid)], timeout=10)
        update.expect(pexpect.EOF, timeout=60)
        update.close()
        assert update.exitstatus != 0 or update.signalstatus is not None
    finally:
        if update.isalive():
            update.close(force=True)

    interrupted_status = global_run(f"{zaigr} global base-image status", timeout=10)
    assert (
        next(line for line in status_before.splitlines() if "base-probe" in line)
        in interrupted_status
    )
    assert "interrupt-me" not in interrupted_status
    assert (
        _stable_project_listing(
            global_run(f"{zaigr} global projects list --full-paths", timeout=10)
        )
        == projects_before
    )
    global_run(f"{zaigr} global base-image setup run after-interruption", timeout=180)
    run(f"{zaigr} project vm start", cwd=recovered.cwd, input="y\n", timeout=180)
    assert (
        run(f"{zaigr} project vm exec -- base-probe", cwd=recovered.cwd, timeout=20)
        == original
    )
    run(
        f"{zaigr} project vm exec -- test ! -e /etc/interrupted-partial",
        cwd=recovered.cwd,
        timeout=20,
    )
    assert (
        run(
            f"{zaigr} project vm exec -- cat /etc/after-interruption",
            cwd=recovered.cwd,
            timeout=20,
        ).strip()
        == "recovered"
    )


@pytest.mark.timeout(600)
def test_concurrent_global_updates_and_creation_select_complete_revisions(
    project_factory, setup_factory, probe_script, tmp_path
):
    """Competing updates serialize or reject clearly; a new project gets one revision."""
    during = project_factory("created-during-update")
    final = project_factory("created-after-updates")
    zaigr = during.zaigr_bin
    run = partial(_checked_run, env=during.env)
    global_run = partial(run, cwd=tmp_path)
    setup_factory("base-probe", probe_script)
    setup_factory(
        "concurrent-first",
        "printf 'first\\n' > /etc/concurrent-first\n",
    )
    setup_factory(
        "concurrent-finish",
        "test -f /etc/concurrent-first\n"
        "printf 'GLOBAL_CONCURRENCY_READY\\n'\n"
        "sleep 15\n"
        "printf 'complete\\n' > /etc/concurrent-complete\n",
    )
    setup_factory(
        "concurrent-second",
        "test -f /etc/concurrent-complete\nprintf 'second\\n' > /etc/concurrent-second",
    )
    global_run(f"{zaigr} global base-image setup run base-probe", timeout=180)
    update = spawn_interactive(
        f"{zaigr} global base-image setup run concurrent-first concurrent-finish",
        cwd=tmp_path,
        env=during.env,
        timeout=180,
    )
    try:
        # Pause the later batch step: no earlier step may be published by itself.
        # The sentinel confirms a mutation is active; sleep only holds its window.
        update.expect_exact("GLOBAL_CONCURRENCY_READY", timeout=120)
        with ThreadPoolExecutor(max_workers=2) as workers:
            competing = workers.submit(
                _run,
                f"{zaigr} global base-image setup run concurrent-second",
                cwd=tmp_path,
                env=during.env,
                timeout=240,
            )
            creation = workers.submit(
                _run,
                f"{zaigr} project vm start",
                cwd=during.cwd,
                env=during.env,
                input="y\n",
                timeout=240,
            )
            stdout, stderr, rc = creation.result(timeout=250)
            assert rc == 0, err_msg(stdout, stderr)
            competing_stdout, competing_stderr, competing_rc = competing.result(
                timeout=250
            )
        update.expect(pexpect.EOF, timeout=60)
        update.close()
        assert update.exitstatus == 0
    finally:
        if update.isalive():
            update.close(force=True)

    if competing_rc != 0:
        assert re.search(
            r"(busy|locked|another|running)",
            competing_stdout + competing_stderr,
            re.IGNORECASE,
        )
        global_run(
            f"{zaigr} global base-image setup run concurrent-second", timeout=180
        )
    during_probe = run(
        f"{zaigr} project vm exec -- base-probe", cwd=during.cwd, timeout=20
    )
    _assert_probe(during_probe, 1)
    applied = run(f"{zaigr} project setup list --applied", cwd=during.cwd, timeout=10)
    if "concurrent-first" in applied:
        assert "concurrent-finish" in applied
        assert (
            run(
                f"{zaigr} project vm exec -- cat /etc/concurrent-first",
                cwd=during.cwd,
                timeout=20,
            ).strip()
            == "first"
        )
        assert (
            run(
                f"{zaigr} project vm exec -- cat /etc/concurrent-complete",
                cwd=during.cwd,
                timeout=20,
            ).strip()
            == "complete"
        )
    else:
        assert "concurrent-finish" not in applied
        run(
            f"{zaigr} project vm exec -- test ! -e /etc/concurrent-first",
            cwd=during.cwd,
            timeout=20,
        )
        run(
            f"{zaigr} project vm exec -- test ! -e /etc/concurrent-complete",
            cwd=during.cwd,
            timeout=20,
        )
    if "concurrent-second" in applied:
        assert "concurrent-first" in applied
        assert (
            run(
                f"{zaigr} project vm exec -- cat /etc/concurrent-second",
                cwd=during.cwd,
                timeout=20,
            ).strip()
            == "second"
        )
    else:
        run(
            f"{zaigr} project vm exec -- test ! -e /etc/concurrent-second",
            cwd=during.cwd,
            timeout=20,
        )

    run(f"{zaigr} project vm start", cwd=final.cwd, input="y\n", timeout=180)
    assert (
        run(f"{zaigr} project vm exec -- base-probe", cwd=final.cwd, timeout=20)
        == during_probe
    )
    assert (
        run(
            f"{zaigr} project vm exec -- cat /etc/concurrent-first",
            cwd=final.cwd,
            timeout=20,
        ).strip()
        == "first"
    )
    assert (
        run(
            f"{zaigr} project vm exec -- cat /etc/concurrent-complete",
            cwd=final.cwd,
            timeout=20,
        ).strip()
        == "complete"
    )
    assert (
        run(
            f"{zaigr} project vm exec -- cat /etc/concurrent-second",
            cwd=final.cwd,
            timeout=20,
        ).strip()
        == "second"
    )
    applied = run(f"{zaigr} project setup list --applied", cwd=final.cwd, timeout=10)
    assert "base-probe" in applied
    assert "concurrent-first" in applied
    assert "concurrent-finish" in applied
    assert "concurrent-second" in applied


@pytest.mark.timeout(600)
def test_capture_accept_preserves_pinned_base_after_global_reset(
    project, setup_factory, probe_script, tmp_path
):
    """Capturing and compacting project changes cannot silently switch its base."""
    zaigr = project.zaigr_bin
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    global_run = partial(_checked_run, cwd=tmp_path, env=project.env)
    setup_factory("base-probe", probe_script)
    global_run(f"{zaigr} global base-image setup run base-probe", timeout=180)
    run(f"{zaigr} project vm start", input="y\n", timeout=180)
    original = run(f"{zaigr} project vm exec -- base-probe", timeout=20)
    installation_id = _assert_probe(original, 1)
    run(
        f"{zaigr} project vm exec -- tee /home/user/before-capture",
        input="before-capture\n",
        timeout=20,
    )
    run(f"{zaigr} project vm stop", timeout=60)
    global_run(f"{zaigr} global base-image reset", timeout=30)

    capture = spawn_interactive(
        f"{zaigr} project setup capture start",
        cwd=project.cwd,
        env=project.env,
        timeout=180,
    )
    try:
        capture.expect(r"root@[^:]+:.*# ", timeout=180)
        # These commands are intentionally interactive: recording is the feature.
        capture.sendline("base-probe")
        capture.expect_exact(installation_id, timeout=20)
        capture.expect(r"root@[^:]+:.*# ", timeout=20)
        capture.sendline("printf 'captured-content\\n' > /etc/captured-content")
        capture.expect(r"root@[^:]+:.*# ", timeout=20)
        review = run(f"{zaigr} project setup capture review", timeout=20)
        assert "captured-content" in review
        run(f"{zaigr} project setup capture accept", timeout=180)
        capture.expect(pexpect.EOF, timeout=30)
        capture.close()
    finally:
        if capture.isalive():
            capture.close(force=True)

    run(f"{zaigr} project vm start", timeout=180)
    assert run(f"{zaigr} project vm exec -- base-probe", timeout=20) == original
    assert (
        run(f"{zaigr} project vm exec -- cat /etc/captured-content", timeout=20).strip()
        == "captured-content"
    )
    assert (
        run(
            f"{zaigr} project vm exec -- cat /home/user/before-capture", timeout=20
        ).strip()
        == "before-capture"
    )
    assert (
        "factory" in global_run(f"{zaigr} global base-image status", timeout=10).lower()
    )
