"""CLI tests for project initialization, VM lifecycle, setup state, and shell access."""

from functools import partial
from pathlib import Path
import socket
import re
import time

import pexpect
import pytest

from ..conftest import REPO_ROOT, err_msg, run as _run, spawn_interactive

run = _run


USER_PROMPT = r"user@[^:]+:.*[$] "
ROOT_PROMPT = r"root@[^:]+:.*# "
ROOT_DIRTY_PROMPT = r"Accessing this VM as root automatically marks the project image dirty\."
ROOT_DIRTY_CONFIRM_PROMPT = r"Continue with root shell\? \[y/N\]"
ROOT_EXEC_CONFIRM_TEXT = "Continue with root exec? [y/N]"
ACTIVE_CAPTURE_PREVIEW_CHOICE = r"Choose: \[d\] discard active and start anew, \[c\] continue appending, \[Enter\] cancel"


def _project_images(project):
    return sorted(
        path.name
        for path in project.store_dir.iterdir()
        if path.name.startswith("image-") and path.suffix in {".img", ".qcow2"}
    )


def _completion_entries(output):
    entries = []
    directive = None
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith(":"):
            directive = line
            continue
        entries.append(line.split("\t", 1)[0])
    return entries, directive


def _checked_run(cmd, **kwargs):
    stdout, stderr, rc = _run(cmd, **kwargs)
    assert rc == 0, err_msg(stdout, stderr)
    return stdout


def _section_lines(text, heading, next_heading):
    start = text.index(heading) + len(heading)
    end = text.index(next_heading, start)
    return [
        line.strip()
        for line in text[start:end].splitlines()
        if line.strip() and line.strip() != "(none)"
    ]


def _section_contains(text, heading, next_heading, expected):
    try:
        return expected in _section_lines(text, heading, next_heading)
    except ValueError:
        return False


def _assert_active_capture_refusal(stdout, stderr, rc, command):
    combined = stdout + stderr
    assert rc != 0, combined
    assert "project setup capture is active" in combined
    assert f"before running {command}" in combined
    assert "zaigr project setup capture accept" in combined
    assert "zaigr project setup capture discard" in combined


def test_project_vm_start_creates_project_store_and_first_image(project):
    """`project vm start` initializes a project store and creates the first project image."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    run(f"{zaigr} project vm start", input="y\n", timeout=120)

    assert project.store_dir.is_dir()
    assert len(_project_images(project)) == 1

    stdout = run(f"{zaigr} project vm show-config")
    assert stdout.strip().splitlines() == ["cpu=1", "ram=512MB"]


def test_project_vm_start_waits_for_minimal_systemd_runtime(project):
    """`project vm start` returns after the minimal systemd runtime is ready."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    run(f"{zaigr} project vm start", input="y\n", timeout=180)

    pid1 = run(f"{zaigr} project vm exec -- ps -p 1 -o comm=", timeout=20)
    assert pid1.strip() == "systemd"

    run(f"{zaigr} project vm exec -- pgrep -x opensnitchd", timeout=20)
    run(f"{zaigr} project vm exec -- mountpoint -q /home/user/workspace", timeout=20)
    run(
        f"{zaigr} project vm exec -- mountpoint -q /home/user/.zaigr-agent-state",
        timeout=20,
    )

    runtime_dir = run(
        f"{zaigr} project vm exec -- stat -c %U:%G:%a /run/user/1000",
        timeout=20,
    )
    assert runtime_dir.strip() == "user:user:700"

    kvm_state = run(
        f"{zaigr} project vm exec -- stat -c %U:%G:%a /dev/kvm",
        timeout=20,
    )
    assert kvm_state.strip() == "root:kvm:660"
    run(f"{zaigr} project vm exec -- test -r /dev/kvm -a -w /dev/kvm", timeout=20)
    run(
        f"{zaigr} project vm exec -- sh -c "
        "'! command -v dbus-daemon >/dev/null 2>&1 && ! pgrep -x dbus-daemon >/dev/null 2>&1'",
        timeout=20,
    )


def test_project_vm_start_returns_after_systemd_boot_hooks_complete(project, setup_factory):
    """`project vm start` only returns after systemd has completed zaigr boot hooks."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    setup_factory(
        setup_name="systemd-boot-hook-readiness",
        script_content=r"""
mkdir -p /etc/zaigr/boot.d
cat > /etc/zaigr/boot.d/20-readiness-test <<'EOF'
#!/bin/bash
set -eu
printf 'boot-hook-ready\n' > /run/zaigr-boot-hook-ready
EOF
chmod 0755 /etc/zaigr/boot.d/20-readiness-test
""",
    )

    run(
        f"{zaigr} project setup run systemd-boot-hook-readiness",
        input="y\n",
        timeout=180,
    )
    run(f"{zaigr} project vm stop")

    run(
        f"{zaigr} project vm start",
        timeout=120,
    )

    output = run(
        f"{zaigr} project vm exec -- cat /run/zaigr-boot-hook-ready"
    )
    assert output.strip() == "boot-hook-ready"


@pytest.mark.timeout(240)
def test_shell_from_child_directory_can_use_initialized_parent_project(project):
    """Nested `zaigr shell` can use the initialized parent project."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    (project.cwd / "parent-marker.txt").write_text("parent\n", encoding="utf-8")

    run(f"{zaigr} project vm start", input="y\n", timeout=120)

    child_dir = project.cwd / "bob"
    child_dir.mkdir()
    (child_dir / "child-marker.txt").write_text("child\n", encoding="utf-8")

    shell = spawn_interactive(
        f"{project.zaigr_bin} shell",
        cwd=child_dir,
        env=project.env,
        timeout=180,
    )
    try:
        shell.expect(r"A zaigr project is already initialized for a parent directory")
        shell.expect(re.escape(str(project.cwd)))
        shell.expect(re.escape(str(child_dir)))
        shell.expect(r"Action \[c/p/n\]:")
        shell.sendline("p")
        shell.expect(USER_PROMPT)
        shell.sendline(
            "if [ -f parent-marker.txt ] && [ -d bob ] && [ ! -f child-marker.txt ]; then "
            "printf 'WORKSPACE_ROOT=parent\\n'; "
            "else printf 'WORKSPACE_ROOT=child\\n'; fi"
        )
        shell.expect(r"WORKSPACE_ROOT=parent")
        shell.expect(USER_PROMPT)
        shell.sendline("exit")
        shell.expect(r"\Z")
    finally:
        shell.close(force=True)


@pytest.mark.timeout(240)
def test_project_vm_clock_heals_on_boot(project):
    """A project VM boot resets a bad guest clock to host launch time."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    wrong_epoch = 946684800  # 2000-01-01T00:00:00Z

    run(f"{zaigr} project vm start", input="y\n", timeout=180)
    bad_epoch_text = run(
        [
            zaigr,
            "project",
            "vm",
            "exec",
            "--root",
            "--",
            "bash",
            "-lc",
            f"date -u -s '@{wrong_epoch}' >/dev/null && date -u +%s",
        ],
        input="y\n",
        timeout=180,
    )
    bad_epoch = int(bad_epoch_text.strip())

    assert wrong_epoch <= bad_epoch <= wrong_epoch + 60

    stdout, stderr, rc = _run(
        f"{project.zaigr_bin} project vm stop",
        cwd=project.cwd,
        env=project.env,
        timeout=30,
    )
    if rc != 0:
        assert "project VM is not running" in stdout + stderr, err_msg(stdout, stderr)

    host_epoch_before_reboot = int(time.time())
    run(f"{zaigr} project vm start", timeout=180)
    healed_epoch_text = run(f"{zaigr} project vm exec -- date -u +%s")
    healed_epoch = int(healed_epoch_text.strip())
    host_epoch_after_read = int(time.time())

    one_year = 365 * 24 * 60 * 60
    assert abs(healed_epoch - wrong_epoch) > one_year, (
        f"guest clock {healed_epoch} was still near the deliberately wrong time {wrong_epoch}"
    )
    assert host_epoch_before_reboot - 60 <= healed_epoch <= host_epoch_after_read + 60, (
        f"guest clock {healed_epoch} was outside host reboot window "
        f"{host_epoch_before_reboot}..{host_epoch_after_read}"
    )



@pytest.mark.timeout(240)
def test_setup_firewall_is_shown_and_allows_host_access(project, setup_factory):
    """Setup firewall entries are shown and allow access from the project VM."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    setup_factory(
        setup_name="debian-access",
        script_content="true",
        firewall=["deb.debian.org"],
    )

    run(
        f"{zaigr} project setup run debian-access",
        input="y\n",
        timeout=120,
    )

    stdout = run(
        f"{zaigr} project firewall show",
        timeout=10,
    )

    assert "# debian-access" in stdout
    assert "deb.debian.org" in stdout

    run(
        f"{zaigr} project vm exec -- curl -4 -sS -o /dev/null "
        "--connect-timeout 3 --max-time 3 http://deb.debian.org",
        timeout=30,
    )


@pytest.mark.timeout(300)
def test_project_firewall_show_uses_temporary_vm_and_reads_vm_allowed_file(project):
    """`project firewall show` reads the VM allowlist, not host-side cache metadata."""
    run = partial(_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    started, stderr, rc = run(
        f"{zaigr} project vm start",
        input="y\n",
        timeout=180,
    )
    assert rc == 0, err_msg(started, stderr)

    append, stderr, rc = run(
        [
            zaigr,
            "project",
            "vm",
            "exec",
            "--root",
            "--",
            "tee",
            "-a",
            "/etc/opensnitchd/lists/domains/allowed.txt",
        ],
        input="y\nmanual-vm-entry.example\n",
        timeout=30,
    )
    assert rc == 0, err_msg(append, stderr)
    assert ROOT_EXEC_CONFIRM_TEXT in stderr
    assert "manual-vm-entry.example" in append

    sync, stderr, rc = run(
        f"{zaigr} project vm exec --root -- sync",
        input="y\n",
        timeout=30,
    )
    assert rc == 0, err_msg(sync, stderr)
    assert ROOT_EXEC_CONFIRM_TEXT in stderr

    stopped, stderr, rc = run(
        f"{zaigr} project vm stop",
        timeout=30,
    )
    assert rc == 0, err_msg(stopped, stderr)

    # No public workflow creates a stale host cache; seed one to verify VM state wins.
    # Seed stale host cache metadata directly; the public behavior under test is
    # that `project firewall show` ignores it and reads the stopped VM image.
    (project.store_dir / "firewall").write_text("cache-only-entry.example\n", encoding="utf-8")

    firewall, stderr, rc = run(
        f"{zaigr} project firewall show",
        timeout=180,
    )

    assert rc == 0, err_msg(firewall, stderr)
    assert "booting temporary VM to read firewall" in stderr
    assert "Start project VM and show firewall? [y/N]" not in stderr
    assert "manual-vm-entry.example" in firewall
    assert "cache-only-entry.example" not in firewall
    status_after, stderr, rc = run(
        f"{zaigr} project status",
        timeout=10,
    )
    assert rc == 0, err_msg(status_after, stderr)
    assert "status: not running" in status_after


@pytest.mark.timeout(240)
def test_project_firewall_domain_log_requires_running_vm(project):
    """`project firewall domain-log` is present and fails clearly when the VM is stopped."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    help_output = run(
        f"{zaigr} project firewall --help",
        timeout=10,
    )
    assert "domain-log" in help_output

    run(
        f"{zaigr} project vm start",
        input="y\n",
        timeout=180,
    )

    run(
        f"{zaigr} project vm stop",
        timeout=60,
    )

    stdout, stderr, rc = _run(
        f"{zaigr} project firewall domain-log",
        cwd=project.cwd,
        env=project.env,
        timeout=10,
    )

    assert rc != 0
    combined = stdout + stderr
    assert "project VM is not running" in combined
    assert "zaigr project vm start" in combined


@pytest.mark.timeout(360)
def test_zaigr_inside_firewall_remove_blocks_removed_domain(project):
    """`zaigr-inside firewall remove` removes allow entries and blocks new access."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    test_domain = "deb.debian.org"
    cname_domain = "debian.map.fastlydns.net"
    test_url = "http://deb.debian.org"
    blocked_curl_status = "28"

    run(
        f"{zaigr} project vm start",
        input="y\n",
        timeout=180,
    )
    run(
        [
            zaigr,
            "project",
            "vm",
            "exec",
            "--",
            "sh",
            "-lc",
            "command -v curl && command -v getent",
        ],
        timeout=20,
    )
    run(
        [zaigr, "project", "vm", "exec", "--", "getent", "ahosts", test_domain],
        timeout=20,
    )
    run(
        f"{zaigr} project vm exec -- curl -4 -fsS -o /dev/null "
        f"--connect-timeout 3 --max-time 8 {test_url}",
        timeout=20,
    )

    allow_before = run(
        [zaigr, "project", "vm", "exec", "--root", "--", "zaigr-inside", "firewall", "list"],
        input="y\n",
        timeout=30,
    )
    assert test_domain in allow_before.splitlines()
    assert cname_domain in allow_before.splitlines()

    run(
        [
            zaigr,
            "project",
            "vm",
            "exec",
            "--root",
            "--",
            "zaigr-inside",
            "firewall",
            "remove",
            test_domain,
            cname_domain,
        ],
        input="y\n",
        timeout=30,
    )

    allow_after_remove = run(
        [zaigr, "project", "vm", "exec", "--root", "--", "zaigr-inside", "firewall", "list"],
        input="y\n",
        timeout=30,
    )
    assert test_domain not in allow_after_remove.splitlines()
    assert cname_domain not in allow_after_remove.splitlines()

    rc = None
    for _ in range(12):
        removed, stderr, rc = _run(
            f"{zaigr} project vm exec -- curl -4 -fsS -o /dev/null "
            f"--connect-timeout 3 --max-time 8 {test_url}",
            cwd=project.cwd,
            env=project.env,
            timeout=20,
        )
        if rc == int(blocked_curl_status):
            break
        time.sleep(1)
    assert rc == int(blocked_curl_status), err_msg(removed, stderr)

    run(
        [
            zaigr,
            "project",
            "vm",
            "exec",
            "--root",
            "--",
            "zaigr-inside",
            "firewall",
            "allow",
            test_domain,
            cname_domain,
        ],
        input="y\n",
        timeout=30,
    )

    allow_after_restore = run(
        [zaigr, "project", "vm", "exec", "--root", "--", "zaigr-inside", "firewall", "list"],
        input="y\n",
        timeout=30,
    )
    assert test_domain in allow_after_restore.splitlines()
    assert cname_domain in allow_after_restore.splitlines()


def test_project_vm_help_exposes_nested_commands(project, tmp_path):
    """VM lifecycle/config actions live under `project vm` only."""
    run = partial(_checked_run, cwd=tmp_path, env=project.env)
    zaigr = project.zaigr_bin

    root = run(
        f"{zaigr} --help",
        timeout=10,
    )
    assert "\n  project" in root

    project_output = run(
        f"{zaigr} project --help",
        timeout=10,
    )
    assert "\n  vm " in project_output

    vm_output = run(
        f"{zaigr} project vm --help",
        timeout=10,
    )
    for command in ["start", "stop", "show-config", "set-config"]:
        assert command in vm_output


def test_project_vm_completion_exposes_nested_commands(project, tmp_path):
    """Shell completion follows the nested `project vm` command tree."""
    run = partial(_checked_run, cwd=tmp_path, env=project.env)
    zaigr = project.zaigr_bin

    project_output = run(
        [zaigr, "__complete", "project", ""],
        timeout=10,
    )
    project_entries, project_directive = _completion_entries(project_output)
    assert "vm" in project_entries
    assert project_directive == ":4"

    vm_output = run(
        [zaigr, "__complete", "project", "vm", ""],
        timeout=10,
    )
    vm_entries, vm_directive = _completion_entries(vm_output)
    for command in ["start", "stop", "show-config", "set-config"]:
        assert command in vm_entries
    assert vm_directive == ":4"

    prefix = run(
        [zaigr, "__complete", "project", "vm", "s"],
        timeout=10,
    )
    prefix_entries, prefix_directive = _completion_entries(prefix)
    for command in ["start", "stop", "show-config", "set-config"]:
        assert command in prefix_entries
    assert prefix_directive == ":4"


def test_global_projects_status_lists_stores_with_compact_and_full_paths(project, tmp_path):
    """`global projects status` lists project stores with compact paths by default."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    run(f"{zaigr} project vm start", input="y\n", timeout=120)
    run(f"{zaigr} project vm stop")
    store_dir = project.store_dir

    stdout = run(
        f"{project.zaigr_bin} global projects status",
        timeout=10,
    )
    assert "STORE" in stdout
    assert "VM" in stdout
    assert "PROJECT" in stdout
    assert store_dir.name in stdout
    assert "off" in stdout
    assert "1" in stdout
    assert "512MB" in stdout
    assert project.cwd.name in stdout

    full = run(
        f"{project.zaigr_bin} global projects status --full-paths",
        timeout=10,
    )
    assert str(project.cwd) in full


def test_global_projects_status_explains_stale_runtime_state(project):
    """`global projects status` tells users how to clear stale VM runtime state."""
    run = partial(_run, cwd=project.cwd, env=project.env)
    store_dir = project.store_dir
    store_dir.mkdir(parents=True, exist_ok=True)
    (store_dir / "project-path").write_text(f"{project.cwd}\n", encoding="utf-8")
    (store_dir / "ram").write_text("512\n", encoding="utf-8")
    (store_dir / "cpus").write_text("1\n", encoding="utf-8")
    (store_dir / "config").write_text("disk=100G\n", encoding="utf-8")
    runtime_dir = store_dir / "runtime"
    runtime_dir.mkdir()
    (runtime_dir / "vm.sock").write_text("stale\n", encoding="utf-8")

    stdout, stderr, rc = run(
        f"{project.zaigr_bin} global projects status",
        timeout=10,
    )

    assert rc == 0, err_msg(stdout, stderr)
    assert store_dir.name in stdout
    assert "stale" in stdout
    assert f"project {store_dir.name} has leftover VM runtime state" in stderr
    assert f"zaigr global projects kill {store_dir.name}" in stderr
    assert "stale project VM monitor marker found" not in stderr
    assert "vm.sock" not in stderr


@pytest.mark.timeout(180)
def test_global_projects_details_prints_project_store_state(project, tmp_path, setup_factory):
    """`global projects details` prints full state for the requested project store."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    setup_factory(
        setup_name="details-firewall",
        script_content="true",
        firewall=["api.github.com"],
    )
    run(
        f"{zaigr} project setup run details-firewall",
        input="y\n",
        timeout=120,
    )
    run(
        f"{zaigr} project vm stop",
        timeout=30,
    )
    store_dir = project.store_dir

    run = partial(_checked_run, cwd=tmp_path, env=project.env)
    stdout = run(
        f"{zaigr} global projects details {store_dir.name}",
        timeout=10,
    )
    assert f"project: {project.cwd}" in stdout
    assert f"store-path: {store_dir}" in stdout
    assert "store-name:" not in stdout
    assert "vm-hostname:" not in stdout
    assert "vm:\n  status: not running" in stdout
    assert "  config: cpu=1, ram=512MB, disk=100G" in stdout
    assert "active-shells: 0" in stdout
    assert "committed to project image (1):" in stdout
    assert "details-firewall" in stdout
    assert "firewall entries (1):" in stdout
    assert "api.github.com" in stdout


def test_project_status_uses_store_path_and_grouped_vm_output(project):
    """`project status` renders store and VM state without hostname/store-name noise."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    run(f"{zaigr} project vm start", input="y\n", timeout=120)
    run(f"{zaigr} project vm stop")
    store_dir = project.store_dir

    stdout = run(
        f"{project.zaigr_bin} project status",
        timeout=10,
    )
    assert f"store-path: {store_dir}" in stdout
    assert "store-name:" not in stdout
    assert "vm-hostname:" not in stdout
    assert "vm:\n  status: not running" in stdout
    assert "  config: cpu=1, ram=512MB" in stdout
    assert "setups:\n  committed to project image (0):" in stdout


def test_project_delete_prompts_default_no_and_keeps_store(project):
    """`project delete` defaults to keeping the project store."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    run(f"{zaigr} project vm start", input="y\n", timeout=120)
    run(f"{zaigr} project vm stop")
    store_dir = project.store_dir

    stdout, stderr, rc = _run(
        f"{project.zaigr_bin} project delete",
        cwd=project.cwd,
        env=project.env,
        input="\n",
        timeout=10,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert f"Delete project store {store_dir}?" in stderr
    assert ":: Project delete cancelled" in stderr
    assert store_dir.is_dir()

    status = run(
        f"{project.zaigr_bin} project status",
        timeout=10,
    )
    assert f"store-path: {store_dir}" in status


def test_project_delete_force_removes_project_store(project):
    """`project delete --force` removes the current project store."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    run(f"{zaigr} project vm start", input="y\n", timeout=120)
    run(f"{zaigr} project vm stop")
    store_dir = project.store_dir

    stdout = run(
        f"{project.zaigr_bin} project delete --force",
        timeout=10,
    )
    assert f":: Deleted project store: {store_dir}" in stdout
    assert not store_dir.exists()

    status, stderr, rc = _run(
        f"{project.zaigr_bin} project status",
        cwd=project.cwd,
        env=project.env,
        timeout=10,
    )
    assert rc != 0
    assert "project status requires a project" in (status + stderr)


def test_global_projects_hash_completion_shows_project_paths(project, tmp_path):
    """Hash arguments complete to store hashes while displaying project paths."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    run(f"{zaigr} project vm start", input="y\n", timeout=120)
    store_dir = project.store_dir
    prefix = store_dir.name[:3]

    stdout = run(
        [project.zaigr_bin, "__complete", "global", "projects", "details", prefix],
        timeout=10,
    )
    assert f"{store_dir.name}\t{project.cwd}" in stdout
    assert ":4" in stdout

    kill = run(
        [project.zaigr_bin, "__complete", "global", "projects", "kill", prefix],
        timeout=10,
    )
    assert f"{store_dir.name}\t{project.cwd}" in kill
    assert ":4" in kill


def test_global_projects_kill_clears_stale_runtime_state(project, tmp_path):
    """`global projects kill` clears stale runtime markers for selected stores."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    run(f"{zaigr} project vm start", input="y\n", timeout=120)
    run(f"{zaigr} project vm stop")
    store_dir = project.store_dir
    runtime_dir = store_dir / "runtime"
    runtime_dir.mkdir(exist_ok=True)
    (runtime_dir / "vm.sock").write_text("stale\n", encoding="utf-8")

    stdout = run(
        f"{project.zaigr_bin} global projects kill {store_dir.name}",
        timeout=10,
    )
    assert f"{store_dir.name}: cleared stale runtime state" in stdout
    assert not runtime_dir.exists()


@pytest.mark.timeout(180)
def test_directory_setup_definition_is_loaded(project):
    """Setups in the directory layout are discovered and executed."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    setup_dir = project.home / ".zaigr" / "setups" / "directory-setup"
    setup_dir.mkdir(parents=True, exist_ok=True)
    (setup_dir / "00-main.script").write_text(
        "printf 'directory-setup-run\\n'\n",
        encoding="utf-8",
    )

    setup = run(
        f"{project.zaigr_bin} project setup run directory-setup",
        input="y\n",
        timeout=120,
    )

    assert "directory-setup-run" in setup
    assert "setup not found" not in setup.lower()


@pytest.mark.timeout(180)
def test_directory_setup_runs_multiple_script_files_in_lexical_order(project):
    """Multiple `*.script` files are concatenated in lexical order."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    setup_dir = project.home / ".zaigr" / "setups" / "multi-script-setup"
    setup_dir.mkdir(parents=True, exist_ok=True)
    (setup_dir / "20-second.script").write_text(
        "printf 'setup-marker-two\\n'\n",
        encoding="utf-8",
    )
    (setup_dir / "10-first.script").write_text(
        "printf 'setup-marker-one\\n'\n",
        encoding="utf-8",
    )

    setup = run(
        f"{project.zaigr_bin} project setup run multi-script-setup",
        input="y\n",
        timeout=120,
    )

    first_index = setup.find("setup-marker-one")
    second_index = setup.find("setup-marker-two")
    assert first_index != -1
    assert second_index != -1
    assert first_index < second_index


@pytest.mark.timeout(180)
def test_directory_setup_merges_multiple_firewall_files(project):
    """Multiple `*.firewall` files are merged into project firewall state."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    setup_dir = project.home / ".zaigr" / "setups" / "multi-firewall-setup"
    setup_dir.mkdir(parents=True, exist_ok=True)
    (setup_dir / "00-main.script").write_text(
        "printf 'multi-firewall-run\\n'\n",
        encoding="utf-8",
    )
    (setup_dir / "10-defaults.firewall").write_text(
        "alpha.example\n",
        encoding="utf-8",
    )
    (setup_dir / "20-extra.firewall").write_text(
        "beta.example\ngamma.example\n",
        encoding="utf-8",
    )

    run(
        f"{project.zaigr_bin} project setup run multi-firewall-setup",
        input="y\n",
        timeout=120,
    )

    firewall = run(
        f"{project.zaigr_bin} project firewall show",
        timeout=10,
    )
    assert "# multi-firewall-setup" in firewall
    assert "alpha.example" in firewall
    assert "beta.example" in firewall
    assert "gamma.example" in firewall


@pytest.mark.timeout(180)
def test_directory_setup_without_script_file_fails_loudly(project):
    """Setup references without a `*.script` file fail with a clear error."""
    run = partial(_run, cwd=project.cwd, env=project.env)
    setup_dir = project.home / ".zaigr" / "setups" / "missing-script-setup"
    setup_dir.mkdir(parents=True, exist_ok=True)
    (setup_dir / "10-only.firewall").write_text(
        "orphan.example\n",
        encoding="utf-8",
    )

    setup, stderr, rc = run(
        f"{project.zaigr_bin} project setup run missing-script-setup",
        input="y\n",
        timeout=120,
    )

    combined = (setup + stderr).lower()
    assert rc != 0
    assert "setup has no scripts: missing-script-setup" in combined


@pytest.mark.timeout(180)
def test_flat_setup_layout_is_not_accepted(project):
    """Legacy flat `setups/<name>.script` definitions are rejected."""
    run = partial(_run, cwd=project.cwd, env=project.env)
    flat_setup_dir = project.home / ".zaigr" / "setups"
    flat_setup_dir.mkdir(parents=True, exist_ok=True)
    (flat_setup_dir / "legacy-layout.script").write_text("printf 'legacy\\n'", encoding="utf-8")
    (flat_setup_dir / "legacy-layout.firewall").write_text("legacy.example\n", encoding="utf-8")

    setup, stderr, rc = run(
        f"{project.zaigr_bin} project setup run legacy-layout",
        input="y\n",
        timeout=120,
    )

    combined = (setup + stderr).lower()
    assert rc != 0
    assert "setup not found" in combined


def test_shell_reuses_running_project_and_skips_redundant_firewall_sync(project, setup_factory):
    """A second shell attach on a running VM should not re-sync committed firewall state."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    setup_factory(
        setup_name="shell-sync-stability",
        script_content="true",
        firewall=["example.org"],
    )

    run(
        f"{project.zaigr_bin} project setup run shell-sync-stability",
        input="y\n",
        timeout=120,
    )

    first_shell = spawn_interactive(
        f"{project.zaigr_bin} shell",
        cwd=project.cwd,
        env=project.env,
        timeout=120,
    )
    first_shell.expect(USER_PROMPT, timeout=120)
    first_shell.sendline(
        "stat -c '%Y' /etc/opensnitchd/lists/domains/allowed.txt | "
        "xargs printf 'FW_MTIME=%s\\n'"
    )
    first_shell.expect(r"FW_MTIME=(\d+)")
    first_mtime = int(first_shell.match.group(1))
    first_shell.sendline("exit")
    first_shell.expect(r"\Z")

    second_shell = spawn_interactive(
        f"{project.zaigr_bin} shell",
        cwd=project.cwd,
        env=project.env,
        timeout=120,
    )
    second_shell.expect(USER_PROMPT, timeout=120)
    second_shell.sendline(
        "stat -c '%Y' /etc/opensnitchd/lists/domains/allowed.txt | "
        "xargs printf 'FW_MTIME=%s\\n'"
    )
    second_shell.expect(r"FW_MTIME=(\d+)")
    second_mtime = int(second_shell.match.group(1))
    second_shell.sendline("exit")
    second_shell.expect(r"\Z")

    assert second_mtime == first_mtime


@pytest.mark.timeout(180)
def test_setup_run_uses_resource_flags_for_image_setup_and_boot(project, setup_factory):
    """`project setup run --ram/--cpu` sizes image setup and the boot after blank initialization."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    # Guest-visible RAM is lower than configured RAM because kernel/device overhead exists.
    setup_resource_probe_script = """
cpu_count="$(nproc)"
if [ "$cpu_count" != "2" ]; then
    printf 'setup-cpu=%s\\n' "$cpu_count" >&2
    exit 1
fi
ram_mb="$(awk '/MemTotal:/ { print int($2 / 1024) }' /proc/meminfo)"
if [ "$ram_mb" -lt "650" ]; then
    printf 'setup-ram=%s\\n' "$ram_mb" >&2
    exit 1
fi
printf 'setup-run-resources-ok\\n'
"""
    setup_factory(
        setup_name="setup-resource-check",
        script_content=setup_resource_probe_script,
    )
    setup_factory(setup_name="running-resource-reject", script_content="true")

    stdout = run(
        f"{zaigr} project setup run --ram 768 --cpu 2 setup-resource-check",
        input="y\n",
        timeout=150,
    )
    assert "setup-run-resources-ok" in stdout

    shown = run(f"{zaigr} project vm show-config")
    assert shown.strip().splitlines() == ["cpu=2", "ram=768MB"]

    boot_cpu = run(f"{zaigr} project vm exec -- nproc")
    assert boot_cpu.strip() == "2"
    boot_ram = run(
        [
            zaigr,
            "project",
            "vm",
            "exec",
            "--",
            "awk",
            "/MemTotal:/ {printf \"%d\\n\", int($2 / 1024)}",
            "/proc/meminfo",
        ]
    )
    assert int(boot_ram.strip()) >= 650

    setup, stderr, rc = _run(
        f"{zaigr} project setup run --ram 1024 running-resource-reject",
        cwd=project.cwd,
        env=project.env,
        timeout=30,
    )
    assert rc != 0
    assert "project vm is already running" in (setup + stderr).lower()
    assert "--ram and --cpu cannot be changed on a running vm" in (
        setup + stderr
    ).lower()


@pytest.mark.timeout(180)
def test_shell_setup_uses_shell_resource_flags_before_boot(project, setup_factory):
    """`shell --setup --ram/--cpu` sizes setup installation before the shell VM boots."""
    # Guest-visible RAM is lower than configured RAM because kernel/device overhead exists.
    setup_resource_probe_script = """
cpu_count="$(nproc)"
if [ "$cpu_count" != "2" ]; then
    printf 'setup-cpu=%s\\n' "$cpu_count" >&2
    exit 1
fi
ram_mb="$(awk '/MemTotal:/ { print int($2 / 1024) }' /proc/meminfo)"
if [ "$ram_mb" -lt "650" ]; then
    printf 'setup-ram=%s\\n' "$ram_mb" >&2
    exit 1
fi
printf 'shell-setup-resources-ok\\n'
"""
    setup_factory(
        setup_name="shell-resource-check",
        script_content=setup_resource_probe_script,
    )

    shell = spawn_interactive(
        f"{project.zaigr_bin} shell --setup shell-resource-check --ram 768 --cpu 2",
        cwd=project.cwd,
        env=project.env,
        timeout=180,
    )
    try:
        shell.expect(r"Initialize project and continue\? \[y/N\]")
        shell.sendline("y")
        shell.expect(r"shell-setup-resources-ok", timeout=150)
        shell.expect(USER_PROMPT, timeout=120)
        shell.sendline("printf 'BOOT_CPU=%s\\n' \"$(nproc)\"")
        shell.expect(r"BOOT_CPU=2")
        shell.expect(USER_PROMPT)
        shell.sendline("exit")
        shell.expect(r"\Z")
    finally:
        shell.close(force=True)


@pytest.mark.timeout(180)
def test_setup_install_uses_full_network_by_default(project, setup_factory):
    """Image setup installation uses unrestricted network access by default."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    setup_factory(
        setup_name="firewall-active",
        script_content="""
pgrep -x opensnitchd >/dev/null
curl -4 -fsS --connect-timeout 5 --max-time 10 https://github.com >/dev/null
printf 'setup-full-network\\n'
""",
        firewall=["deb.debian.org"],
    )

    stdout = run(
        f"{project.zaigr_bin} project setup run firewall-active",
        input="y\n",
        timeout=120,
    )

    assert "setup-full-network" in stdout


@pytest.mark.timeout(120)
def test_project_setup_run_works(project, setup_factory):
    """`project setup run` executes named setups."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    setup_factory(
        setup_name="basic-project-setup-run",
        script_content="printf 'project-setup-run-ok\\n'",
    )

    stdout = run(
        f"{zaigr} project setup run basic-project-setup-run",
        input="y\n",
        timeout=120,
    )

    assert "project-setup-run-ok" in stdout


@pytest.mark.timeout(120)
def test_project_setup_run_force_reruns_committed_setup(project, setup_factory):
    """`project setup run --force` reruns a setup that is already committed."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    setup_factory(
        setup_name="force-project-setup-run",
        script_content="printf 'force-project-setup-run-ok\\n'",
    )

    stdout = run(
        f"{zaigr} project setup run force-project-setup-run",
        input="y\n",
        timeout=120,
    )
    assert "force-project-setup-run-ok" in stdout

    skipped = run(
        f"{zaigr} project setup run force-project-setup-run",
        timeout=120,
    )
    assert (
        ":: Skipping setups already committed to the project image: force-project-setup-run"
        in skipped
    )
    assert "force-project-setup-run-ok" not in skipped

    forced = run(
        f"{zaigr} project setup run --force force-project-setup-run",
        timeout=120,
    )
    assert "force-project-setup-run-ok" in forced


@pytest.mark.timeout(360)
def test_project_setup_run_force_on_running_vm_replaces_committed_setup(
    project, setup_factory
):
    """Committing a forced setup rerun from a running VM replaces the committed record."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    (project.cwd / "force-running-mode").write_text("old\n", encoding="utf-8")
    setup_factory(
        setup_name="force-running-marker",
        script_content=(
            "mode=$(cat /home/user/workspace/force-running-mode)\n"
            "if [ \"$mode\" = \"new\" ]; then\n"
            "  printf 'FORCE_RUNNING_MARKER_V2_RAN\\n'\n"
            "  printf 'new\\n' > /etc/zaigr-force-running-new\n"
            "else\n"
            "  printf 'FORCE_RUNNING_MARKER_V1_RAN\\n'\n"
            "  printf 'old\\n' > /etc/zaigr-force-running-old\n"
            "fi"
        ),
    )

    first = run(
        f"{zaigr} project setup run force-running-marker",
        input="y\n",
        timeout=120,
    )
    assert "FORCE_RUNNING_MARKER_V1_RAN" in first

    run(
        f"{zaigr} project vm exec -- test -f /etc/zaigr-force-running-old",
        timeout=20,
    )

    (project.cwd / "force-running-mode").write_text("new\n", encoding="utf-8")

    forced = run(
        f"{zaigr} project setup run --force force-running-marker",
        timeout=60,
    )
    assert "FORCE_RUNNING_MARKER_V2_RAN" in forced
    assert "awaiting image commit" in forced

    run(f"{zaigr} project vm stop", timeout=60)

    shell = spawn_interactive(
        f"{zaigr} shell",
        cwd=project.cwd,
        env=project.env,
        timeout=240,
    )
    try:
        shell.expect(r"1 setup is awaiting image commit:")
        shell.expect(r"- force-running-marker")
        shell.expect(r"Action \[c/d\]:")
        shell.sendline("commit")
        shell.expect(r"Committed 1 setups to the project image", timeout=240)
        shell.expect(USER_PROMPT, timeout=240)
        shell.sendline(
            "if [ ! -e /etc/zaigr-force-running-old ] "
            "&& [ -f /etc/zaigr-force-running-new ]; then "
            "printf 'FORCE_REPLACEMENT_IMAGE_OK\\n'; "
            "else printf 'FORCE_REPLACEMENT_IMAGE_STALE\\n'; fi"
        )
        shell.expect(r"FORCE_REPLACEMENT_IMAGE_OK", timeout=20)
        shell.expect(USER_PROMPT, timeout=120)
        shell.sendline("exit")
        shell.expect(r"\Z", timeout=60)
    finally:
        shell.close(force=True)

    list_output = run(
        f"{zaigr} project setup list --committed",
        timeout=10,
    )
    assert "committed (1):" in list_output
    assert list_output.count("force-running-marker") == 1


@pytest.mark.timeout(120)
def test_project_setup_list_shows_committed_setups(project, setup_factory):
    """`project setup list --committed` prints committed setup entries."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    setup_factory(
        setup_name="committed-list",
        script_content="printf 'committed-list-run\\n'",
    )
    run(
        f"{zaigr} project setup run committed-list",
        input="y\n",
        timeout=120,
    )

    list_output = run(
        f"{zaigr} project setup list --committed",
        timeout=10,
    )
    assert "committed (1):" in list_output
    assert "committed-list" in list_output


@pytest.mark.timeout(120)
def test_project_setup_show_committed_prints_stored_scripts(project, setup_factory):
    """`project setup show --committed` prints stored setup scripts."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    setup_factory(
        setup_name="committed-show",
        script_content="printf 'stored-setup-script\\n'",
    )
    run(
        f"{zaigr} project setup run committed-show",
        input="y\n",
        timeout=120,
    )

    show = run(
        f"{zaigr} project setup show --committed",
        timeout=10,
    )
    assert "setup scripts in committed (1):" in show
    assert "--- committed: committed-show ---" in show
    assert "stored-setup-script" in show

@pytest.mark.timeout(240)
def test_project_setup_capture_records_endpoints_and_discard_clears_capture(
    project,
):
    """Capture records runtime endpoints automatically and discard clears the capture."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    capture = spawn_interactive(
        f"{zaigr} project setup capture start",
        cwd=project.cwd,
        env=project.env,
        timeout=240,
    )

    try:
        capture.expect(r"Initialize project and continue\? \[y/N\]", timeout=120)
        capture.sendline("y")
        capture.expect(ROOT_PROMPT, timeout=180)
        assert "rootfs=capture-overlay.qcow2" in capture.before
        capture_curl = "curl -4 -fsS --connect-timeout 3 --max-time 8 http://deb.debian.org"
        capture.sendline(
            "status=unset; "
            "for _ in $(seq 1 3); do "
            f"{capture_curl} >/dev/null; "
            "status=$?; "
            "[ \"$status\" = \"0\" ] && break; "
            "sleep 1; "
            "done; "
            "printf 'CAPTURE_READY_STATUS=%s\\n' \"$status\""
        )
        capture.expect(r"CAPTURE_READY_STATUS=([0-9]+)", timeout=36)
        capture_status = capture.match.group(1)
        capture.expect(ROOT_PROMPT)
        assert capture_status == "0"

        nested = spawn_interactive(
            f"{project.zaigr_bin} project setup capture start",
            cwd=project.cwd,
            env=project.env,
            timeout=120,
        )
        try:
            nested.expect(r":: An active setup capture already exists for this project\.", timeout=60)
            nested.expect(r"setup capture:")
            nested.expect(r"proposed setup.firewall:")
            nested.expect(r"recorded setup.script lines:")
            nested.expect(ACTIVE_CAPTURE_PREVIEW_CHOICE, timeout=60)
            nested.sendline("")
            nested.expect(r":: Capture start cancelled", timeout=60)
            nested.expect(r"\Z")
        finally:
            if nested.isalive():
                nested.close()

        for _ in range(10):
            review, stderr, rc = _run(
                f"{zaigr} project setup capture review",
                cwd=project.cwd,
                env=project.env,
                timeout=20,
            )
            if rc == 0 and _section_contains(
                review,
                "observed endpoints (live):",
                "proposed setup.firewall:",
                "deb.debian.org",
            ):
                break
            time.sleep(1)
        assert rc == 0, err_msg(review, stderr)
        assert "setup capture:" in review
        assert "deb.debian.org" in _section_lines(
            review,
            "observed endpoints (live):",
            "proposed setup.firewall:",
        )
        assert "proposed setup.firewall:" in review
        assert "deb.debian.org" in _section_lines(
            review,
            "proposed setup.firewall:",
            "proposed setup.script:",
        )
        assert "proposed setup.script:" in review
        assert capture_curl in review
        assert "command capture is not implemented" not in review

        discard = run(
            f"{zaigr} project setup capture discard",
            input="y\n",
            timeout=30,
        )
        assert "discarded setup capture" in discard.lower()

        capture_again = spawn_interactive(
            f"{zaigr} project setup capture start",
            cwd=project.cwd,
            env=project.env,
            timeout=120,
        )
        try:
            capture_again.expect(ROOT_PROMPT, timeout=60)
            assert "rootfs=capture-overlay.qcow2" in capture_again.before
            review_again = run(
                f"{zaigr} project setup capture review",
                timeout=20,
            )
            assert "deb.debian.org" not in review_again
            assert capture_curl not in review_again
        finally:
            if capture_again.isalive():
                capture_again.sendline("exit")
                capture_again.expect(r"\Z")
    finally:
        if capture is not None and capture.isalive():
            capture.sendline("exit")
            capture.expect(r"\Z")


@pytest.mark.timeout(300)
def test_vm_entry_flows_refuse_active_setup_capture(project, setup_factory):
    """Active setup capture blocks normal setup, exec, preset, and root entry points."""
    run = partial(_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    setup_factory(
        setup_name="overlay-marker",
        script_content=(
            "printf 'OVERLAY_MARKER_RAN\\n'\n"
            "printf 'overlay-marker-present\\n' > /etc/zaigr-overlay-marker"
        ),
    )
    setup_factory.preset(
        name="capture-refusal-preset",
        run="printf 'PRESET_RAN\\n'",
        setups=[],
    )

    capture = spawn_interactive(
        f"{zaigr} project setup capture start",
        cwd=project.cwd,
        env=project.env,
        timeout=240,
    )
    try:
        capture.expect(r"Initialize project and continue\? \[y/N\]", timeout=120)
        capture.sendline("y")
        capture.expect(ROOT_PROMPT, timeout=180)
        assert "rootfs=capture-overlay.qcow2" in capture.before

        stdout, stderr, rc = run(
            f"{zaigr} project setup run overlay-marker",
            timeout=30,
        )
        _assert_active_capture_refusal(stdout, stderr, rc, "zaigr project setup run")
        assert "OVERLAY_MARKER_RAN" not in stdout + stderr

        capture.sendline(
            "test ! -e /etc/zaigr-overlay-marker; "
            "printf 'MARKER_ABSENT_STATUS=%s\\n' \"$?\""
        )
        capture.expect(r"MARKER_ABSENT_STATUS=0")
        capture.expect(ROOT_PROMPT)

        stdout, stderr, rc = run(
            f"{zaigr} shell --setup overlay-marker",
            timeout=30,
        )
        _assert_active_capture_refusal(stdout, stderr, rc, "zaigr shell")
        assert "OVERLAY_MARKER_RAN" not in stdout + stderr

        stdout, stderr, rc = run(
            f"{zaigr} shell --preset capture-refusal-preset",
            timeout=30,
        )
        _assert_active_capture_refusal(stdout, stderr, rc, "zaigr shell")
        assert "PRESET_RAN" not in stdout + stderr

        stdout, stderr, rc = run(
            f"{zaigr} shell",
            input="exit\n",
            timeout=30,
        )
        _assert_active_capture_refusal(stdout, stderr, rc, "zaigr shell")

        stdout, stderr, rc = run(
            f"{zaigr} project vm start",
            timeout=30,
        )
        _assert_active_capture_refusal(stdout, stderr, rc, "zaigr project vm start")

        stdout, stderr, rc = run(
            f"{zaigr} project vm exec -- true",
            timeout=30,
        )
        _assert_active_capture_refusal(stdout, stderr, rc, "zaigr project vm exec")

        stdout, stderr, rc = run(
            f"{zaigr} shell --root",
            timeout=30,
        )
        _assert_active_capture_refusal(stdout, stderr, rc, "zaigr shell")
        assert "Accessing this VM as root automatically marks the project image dirty" not in stdout + stderr

        discard, stderr, rc = run(
            f"{zaigr} project setup capture discard",
            input="y\n",
            timeout=60,
        )
        assert rc == 0, err_msg(discard, stderr)
        assert "discarded setup capture" in discard.lower()
    finally:
        if capture.isalive():
            capture.close(force=True)


@pytest.mark.timeout(240)
@pytest.mark.parametrize(
    ("choice", "expect_root_prompt"),
    [("", False), ("c", True), ("d", True)],
)
def test_project_setup_capture_start_with_existing_capture_preview_and_action(
    project,
    choice,
    expect_root_prompt,
):
    """`project setup capture start` previews active capture state and handles action choice."""
    capture = spawn_interactive(
        f"{project.zaigr_bin} project setup capture start",
        cwd=project.cwd,
        env=project.env,
        timeout=240,
    )

    try:
        capture.expect(r"Initialize project and continue\? \[y/N\]", timeout=120)
        capture.sendline("y")
        capture.expect(ROOT_PROMPT, timeout=180)
        assert "rootfs=capture-overlay.qcow2" in capture.before

        for i in range(1, 8):
            capture.sendline(f"printf 'preview-line-{i}\\n'")
            capture.expect(fr"preview-line-{i}")
            capture.expect(ROOT_PROMPT)

        active_start = spawn_interactive(
            f"{project.zaigr_bin} project setup capture start",
            cwd=project.cwd,
            env=project.env,
            timeout=120,
        )
        try:
            active_start.expect(r":: An active setup capture already exists for this project\.", timeout=60)
            active_start.expect(r"setup capture:")
            active_start.expect(r"mode: capture overlay")
            active_start.expect(r"proposed setup.firewall:")
            active_start.expect(r"recorded setup.script lines:")
            active_start.expect(r"\.\.\. \(\d+ more omitted\)", timeout=60)
            active_start.expect(ACTIVE_CAPTURE_PREVIEW_CHOICE, timeout=60)
            active_start.sendline(choice)

            if expect_root_prompt:
                active_start.expect(ROOT_PROMPT, timeout=120)
                active_start.sendline("exit")
                active_start.expect(r"\Z")
            else:
                active_start.expect(r":: Capture start cancelled", timeout=60)
                active_start.expect(r"\Z")
        finally:
            if active_start.isalive():
                active_start.sendline("exit")
                active_start.expect(r"\Z")
    finally:
        if capture.isalive():
            capture.sendline("exit")
            capture.expect(r"\Z")


def test_project_setup_capture_accept_creates_local_setup(project):
    """`project setup capture accept` creates a local setup definition."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    capture = spawn_interactive(
        f"{zaigr} project setup capture start",
        cwd=project.cwd,
        env=project.env,
        timeout=240,
    )
    try:
        capture.expect(r"Initialize project and continue\? \[y/N\]", timeout=120)
        capture.sendline("y")
        capture.expect(ROOT_PROMPT, timeout=180)
        capture_curl = "curl -4 -fsS --connect-timeout 3 --max-time 8 http://deb.debian.org"
        capture.sendline(
            "status=unset; "
            "for _ in $(seq 1 3); do "
            f"{capture_curl} >/dev/null; "
            "status=$?; "
            "[ \"$status\" = \"0\" ] && break; "
            "sleep 1; "
            "done; "
            "printf 'CAPTURE_READY_STATUS=%s\\n' \"$status\""
        )
        capture.expect(r"CAPTURE_READY_STATUS=([0-9]+)", timeout=36)
        capture_status = capture.match.group(1)
        capture.expect(ROOT_PROMPT)
        assert capture_status == "0"
        capture.sendline("false")
        capture.expect(ROOT_PROMPT)
        followup_curl = "curl -4 -sS --connect-timeout 5 --max-time 10 http://deb.debian.org"
        capture.sendline(f"{followup_curl} >/dev/null || true")
        capture.expect(ROOT_PROMPT)

        for _ in range(10):
            review, stderr, rc = _run(
                f"{zaigr} project setup capture review",
                cwd=project.cwd,
                env=project.env,
                timeout=20,
            )
            if rc == 0 and "# Returned" in review and _section_contains(
                review,
                "proposed setup.firewall:",
                "proposed setup.script:",
                "deb.debian.org",
            ):
                break
            time.sleep(1)
        assert rc == 0, err_msg(review, stderr)
        assert "deb.debian.org" in _section_lines(
            review,
            "proposed setup.firewall:",
            "proposed setup.script:",
        )
        assert capture_curl in review
        assert followup_curl in review
        assert re.search(r"^\s*# Returned \d+$", review, re.MULTILINE)
        assert "command capture is not implemented" not in review
        assert "history -r \"$HISTFILE\" 2>/dev/null || true" not in review
        assert "history -a \"$HISTFILE\"; history -n \"$HISTFILE\"" not in review
        assert "PROMPT_COMMAND='history -a \"$HISTFILE\"; history -n \"$HISTFILE\"'" not in review
        assert "PS1='\\\\u@\\\\h:\\\\w# '" not in review
        assert not re.search(r"(?m)^history$", review)

        if "# Needed access to deb.debian.org" in review:
            assert "# Needed access to deb.debian.org" in review

        accept = run(
            f"{zaigr} project setup capture accept",
            timeout=120,
        )
        assert "accepted setup capture" in accept.lower()
        assert "promoted capture overlay" in accept.lower()

        setup_match = re.search(r"Updated setup definition: (.+)", accept)
        assert setup_match is not None
        setup_path = Path(setup_match.group(1))
        assert setup_path.name.startswith("capture-")
        assert (setup_path / "setup.script").is_file()
        assert (setup_path / "setup.firewall").is_file()
        setup_script = (setup_path / "setup.script").read_text(encoding="utf-8")
        assert capture_curl in setup_script
        assert followup_curl in setup_script
        assert "command capture is not implemented" not in setup_script
        assert "history -r \"$HISTFILE\" 2>/dev/null || true" not in setup_script
        assert "PROMPT_COMMAND='history -a \"$HISTFILE\"; history -n \"$HISTFILE\"'" not in setup_script
        assert "PS1='\\\\u@\\\\h:\\\\w# '" not in setup_script
        assert not re.search(r"(?m)^history$", setup_script)
        assert "deb.debian.org" in (setup_path / "setup.firewall").read_text(encoding="utf-8")
    finally:
        if capture.isalive():
            capture.sendline("exit")
            capture.expect(r"\Z")


@pytest.mark.timeout(240)
def test_project_setup_capture_can_attach_to_running_vm(project):
    """Capture can attach to an existing VM, but discard only clears capture state."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    run(f"{zaigr} project vm start", input="y\n", timeout=180)

    capture = spawn_interactive(
        f"{zaigr} project setup capture start",
        cwd=project.cwd,
        env=project.env,
        timeout=120,
    )
    try:
        capture.expect(r"A project VM is already running\.", timeout=60)
        capture.expect(r"Discarding the capture will not undo changes made in that VM\.")
        capture.expect(r"Continue\? \[y/N\]")
        capture.sendline("y")
        capture.expect(ROOT_PROMPT, timeout=60)
        capture_curl = "curl -4 -fsS --connect-timeout 3 --max-time 8 http://deb.debian.org"
        capture.sendline(
            "status=unset; "
            "for _ in $(seq 1 3); do "
            f"{capture_curl} >/dev/null; "
            "status=$?; "
            "[ \"$status\" = \"0\" ] && break; "
            "sleep 1; "
            "done; "
            "printf 'CAPTURE_READY_STATUS=%s\\n' \"$status\""
        )
        capture.expect(r"CAPTURE_READY_STATUS=([0-9]+)", timeout=36)
        capture_status = capture.match.group(1)
        capture.expect(ROOT_PROMPT)
        assert capture_status == "0"

        for _ in range(10):
            review, stderr, rc = _run(
                f"{zaigr} project setup capture review",
                cwd=project.cwd,
                env=project.env,
                timeout=20,
            )
            if rc == 0 and _section_contains(
                review,
                "observed endpoints (live):",
                "proposed setup.firewall:",
                "deb.debian.org",
            ):
                break
            time.sleep(1)
        assert rc == 0, err_msg(review, stderr)
        assert "mode: running VM" in review
        assert "deb.debian.org" in _section_lines(
            review,
            "observed endpoints (live):",
            "proposed setup.firewall:",
        )
        assert "deb.debian.org" in _section_lines(
            review,
            "proposed setup.firewall:",
            "proposed setup.script:",
        )
        assert capture_curl in review
        assert "command capture is not implemented" not in review

        active_restart = spawn_interactive(
            f"{zaigr} project setup capture start",
            cwd=project.cwd,
            env=project.env,
            timeout=120,
        )
        try:
            active_restart.expect(r":: An active setup capture already exists for this project\.", timeout=60)
            active_restart.expect(r"mode: running VM")
            active_restart.expect(r"discard: clears capture metadata/logs only; VM changes remain")
            active_restart.expect(ACTIVE_CAPTURE_PREVIEW_CHOICE, timeout=60)
            active_restart.sendline("")
            active_restart.expect(r":: Capture start cancelled", timeout=60)
            active_restart.expect(r"\Z")
        finally:
            if active_restart.isalive():
                active_restart.sendline("exit")
                active_restart.expect(r"\Z")

        discard = run(
            f"{zaigr} project setup capture discard",
            timeout=20,
        )
        assert "discarded setup capture" in discard.lower()
    finally:
        if capture.isalive():
            capture.sendline("exit")
            capture.expect(r"\Z")


@pytest.mark.timeout(360)
def test_project_setup_capture_firewall_allowance_does_not_leak_to_parallel_shell(project):
    """Setup capture firewall allowance is scoped to the capture session."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    test_domain = "pypi.org"
    test_url = "https://pypi.org"
    normal_curl = f"curl -4 -sS --connect-timeout 3 --max-time 8 {test_url}"
    capture_curl = f"curl -4 -sS --connect-timeout 5 --max-time 15 {test_url}"
    normal_curl_status = [
        zaigr,
        "project",
        "vm",
        "exec",
        "--",
        "bash",
        "-lc",
        f"{normal_curl} >/dev/null; printf '%s\\n' \"$?\"",
    ]

    run(f"{zaigr} project vm start", input="y\n", timeout=180)
    run(
        [
            zaigr,
            "project",
            "vm",
            "exec",
            "--",
            "sh",
            "-lc",
            "command -v curl && command -v getent",
        ],
        timeout=20,
    )
    run(
        [zaigr, "project", "vm", "exec", "--", "getent", "ahosts", test_domain],
        timeout=20,
    )
    normal_before_status = "0"
    for _ in range(12):
        normal_before_status = run(normal_curl_status, timeout=20).strip()
        if normal_before_status != "0":
            break
        time.sleep(1)
    assert normal_before_status != "0"

    normal_shell = spawn_interactive(
        f"{zaigr} shell",
        cwd=project.cwd,
        env=project.env,
        timeout=30,
    )
    capture = None
    try:
        normal_shell.expect(USER_PROMPT, timeout=60)
        capture = spawn_interactive(
            f"{zaigr} project setup capture start",
            cwd=project.cwd,
            env=project.env,
            timeout=120,
        )
        capture.expect(r"A project VM is already running\.", timeout=60)
        capture.expect(r"Continue\? \[y/N\]")
        capture.sendline("y")
        capture.expect(ROOT_PROMPT, timeout=60)
        capture.sendline(
            f"{capture_curl} >/dev/null; "
            "printf 'CAPTURE_STATUS=%s\\n' \"$?\""
        )
        capture.expect(r"CAPTURE_STATUS=([0-9]+)", timeout=30)
        assert capture.match.group(1) == "0", (
            f"setup capture could not reach {test_domain}; "
            "this is an environment firewall/allowlist failure or a regression "
            "in the temporary capture firewall allowance"
        )
        capture.expect(ROOT_PROMPT)

        for _ in range(10):
            review, stderr, rc = _run(
                f"{zaigr} project setup capture review",
                cwd=project.cwd,
                env=project.env,
                timeout=20,
            )
            if rc == 0 and _section_contains(
                review,
                "observed endpoints (live):",
                "proposed setup.firewall:",
                test_domain,
            ):
                break
            time.sleep(1)
        assert rc == 0, err_msg(review, stderr)
        assert "mode: running VM" in review
        assert test_domain in _section_lines(
            review,
            "observed endpoints (live):",
            "proposed setup.firewall:",
        )
        assert test_domain in _section_lines(
            review,
            "proposed setup.firewall:",
            "proposed setup.script:",
        )
        assert capture_curl in review
        assert "# Returned 0" in review

        normal_shell.sendline(
            f"{normal_curl} >/dev/null; "
            "printf 'NORMAL_DURING_STATUS=%s\\n' \"$?\""
        )
        normal_shell.expect(r"NORMAL_DURING_STATUS=([0-9]+)", timeout=20)
        assert normal_shell.match.group(1) != "0"
        normal_shell.expect(USER_PROMPT)

        capture.sendline("exit")
        capture.expect(r"\Z")

        normal_shell.sendline(
            f"{normal_curl} >/dev/null; "
            "printf 'NORMAL_AFTER_STATUS=%s\\n' \"$?\""
        )
        normal_shell.expect(r"NORMAL_AFTER_STATUS=([0-9]+)", timeout=20)
        assert normal_shell.match.group(1) != "0"
        normal_shell.expect(USER_PROMPT)

        discard = run(
            f"{zaigr} project setup capture discard",
            timeout=20,
        )
        assert "discarded setup capture" in discard.lower()
    finally:
        if capture is not None and capture.isalive():
            capture.sendline("exit")
            capture.expect(r"\Z")
        if normal_shell.isalive():
            normal_shell.sendline("exit")
            normal_shell.expect(r"\Z")


def test_global_setup_commands_work_without_project_metadata(project, tmp_path):
    """Global setup commands work without project metadata."""
    run = partial(_checked_run, cwd=tmp_path, env=project.env)
    zaigr = project.zaigr_bin

    setup_list = run(
        f"{zaigr} global setup list",
        timeout=10,
    )
    assert "go" in setup_list

    setup_show = run(
        f"{zaigr} global setup show --script go",
        timeout=10,
    )
    assert "name: go" in setup_show
    assert "path:" in setup_show
    assert "== script file: setup.script ==" in setup_show

    setup_firewall = run(
        f"{zaigr} global setup show --firewall go",
        timeout=10,
    )
    assert "== firewall file: setup.firewall ==" in setup_firewall
    assert "go.dev" in setup_firewall

    setup_full = run(
        f"{zaigr} global setup show --full go",
        timeout=10,
    )
    assert "== script file: setup.script ==" in setup_full
    assert "== firewall file: setup.firewall ==" in setup_full
    assert "go.dev" in setup_full

    setup_both = run(
        f"{zaigr} global setup show --script --firewall go",
        timeout=10,
    )
    assert setup_full == setup_both

    setup_path = run(
        f"{zaigr} global setup path go",
        timeout=10,
    )
    assert setup_path.strip().endswith("/.zaigr/setups/go")


@pytest.mark.timeout(900)
def test_global_firewall_allowlist_applies_to_project_starts(project, setup_factory, tmp_path):
    """Global firewall entries are managed globally and applied to project VM starts."""
    run = partial(_run, cwd=tmp_path, env=project.env)
    zaigr = project.zaigr_bin

    list_output, stderr, rc = run(
        f"{zaigr} global firewall list",
        timeout=10,
    )
    assert rc == 0, err_msg(list_output, stderr)
    assert "No global firewall entries have been configured." in list_output

    invalid, stderr, rc = run(
        f"{zaigr} global firewall allow '*.github.com'",
        timeout=10,
    )
    assert rc != 0
    assert "invalid domain: *.github.com" in (invalid + stderr)

    allow, stderr, rc = run(
        f"{zaigr} global firewall allow github.com GITHUB.COM",
        timeout=10,
    )
    assert rc == 0, err_msg(allow, stderr)
    assert "allowed github.com" in allow

    list_output, stderr, rc = run(
        f"{zaigr} global firewall list",
        timeout=10,
    )
    assert rc == 0, err_msg(list_output, stderr)
    assert list_output.splitlines().count("github.com") == 1

    complete, stderr, rc = run(
        [zaigr, "__complete", "global", "firewall", "remove", "g"],
        timeout=10,
    )
    assert rc == 0, err_msg(complete, stderr)
    complete_entries, complete_directive = _completion_entries(complete)
    assert "github.com" in complete_entries
    assert complete_directive == ":4"

    setup_factory(
        setup_name="global-firewall-project",
        script_content="true",
        firewall=["pypi.org"],
    )

    run = partial(_run, cwd=project.cwd, env=project.env)
    setup, stderr, rc = run(
        f"{zaigr} project setup run global-firewall-project --ram 512 --cpu 1",
        input="y\n",
        timeout=240,
    )
    assert rc == 0, err_msg(setup, stderr)
    setup_combined = setup + stderr
    assert "warning: applying global firewall allowlist entries:" in setup_combined
    assert "github.com" in setup_combined

    firewall, stderr, rc = run(
        f"{zaigr} project firewall show",
        timeout=30,
    )
    assert rc == 0, err_msg(firewall, stderr)
    firewall_lines = firewall.splitlines()
    assert "# global" in firewall_lines
    assert "github.com" in firewall_lines
    assert "# global-firewall-project" in firewall_lines
    assert "pypi.org" in firewall_lines

    run = partial(_run, cwd=tmp_path, env=project.env)
    remove, stderr, rc = run(
        f"{zaigr} global firewall remove github.com",
        timeout=10,
    )
    assert rc == 0, err_msg(remove, stderr)
    assert "removed github.com" in remove

    list_output, stderr, rc = run(
        f"{zaigr} global firewall list",
        timeout=10,
    )
    assert rc == 0, err_msg(list_output, stderr)
    assert "github.com" not in list_output

    run = partial(_run, cwd=project.cwd, env=project.env)
    stopped, stderr, rc = run(
        f"{zaigr} project vm stop",
        timeout=30,
    )
    assert rc == 0, err_msg(stopped, stderr)

    start, stderr, rc = run(
        f"{zaigr} project vm start",
        timeout=120,
    )
    assert rc == 0, err_msg(start, stderr)
    start_combined = start + stderr
    assert "warning: applying global firewall allowlist entries:" not in start_combined

    firewall, stderr, rc = run(
        f"{zaigr} project firewall show",
        timeout=30,
    )
    assert rc == 0, err_msg(firewall, stderr)
    firewall_lines = firewall.splitlines()
    assert "# global" not in firewall_lines
    assert "github.com" not in firewall_lines
    assert "# global-firewall-project" in firewall_lines
    assert "pypi.org" in firewall_lines


def test_global_preset_commands_without_project_metadata(project, tmp_path):
    """Global preset commands work without project metadata."""
    run = partial(_checked_run, cwd=tmp_path, env=project.env)
    zaigr = project.zaigr_bin

    preset_list = run(
        f"{zaigr} global preset list",
        timeout=10,
    )
    assert "codex" in preset_list

    preset_show = run(
        f"{zaigr} global preset show codex",
        timeout=10,
    )
    assert "name: codex" in preset_show
    assert "run script:" in preset_show
    assert "setup dependencies:" in preset_show

    preset_full = run(
        f"{zaigr} global preset show codex --full",
        timeout=10,
    )
    assert "== preset run script: run ==" in preset_full
    assert "setup dependency 1:" in preset_full
    assert "name: codex" in preset_full
    assert "== script file: setup.script ==" in preset_full
    assert "== firewall file: setup.firewall ==" in preset_full

    preset_both = run(
        f"{zaigr} global preset show codex --script --firewall",
        timeout=10,
    )
    assert preset_full == preset_both

    preset_path = run(
        f"{zaigr} global preset path codex",
        timeout=10,
    )
    assert preset_path.strip().endswith("/.zaigr/presets/codex")


def test_zaigr_dev_preset_depends_on_every_builtin_setup(project, tmp_path):
    """The builtin `zaigr-dev` preset pulls in every builtin setup."""
    run = partial(_checked_run, cwd=tmp_path, env=project.env)
    zaigr = project.zaigr_bin

    preset_show = run(
        f"{zaigr} global preset show zaigr-dev",
        timeout=10,
    )

    assert "name: zaigr-dev" in preset_show
    assert "setup dependencies:" in preset_show
    for setup in [
        "claude",
        "codex",
        "docker",
        "go",
        "k3s",
        "kernel-mmdebstrap",
        "nodejs",
        "podman",
        "python",
        "release-tools",
        "yocto-kas",
    ]:
        assert f"  {setup}\n" in preset_show


@pytest.mark.parametrize(
    ("mode", "shell_args", "expected_flag"),
    [
        ("preset", "--preset root-preset", "--preset"),
        ("setup", "--setup root-setup", "--setup"),
    ],
)
def test_shell_rejects_root_with_preset_or_setup(
    project, setup_factory, mode, shell_args, expected_flag
):
    """`zaigr shell --root` cannot be combined with preset/setup startup modes."""
    run = partial(_run, cwd=project.cwd, env=project.env)
    if mode == "preset":
        setup_factory.preset(name="root-preset", run="", setups=[])
    else:
        setup_factory(setup_name="root-setup", script_content="printf 'setup-created\\n'")

    stdout, stderr, rc = run(
        f"{project.zaigr_bin} shell {shell_args} --root",
        timeout=30,
    )

    assert rc != 0
    combined = (stdout + stderr).lower()
    assert "--root" in combined
    assert expected_flag in combined
    assert "cannot" in combined


def test_project_vm_smoke(project):
    """`zaigr shell` works for user access, and `zaigr shell --root` works for root access."""
    shell = spawn_interactive(
        f"{project.zaigr_bin} shell",
        cwd=project.cwd,
        env=project.env,
        timeout=180,
    )
    shell.expect(r"Initialize project and continue\? \[y/N\]")
    shell.sendline("y")
    shell.expect(USER_PROMPT)
    shell.sendline("pwd")
    shell.expect(r"/workspace")
    shell.expect(USER_PROMPT)
    shell.sendline("touch /root/smoke-check")
    shell.expect(r"Permission denied")
    shell.expect(USER_PROMPT)
    shell.sendline("exit")
    shell.expect(r"\Z")
    shell.close()

    root_shell = spawn_interactive(
        f"{project.zaigr_bin} shell --root",
        cwd=project.cwd,
        env=project.env,
        timeout=180,
    )
    root_shell.expect(ROOT_DIRTY_PROMPT)
    root_shell.expect(ROOT_DIRTY_CONFIRM_PROMPT)
    root_shell.sendline("y")
    root_shell.expect(ROOT_PROMPT)
    root_shell.sendline("touch /root/smoke-check; ls -l /root/smoke-check")
    root_shell.expect(r"smoke-check")
    root_shell.expect(ROOT_PROMPT)
    root_shell.sendline("exit")
    root_shell.expect(r"\Z")
    root_shell.close()


@pytest.mark.timeout(240)
def test_shell_root_dirty_prompt_rejects_then_accept_marks_project_image_dirty(project):
    """`zaigr shell --root` only marks the project image dirty after confirmation."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    root_shell = spawn_interactive(
        f"{project.zaigr_bin} shell --root",
        cwd=project.cwd,
        env=project.env,
        timeout=180,
    )
    try:
        root_shell.expect(r"Initialize project and continue\? \[y/N\]")
        root_shell.sendline("y")
        root_shell.expect(ROOT_DIRTY_PROMPT)
        root_shell.expect(ROOT_DIRTY_CONFIRM_PROMPT)
        root_shell.sendline("n")
        root_shell.expect(pexpect.EOF)
        root_shell.close()
        assert root_shell.exitstatus != 0
    finally:
        if root_shell.isalive():
            root_shell.close(force=True)

    status = run(
        f"{project.zaigr_bin} project status",
        timeout=10,
    )
    assert "project-image-dirty:" not in status

    root_shell = spawn_interactive(
        f"{project.zaigr_bin} shell --root",
        cwd=project.cwd,
        env=project.env,
        timeout=180,
    )
    try:
        root_shell.expect(ROOT_DIRTY_PROMPT)
        root_shell.expect(ROOT_DIRTY_CONFIRM_PROMPT)
        root_shell.sendline("y")
        root_shell.expect(ROOT_PROMPT)
        root_shell.sendline("exit")
        root_shell.expect(r"\Z")
    finally:
        root_shell.close(force=True)

    status = run(
        f"{project.zaigr_bin} project status",
        timeout=10,
    )
    assert "project-image-dirty: yes (root-shell," in status


def test_project_vm_start_starts_vm_without_shell_attach(project):
    """`project vm start` ensures the project VM is running in the background."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    run(
        f"{project.zaigr_bin} project vm start",
        input="y\n",
        timeout=120,
    )

    status = run(
        f"{project.zaigr_bin} project status",
        timeout=10,
    )
    assert "status: running" in status

    exec_output = run(
        f"{project.zaigr_bin} project vm exec -- printf 'vm-exec-ok\\n'",
        timeout=10,
    )
    assert exec_output.strip() == "vm-exec-ok"

    pwd = run(
        f"{project.zaigr_bin} project vm exec -- pwd",
        timeout=10,
    )
    assert pwd.strip() == "/home/user/workspace"

    stdin = run(
        [
            project.zaigr_bin,
            "project",
            "vm",
            "exec",
            "--",
            "cat",
        ],
        input="stdin-through-exec\n",
        timeout=10,
    )
    assert stdin.strip() == "stdin-through-exec"

    failed_exec, stderr, rc = _run(
        [
            project.zaigr_bin,
            "project",
            "vm",
            "exec",
            "--",
            "bash",
            "-lc",
            "exit 7",
        ],
        cwd=project.cwd,
        env=project.env,
        timeout=10,
    )
    assert rc == 7, err_msg(failed_exec, stderr)

    shown = run(
        f"{project.zaigr_bin} project vm show-config",
        timeout=10,
    )
    assert shown.strip().splitlines() == ["cpu=1", "ram=512MB"]


def test_project_vm_set_config_updates_defaults(project):
    """`project vm set-config` rewrites stored defaults for future project VM starts."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    run(f"{zaigr} project vm start", input="y\n", timeout=120)
    run(f"{zaigr} project vm stop")

    stdout = run(
        f"{zaigr} project vm set-config --ram 768 --cpu 2",
        timeout=10,
    )
    assert ":: Project defaults updated" in stdout

    shown = run(
        f"{zaigr} project vm show-config",
        timeout=10,
    )
    assert shown.strip().splitlines() == ["cpu=2", "ram=768MB"]


def test_running_vm_rejects_resource_overrides(project):
    """Runtime start/shell calls cannot change CPU or RAM on an already-running project VM."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    stdout = run(
        f"{project.zaigr_bin} project vm start",
        input="y\n",
        timeout=120,
    )
    stdout, stderr, rc = _run(
        f"{project.zaigr_bin} project vm start --ram 1024",
        cwd=project.cwd,
        env=project.env,
        timeout=10,
    )
    assert rc != 0
    assert "project vm is already running" in (stdout + stderr).lower()
    assert "--ram and --cpu cannot be changed on a running vm" in (stdout + stderr).lower()

    stdout, stderr, rc = _run(
        f"{project.zaigr_bin} shell --ram 1024",
        cwd=project.cwd,
        env=project.env,
        timeout=10,
    )
    assert rc != 0
    assert "project vm is already running" in (stdout + stderr).lower()
    assert "--ram and --cpu cannot be changed on a running vm" in (stdout + stderr).lower()


@pytest.mark.timeout(240)
def test_global_projects_kill_stops_running_vm(project):
    """`global projects kill` gracefully stops the selected running project VM."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    run(
        f"{project.zaigr_bin} project vm start",
        input="y\n",
        timeout=180,
    )

    store_hash = project.store_dir.name
    stdout = run(
        f"{project.zaigr_bin} global projects kill {store_hash}",
        timeout=60,
    )
    assert f"{store_hash}: stopped" in stdout

    status = run(
        f"{project.zaigr_bin} project status",
        timeout=10,
    )
    assert "status: not running" in status


@pytest.mark.timeout(240)
def test_global_projects_kill_prompts_when_shell_is_active(project):
    """`global projects kill` asks before stopping a VM with an attached shell."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    shell = spawn_interactive(
        f"{zaigr} shell",
        cwd=project.cwd,
        env=project.env,
        timeout=180,
    )
    try:
        shell.expect(r"Initialize project and continue\? \[y/N\]")
        shell.sendline("y")
        shell.expect(USER_PROMPT)

        store_hash = project.store_dir.name
        stdout, stderr, rc = _run(
            f"{zaigr} global projects kill {store_hash}",
            cwd=project.cwd,
            env=project.env,
            input="n\n",
            timeout=15,
        )
        assert rc == 0, err_msg(stdout, stderr)
        assert "active shell session" in stderr
        assert "Stopping the VM will close them." in stderr
        assert f"{store_hash}: skipped" in stdout

        status = run(
            f"{zaigr} project status",
            timeout=10,
        )
        assert "status: running" in status
    finally:
        shell.sendline("exit")
        shell.expect(r"\Z", timeout=30)
        shell.close(force=True)


@pytest.mark.timeout(300)
def test_two_projects_keep_setup_state_separate(project_factory, setup_factory):
    """Project store state stays isolated when a test creates multiple projects."""
    setup_factory(setup_name="hello", script_content="printf 'hello\\n' > /etc/zaigr-hello")
    project_a = project_factory("alpha")
    project_b = project_factory("beta")

    for project in (project_a, project_b):
        run = partial(_checked_run, cwd=project.cwd, env=project.env)
        run(
            f"{project.zaigr_bin} project vm start",
            input="y\n",
            timeout=120,
        )
        run(
            f"{project.zaigr_bin} project vm stop",
            timeout=30,
        )

    run = partial(_checked_run, cwd=project_a.cwd, env=project_a.env)
    run(
        f"{project_a.zaigr_bin} project setup run hello",
        timeout=180,
    )

    status_a = run(
        f"{project_a.zaigr_bin} project status",
        timeout=10,
    )

    run = partial(_checked_run, cwd=project_b.cwd, env=project_b.env)
    status_b = run(
        f"{project_b.zaigr_bin} project status",
        timeout=10,
    )
    assert "committed to project image (1):" in status_a
    assert "committed to project image (0):" in status_b

    run = partial(_checked_run, cwd=project_a.cwd, env=project_a.env)
    list_a = run(
        f"{project_a.zaigr_bin} project setup list --committed",
        timeout=10,
    )
    assert "committed (1):" in list_a
    assert "hello" in list_a

    run = partial(_checked_run, cwd=project_b.cwd, env=project_b.env)
    list_b = run(
        f"{project_b.zaigr_bin} project setup list --committed",
        timeout=10,
    )
    assert "committed (0):" in list_b
    assert "hello" not in list_b


@pytest.mark.timeout(240)
def test_awaiting_setup_commit_promotes_clean_project_image_without_replay(project, setup_factory):
    """Clean awaiting setup commits promote the current image instead of reinstalling."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    setup_factory(
        setup_name="fast-promote",
        script_content=(
            "printf 'FAST_PROMOTE_SETUP_RAN\\n'\n"
            "printf 'fast-promote-present\\n' > /etc/zaigr-fast-promote"
        ),
    )

    run(
        f"{project.zaigr_bin} project vm start",
        input="y\n",
        timeout=120,
    )

    setup = run(
        f"{project.zaigr_bin} project setup run fast-promote",
        timeout=60,
    )
    assert "FAST_PROMOTE_SETUP_RAN" in setup

    run(
        f"{project.zaigr_bin} project vm stop",
        timeout=60,
    )

    shell = spawn_interactive(
        f"{project.zaigr_bin} shell",
        cwd=project.cwd,
        env=project.env,
        timeout=180,
    )
    try:
        shell.expect(r"1 setup is awaiting image commit:")
        shell.expect(r"- fast-promote")
        shell.expect(r"Save this setup to the project image before starting this VM\?")
        shell.expect(r"Action \[c/d\]:")
        shell.sendline("commit")
        shell.expect(r"Promoted current project image without reinstalling setups")
        shell.expect(r"Committed 1 setups to the project image")
        shell.expect(USER_PROMPT, timeout=120)
        shell.sendline("cat /etc/zaigr-fast-promote")
        shell.expect(r"fast-promote-present")
        shell.expect(USER_PROMPT)
        shell.sendline("exit")
        shell.expect(r"\Z")
    finally:
        shell.close(force=True)

    assert "FAST_PROMOTE_SETUP_RAN" not in shell.transcript.getvalue()


@pytest.mark.timeout(180)
def test_project_clean_resets_vm_image_and_setup_status(project, setup_factory):
    """`project clean` removes running-VM setup state and rebuilds from the base image."""
    run = partial(_run, cwd=project.cwd, env=project.env)
    setup_factory(
        setup_name="clean-marker",
        script_content="printf 'clean-mark\\n' > /etc/zaigr-clean-mark",
    )

    stdout, stderr, rc = run(
        f"{project.zaigr_bin} project vm start",
        input="y\n",
        timeout=120,
    )
    assert rc == 0, err_msg(stdout, stderr)

    stdout, stderr, rc = run(
        f"{project.zaigr_bin} project setup run clean-marker",
        timeout=60,
    )
    assert rc == 0, err_msg(stdout, stderr)

    marker, stderr, rc = run(
        f"{project.zaigr_bin} project vm exec --root -- cat /etc/zaigr-clean-mark",
        input="y\n",
        timeout=30,
    )
    assert rc == 0, err_msg(marker, stderr)
    assert ROOT_EXEC_CONFIRM_TEXT in stderr
    assert "clean-mark" in marker

    root_stdin, stderr, rc = run(
        [
            project.zaigr_bin,
            "project",
            "vm",
            "exec",
            "--root",
            "--",
            "cat",
        ],
        input="y\nroot-stdin-through-exec\n",
        timeout=30,
    )
    assert rc == 0, err_msg(root_stdin, stderr)
    assert ROOT_EXEC_CONFIRM_TEXT in stderr
    assert root_stdin.strip() == "root-stdin-through-exec"

    status, stderr, rc = run(
        f"{project.zaigr_bin} project status",
        timeout=10,
    )
    assert rc == 0, err_msg(status, stderr)
    assert "project-image-dirty: yes (root-exec," in status
    assert "awaiting image commit (1):" in status

    list_output, stderr, rc = run(
        f"{project.zaigr_bin} project setup list --awaiting-commit",
        timeout=10,
    )
    assert rc == 0, err_msg(list_output, stderr)
    assert "awaiting-commit (1):" in list_output
    assert "clean-marker" in list_output

    stdout, stderr, rc = run(
        f"{project.zaigr_bin} project vm stop",
        timeout=30,
    )
    assert rc == 0, err_msg(stdout, stderr)

    clean, stderr, rc = run(
        f"{project.zaigr_bin} project clean",
        timeout=120,
    )
    assert rc == 0, err_msg(clean, stderr)
    assert ":: Removed setup state (0 committed to project image, 1 awaiting image commit, 0 failed)" in clean

    status, stderr, rc = run(
        f"{project.zaigr_bin} project status",
        timeout=10,
    )
    assert rc == 0, err_msg(status, stderr)
    assert "awaiting image commit (0):" in status
    assert "project-image-dirty:" not in status

    list_output, stderr, rc = run(
        f"{project.zaigr_bin} project setup list --awaiting-commit",
        timeout=10,
    )
    assert rc == 0, err_msg(list_output, stderr)
    assert "awaiting-commit (0):" in list_output
    assert "clean-marker" not in list_output

    stdout, stderr, rc = run(
        f"{project.zaigr_bin} project vm start",
        timeout=120,
    )
    assert rc == 0, err_msg(stdout, stderr)

    marker_cleaned, stderr, rc = run(
        [
            project.zaigr_bin,
            "project",
            "vm",
            "exec",
            "--root",
            "--",
            "bash",
            "-lc",
            "test ! -e /etc/zaigr-clean-mark && printf 'marker-cleaned\\n'",
        ],
        input="y\n",
        timeout=30,
    )
    assert rc == 0, err_msg(marker_cleaned, stderr)
    assert ROOT_EXEC_CONFIRM_TEXT in stderr
    assert "marker-cleaned" in marker_cleaned


@pytest.mark.timeout(180)
def test_project_delete_refuses_running_vm(project):
    """`project delete --force` refuses to delete a store with a running project VM."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    run(
        f"{project.zaigr_bin} project vm start",
        input="y\n",
        timeout=120,
    )
    assert project.store_dir.is_dir()

    delete, stderr, rc = _run(
        f"{project.zaigr_bin} project delete --force",
        cwd=project.cwd,
        env=project.env,
        timeout=10,
    )
    assert rc != 0
    combined = delete + stderr
    assert "project VM is running" in combined
    assert "zaigr project vm stop" in combined
    assert project.store_dir.is_dir()


@pytest.mark.timeout(120)
def test_shell_runs_test_local_preset(project, setup_factory):
    """`zaigr shell --preset <preset>` applies preset setups and runs the preset script."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    setup_factory(
        setup_name="fast-build",
        script_content="printf 'setup-applied\\n' > /etc/zaigr-fast-build",
    )
    setup_factory.preset(
        name="fast",
        run="""
test "$(cat /etc/zaigr-fast-build)" = "setup-applied"
printf 'preset-ran\\n'
""",
        setups=["fast-build"],
    )

    preset = run(
        f"{project.zaigr_bin} shell --preset fast",
        input="y\n",
        timeout=120,
    )
    assert "preset-ran" in preset

    status = run(
        f"{project.zaigr_bin} project status",
        timeout=10,
    )
    assert "committed to project image (1):" in status
    assert "fast-build  v." in status

    list_output = run(
        f"{project.zaigr_bin} project setup list --committed",
        timeout=10,
    )
    assert "committed (1):" in list_output
    assert "fast-build" in list_output


@pytest.mark.timeout(120)
def test_two_projects_can_run_at_the_same_time(project_factory):
    """Two projects can boot concurrently."""
    project_a = project_factory("alpha")
    project_b = project_factory("beta")

    run = partial(_checked_run, cwd=project_a.cwd, env=project_a.env)
    run(
        f"{project_a.zaigr_bin} project vm start",
        input="y\n",
        timeout=120,
    )

    run = partial(_checked_run, cwd=project_b.cwd, env=project_b.env)
    run(
        f"{project_b.zaigr_bin} project vm start",
        input="y\n",
        timeout=120,
    )

    run = partial(_checked_run, cwd=project_a.cwd, env=project_a.env)
    status_a = run(
        f"{project_a.zaigr_bin} project status",
        timeout=10,
    )
    assert "status: running" in status_a

    run = partial(_checked_run, cwd=project_b.cwd, env=project_b.env)
    status_b = run(
        f"{project_b.zaigr_bin} project status",
        timeout=10,
    )
    assert "status: running" in status_b

    run = partial(_checked_run, cwd=project_a.cwd, env=project_a.env)
    exec_a = run(
        f"{project_a.zaigr_bin} project vm exec -- printf 'project-a-ok\\n'",
        timeout=10,
    )
    assert exec_a.strip() == "project-a-ok"

    run = partial(_checked_run, cwd=project_b.cwd, env=project_b.env)
    exec_b = run(
        f"{project_b.zaigr_bin} project vm exec -- printf 'project-b-ok\\n'",
        timeout=10,
    )
    assert exec_b.strip() == "project-b-ok"


def test_project_status_reports_stale_vm_marker(project):
    """`project status` surfaces a stale session marker without claiming the VM is running."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    run(
        f"{project.zaigr_bin} project vm start",
        input="y\n",
        timeout=120,
    )
    run(
        f"{project.zaigr_bin} project vm stop",
        timeout=30,
    )

    sock_path = Path(project.store_dir) / "runtime" / "vm.sock"
    sock_path.parent.mkdir(exist_ok=True)
    if sock_path.exists():
        sock_path.unlink()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.bind(str(sock_path))
    finally:
        sock.close()

    status = run(
        f"{project.zaigr_bin} project status",
        timeout=10,
    )
    assert "status: stale session marker found; not running" in status


def test_misc_full_version_command(tmp_path):
    """`zaigr --version` and `zaigr misc full-version` are deterministic and metadata-only."""
    test_bin = tmp_path / "zaigr"
    run = partial(_checked_run, cwd=REPO_ROOT)
    run(
        f'go build -ldflags "-X main.version=1.4.0 -X main.build=1 -X main.commit=def456 -X main.buildTime=20260429-222429" -o {test_bin} ./cmd/zaigr',
        timeout=120,
    )

    run = _checked_run
    version = run(f"{test_bin} --version", timeout=10)
    assert version == "1.4.0\n"

    misc = run(f"{test_bin} misc", timeout=10)
    assert "Miscellaneous commands" in misc
    assert "full-version" in misc

    full = run(f"{test_bin} misc full-version", timeout=10)
    assert full.endswith("\n")
    lines = full.splitlines()
    fields = [line.split(": ", 1)[0] for line in lines]
    assert fields == [
        "version",
        "build",
        "commit",
        "built",
        "miniconfig",
        "building-blocks",
        "base-image",
    ]
    assert lines[:4] == [
        "version: 1.4.0",
        "build: 1",
        "commit: def456",
        "built: 20260429-222429",
    ]
    assert len(lines) == 7
    assert lines[4].startswith("miniconfig: ") and lines[4] != "miniconfig: "
    assert lines[5].startswith("building-blocks: ") and lines[5] != "building-blocks: "
    assert lines[6].startswith("base-image: ") and lines[6] != "base-image: "

    lower_output = (version + full).lower()
    assert "linux" not in lower_output
    assert "amd64" not in lower_output
    assert "platform" not in lower_output
    assert "zaigr 1.4.0 (" not in version + full
