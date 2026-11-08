"""Adversarial public workflows for persistent exact project IPv4 permissions."""

import os
from functools import partial

import pytest

from ..conftest import err_msg
from ..conftest import run as _run


@pytest.fixture(autouse=True)
def small_vm_resources(monkeypatch):
    """Keep independently owned test VMs within the parallel worker budget."""
    monkeypatch.setenv("ZAIGR_VM_RAM", "512")
    monkeypatch.setenv("ZAIGR_VM_CPU", "1")
    monkeypatch.setenv("ZAIGR_DISK_SIZE", "8G")


def _checked_run(cmd, **kwargs):
    """Record a visible command and return successful stdout."""
    stdout, stderr, rc = _run(cmd, **kwargs)
    assert rc == 0, err_msg(stdout, stderr)
    return stdout


@pytest.mark.timeout(180)
def test_global_firewall_enumeration_failure_is_recoverable(project):
    """A real project-store permission failure is visible and can be reconciled."""
    if os.geteuid() == 0:
        pytest.fail("permission-boundary test requires the normal unprivileged test uid")
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    run(f"{zaigr} project vm start", input="y\n", timeout=180)
    store_root = project.home / ".zaigr" / "store"
    store_root.mkdir(parents=True, exist_ok=True)
    original_mode = store_root.stat().st_mode & 0o777
    store_root.chmod(0)
    try:
        stdout, stderr, rc = _run(
            f"{zaigr} global firewall allow enumeration-recovery.example",
            cwd=project.cwd, env=project.env, timeout=20,
        )
        diagnostic = stdout + stderr
        assert rc != 0, diagnostic
        assert "global firewall saved" in diagnostic
        assert "project stores could not be enumerated" in diagnostic
        assert "permission denied" in diagnostic.lower()
    finally:
        store_root.chmod(original_mode)
    assert "enumeration-recovery.example" in run(f"{zaigr} global firewall list")
    effective = run(f"{zaigr} project firewall show")
    assert "enumeration-recovery.example" in effective, effective
    assert "enumeration-recovery.example" in run(
        f"{zaigr} global firewall allow enumeration-recovery.example"
    )
    assert run(f"{zaigr} project vm exec -- printf LIVE_POLICY_RECONCILED") == "LIVE_POLICY_RECONCILED"
    removed = run(
        f"{zaigr} global firewall remove enumeration-recovery.example"
    )
    assert "removed enumeration-recovery.example" in removed
    assert "enumeration-recovery.example" not in run(f"{zaigr} project firewall show")
    assert run(f"{zaigr} project vm exec -- printf LIVE_POLICY_REMOVED") == "LIVE_POLICY_REMOVED"


