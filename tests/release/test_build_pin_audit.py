"""Check that production build inputs use locked dependency versions."""

import shutil
import sys
from pathlib import Path

from tests.conftest import REPO_ROOT, err_msg, run


def _build_pin_fixture(tmp_path):
    """Create a small repository containing only the audit's input paths."""
    repo = tmp_path / "repo"
    (repo / "vm_prep/nested").mkdir(parents=True)
    (repo / "release").mkdir()
    (repo / "deps.lock").write_text(
        "KERNEL_VERSION=6.12.0\nKERNEL_TAG=v6.12\nGO_VERSION=1.24.4\n"
        "VIRTIOFSD_VERSION=1.13.2\nDEBIAN_SUITE=trixie\n",
        encoding="utf-8",
    )
    (repo / "vm_prep/nested/build-tool.sh").write_text(
        "#!/bin/sh\n. \"$REPO/deps.lock\"\n"
        "TOOL_URL=https://example.invalid/v${GO_VERSION}/tool.tar.gz\n"
        "printf '%s\\n' \"$DEBIAN_SUITE\"\n",
        encoding="utf-8",
    )
    shutil.copy2(Path(REPO_ROOT) / "release/check-build-pins", repo / "release/check-build-pins")
    return repo


def test_repository_build_inputs_have_no_unlocked_versions():
    """Keep the maintained build scripts clear of untracked pins."""
    stdout, stderr, rc = run(
        [sys.executable, str(Path(REPO_ROOT) / "release/check-build-pins")],
        cwd=REPO_ROOT,
    )

    assert rc == 0, err_msg(stdout, stderr)


def test_build_pin_audit_accepts_locked_build_inputs_and_ignores_setups(tmp_path):
    """Build scripts may use lock values; guest setup defaults are out of scope."""
    repo = _build_pin_fixture(tmp_path)
    setup = repo / "setups/go"
    setup.mkdir(parents=True)
    (setup / "install.sh").write_text("GO_VERSION=99.99.99\n", encoding="utf-8")

    stdout, stderr, rc = run(
        [sys.executable, str(repo / "release/check-build-pins"), str(repo)], cwd=repo
    )

    assert rc == 0, err_msg(stdout, stderr)
    assert "use deps.lock" in stdout


def test_build_pin_audit_rejects_hardcoded_build_script_versions(tmp_path):
    """Even a lock-matching literal in a discovered build script fails audit."""
    repo = _build_pin_fixture(tmp_path)
    build_script = repo / "vm_prep/nested/build-tool.sh"
    build_script.write_text(
        build_script.read_text(encoding="utf-8")
        + "VIRTIOFSD_VERSION=1.13.2\n"
        "VERSION=99.99.99\n"
        "VERSION=1.2\n"
        'GO_VERSION="${GO_VERSION:-1.24.4}"\n'
        "DEBIAN_SUITE=trixie\n"
        "curl https://example.invalid/releases/v1.24.4/tool.tar.gz\n",
        encoding="utf-8",
    )

    _stdout, stderr, rc = run(
        [sys.executable, str(repo / "release/check-build-pins"), str(repo)], cwd=repo
    )

    assert rc == 1
    assert "vm_prep/nested/build-tool.sh:5: VIRTIOFSD_VERSION=1.13.2" in stderr
    assert "vm_prep/nested/build-tool.sh:6: VERSION=99.99.99" in stderr
    assert "vm_prep/nested/build-tool.sh:7: VERSION=1.2" in stderr
    assert 'vm_prep/nested/build-tool.sh:8: GO_VERSION="${GO_VERSION:-1.24.4}"' in stderr
    assert "vm_prep/nested/build-tool.sh:9: DEBIAN_SUITE=trixie" in stderr
    assert "vm_prep/nested/build-tool.sh:10: version literal in URL" in stderr
    assert "Version literals" in stderr


def test_build_pin_audit_rejects_locked_values_as_direct_command_arguments(tmp_path):
    """Catch suite and tag pins passed directly to their build commands."""
    repo = _build_pin_fixture(tmp_path)
    build_script = repo / "vm_prep/nested/build-tool.sh"
    build_script.write_text(
        build_script.read_text(encoding="utf-8")
        + "mmdebstrap --variant=minbase trixie rootfs.tar http://example.invalid/debian\n"
        + "git clone --depth 1 \\\n"
        + "  --branch v6.12 https://example.invalid/kernel.git source\n"
        + "git clone --branch v99.99 https://example.invalid/other.git source\n",
        encoding="utf-8",
    )

    _stdout, stderr, rc = run(
        [sys.executable, str(repo / "release/check-build-pins"), str(repo)], cwd=repo
    )

    assert rc == 1
    assert "literal Debian suite argument trixie" in stderr
    assert "literal clone branch v6.12" in stderr
    assert "literal clone branch v99.99" in stderr
