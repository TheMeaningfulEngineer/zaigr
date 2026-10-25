"""Exercise the real Makefile schedule with small external pytest substitutes."""

import json
import os
import shutil
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT, err_msg, run


@pytest.fixture
def schedule_repo(tmp_path):
    """Provide isolated build inputs and observable pytest processes."""
    shutil.copy2(Path(REPO_ROOT) / "Makefile", tmp_path / "Makefile")
    commands = tmp_path / "bin"
    commands.mkdir()
    binary = tmp_path / "selected-zaigr"
    binary.write_text("#!/bin/sh\nexit 0\n")
    binary.chmod(0o755)
    events = tmp_path / "events"
    events.mkdir()
    fake_pytest = commands / "pytest"
    fake_pytest.write_text('''#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

suite = next(arg.split('/')[1] for arg in sys.argv[1:]
             if arg.startswith('tests/') and arg != 'tests/pytest.ini')
events = Path('events')
record = {'args': sys.argv[1:], 'binary': os.environ.get('ZAIGR_TEST_BINARY'),
          'distros': os.environ.get('CLOUDVM_DISTROS'),
          'finished_before_start': sorted(p.stem for p in events.glob('*.finished'))}
(events / (suite + '.started')).write_text(json.dumps(record))
code = 17 if os.environ.get('FAIL_SUITE') == suite else 0
(events / (suite + '.finished')).write_text(str(code))
print(suite + ' completed', flush=True)
sys.exit(code)
''')
    fake_pytest.chmod(0o755)
    env = {
        key: value for key, value in os.environ.items()
        if key not in {
            "MAKEFLAGS", "MFLAGS", "MAKEOVERRIDES", "ZAIGR_TEST_BINARY",
            "PYTEST_XDIST_WORKERS", "PYTEST_OVERLAP_WORKERS", "PYTEST_BUILTIN_WORKERS",
            "CLOUDVM_DISTROS", "FAIL_SUITE",
        }
    }
    env.update({"PATH": f"{commands}:{env['PATH']}", "ZAIGR_TEST_BINARY": str(binary)})
    return tmp_path, env


def _records(repo):
    """Read the pytest invocations recorded by the fake executable."""
    return {
        path.stem: json.loads(path.read_text())
        for path in (repo / "events").glob("*.started")
    }


@pytest.mark.parametrize("workers", [None, "2"])
def test_all_runs_cloud_install_serially_after_cli(schedule_repo, workers):
    repo, env = schedule_repo
    if workers is not None:
        env["PYTEST_XDIST_WORKERS"] = workers
    out, err, rc = run(["make", "-j8", "test-all"], cwd=repo, env=env, timeout=15)
    assert rc == 0, err_msg(out, err)
    records = _records(repo)
    assert set(records) == {"release", "versioning", "cli", "install", "builtin"}
    assert records["release"]["finished_before_start"] == []
    assert records["versioning"]["finished_before_start"] == ["release"]
    assert records["cli"]["finished_before_start"] == ["release", "versioning"]
    assert records["install"]["finished_before_start"] == ["cli", "release", "versioning"]
    assert records["builtin"]["finished_before_start"] == ["cli", "install", "release", "versioning"]
    cli_args = records["cli"]["args"]
    assert cli_args[cli_args.index("-n") + 1] == (workers or "8")
    assert "-n" not in records["install"]["args"]
    assert records["install"]["distros"] == ""
    assert records["cli"]["binary"] == env["ZAIGR_TEST_BINARY"]
    assert records["install"]["binary"] == env["ZAIGR_TEST_BINARY"]


def test_install_passes_distro_subset_to_pytest(schedule_repo):
    repo, env = schedule_repo
    out, err, rc = run(
        ["make", "test-install", "CLOUDVM_DISTROS=ubuntu-24.04,debian-13"],
        cwd=repo, env=env, timeout=15,
    )
    assert rc == 0, err_msg(out, err)
    record = _records(repo)["install"]
    assert record["distros"] == "ubuntu-24.04,debian-13"


@pytest.mark.parametrize("failed_suite", ["cli", "install"])
def test_serial_vm_suites_stop_before_builtin_after_failure(schedule_repo, failed_suite):
    repo, env = schedule_repo
    env["FAIL_SUITE"] = failed_suite
    out, err, rc = run(["make", "test-cli-install"], cwd=repo, env=env, timeout=15)
    assert rc != 0, err_msg(out, err)
    records = _records(repo)
    assert failed_suite in records
    assert "builtin" not in records
    if failed_suite == "cli":
        assert "install" not in records
    else:
        assert records["install"]["finished_before_start"] == ["cli"]


def test_standalone_cli_keeps_eight_workers(schedule_repo):
    repo, env = schedule_repo
    out, err, rc = run(["make", "test-cli"], cwd=repo, env=env, timeout=15)
    assert rc == 0, err_msg(out, err)
    record = _records(repo)["cli"]
    assert record["args"][record["args"].index("-n") + 1] == "8"
    assert "install" not in _records(repo)


def test_suite_targets_check_selected_binary_before_starting_pytest(schedule_repo):
    repo, env = schedule_repo
    env["ZAIGR_TEST_BINARY"] = str(repo / "missing-binary")
    out, err, rc = run(["make", "test-cli-install"], cwd=repo, env=env, timeout=15)
    assert rc != 0, err_msg(out, err)
    assert "Missing executable test binary" in out + err
    assert not list((repo / "events").iterdir())


@pytest.mark.parametrize("failed_suite", ["release", "versioning"])
def test_all_stops_before_vm_suites_when_an_earlier_phase_fails(schedule_repo, failed_suite):
    repo, env = schedule_repo
    env["FAIL_SUITE"] = failed_suite
    out, err, rc = run(["make", "-j8", "test-all"], cwd=repo, env=env, timeout=15)
    assert rc != 0, err_msg(out, err)
    started = set(_records(repo))
    assert started == ({"release"} if failed_suite == "release" else {"release", "versioning"})


def test_all_builds_once_then_uses_that_binary_for_vm_suites(schedule_repo):
    repo, env = schedule_repo
    env.pop("ZAIGR_TEST_BINARY")
    prep = repo / "vm_prep"
    prep.mkdir()
    for script in ("build-kernel.sh", "build-base-rootfs.sh", "build-virtiofsd.sh", "fetch-slirp4netns.sh"):
        path = prep / script
        path.write_text("#!/bin/sh\nexit 0\n")
        path.chmod(0o755)
    go = repo / "bin" / "go"
    go.write_text('''#!/bin/sh
set -eu
test -f events/versioning.finished
printf 'build\\n' >> events/builds
printf '#!/bin/sh\\nexit 0\\n' > zaigr
chmod +x zaigr
''')
    go.chmod(0o755)
    out, err, rc = run(["make", "-j8", "test-all"], cwd=repo, env=env, timeout=15)
    assert rc == 0, err_msg(out, err)
    assert (repo / "events" / "builds").read_text() == "build\n"
    for suite in ("cli", "install", "builtin"):
        assert _records(repo)[suite]["binary"] == str(repo / "zaigr")
