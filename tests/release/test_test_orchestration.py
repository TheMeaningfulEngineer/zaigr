"""Exercise the real Makefile schedule with small external pytest substitutes."""

import json
import os
import shutil
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT, err_msg, run


@pytest.fixture
def gate_repo(tmp_path):
    """Provide isolated build inputs and observable, bounded pytest processes."""
    shutil.copy2(Path(REPO_ROOT) / "Makefile", tmp_path / "Makefile")
    commands = tmp_path / "bin"
    commands.mkdir()
    binary = tmp_path / "selected-zaigr"
    binary.write_text("#!/bin/sh\nexit 0\n")
    binary.chmod(0o755)
    events = tmp_path / "events"
    events.mkdir()
    fake_pytest = commands / "pytest"
    fake_pytest.write_text("""#!/usr/bin/env python3
import json
import os
import sys
import time
from pathlib import Path

suite = next(arg.split('/')[1] for arg in sys.argv[1:]
             if arg.startswith('tests/') and arg != 'tests/pytest.ini')
events = Path('events')
record = {'args': sys.argv[1:], 'binary': os.environ.get('ZAIGR_TEST_BINARY'),
          'finished_before_start': sorted(p.stem for p in events.glob('*.finished'))}
(events / (suite + '.started')).write_text(json.dumps(record))
if os.environ.get('EXPECT_OVERLAP') and suite in ('cli', 'install'):
    peer = 'install' if suite == 'cli' else 'cli'
    deadline = time.monotonic() + 5
    while not (events / (peer + '.started')).exists():
        if time.monotonic() > deadline:
            sys.exit('peer did not start concurrently')
        time.sleep(0.01)
code = 17 if os.environ.get('FAIL_SUITE') == suite else 0
(events / (suite + '.finished')).write_text(str(code))
print(suite + ' completed', flush=True)
sys.exit(code)
""")
    fake_pytest.chmod(0o755)
    env = {key: value for key, value in os.environ.items() if key not in {
        "MAKEFLAGS", "MFLAGS", "MAKEOVERRIDES", "ZAIGR_TEST_BINARY",
        "PYTEST_XDIST_WORKERS", "PYTEST_OVERLAP_WORKERS", "PYTEST_BUILTIN_WORKERS",
        "EXPECT_OVERLAP", "FAIL_SUITE",
    }}
    env.update({"PATH": f"{commands}:{env['PATH']}", "ZAIGR_TEST_BINARY": str(binary)})
    return tmp_path, env


@pytest.mark.parametrize("workers", [None, "2"])
def test_all_overlaps_only_cli_install_after_versioning(gate_repo, workers):
    repo, env = gate_repo
    env["EXPECT_OVERLAP"] = "1"
    if workers is not None:
        env["PYTEST_OVERLAP_WORKERS"] = workers
    out, err, rc = run(["make", "-j8", "test-all"], cwd=repo, env=env, timeout=15)
    assert rc == 0, err_msg(out, err)
    records = {
        path.stem: json.loads(path.read_text())
        for path in (repo / "events").glob("*.started")
    }
    assert set(records) == {"release", "versioning", "cli", "install", "builtin"}
    assert records["release"]["finished_before_start"] == []
    assert records["versioning"]["finished_before_start"] == ["release"]
    for suite in ("cli", "install"):
        assert {"release", "versioning"} <= set(records[suite]["finished_before_start"])
        assert "builtin" not in records[suite]["finished_before_start"]
    assert records["builtin"]["finished_before_start"] == ["cli", "install", "release", "versioning"]
    cli_args = records["cli"]["args"]
    assert cli_args[cli_args.index("-n") + 1] == (workers or "4")
    assert "--maxschedchunk=1" in cli_args
    assert "-n" not in records["install"]["args"]
    assert records["cli"]["binary"] == env["ZAIGR_TEST_BINARY"]
    assert records["install"]["binary"] == env["ZAIGR_TEST_BINARY"]


@pytest.mark.parametrize("failed_suite", ["cli", "install"])
def test_overlap_waits_for_both_suites_and_propagates_failure(gate_repo, failed_suite):
    repo, env = gate_repo
    env.update({"EXPECT_OVERLAP": "1", "FAIL_SUITE": failed_suite})
    out, err, rc = run(["make", "test-all"], cwd=repo, env=env, timeout=15)
    assert rc != 0, err_msg(out, err)
    assert (repo / "events" / f"{failed_suite}.finished").read_text() == "17"
    peer = "install" if failed_suite == "cli" else "cli"
    assert (repo / "events" / f"{peer}.finished").read_text() == "0"
    assert not (repo / "events" / "builtin.started").exists()


def test_standalone_cli_keeps_eight_workers(gate_repo):
    repo, env = gate_repo
    out, err, rc = run(["make", "test-cli"], cwd=repo, env=env, timeout=15)
    assert rc == 0, err_msg(out, err)
    record = json.loads((repo / "events" / "cli.started").read_text())
    assert record["args"][record["args"].index("-n") + 1] == "8"
    assert not (repo / "events" / "install.started").exists()


def test_overlap_checks_selected_binary_before_starting_suites(gate_repo):
    repo, env = gate_repo
    env["ZAIGR_TEST_BINARY"] = str(repo / "missing-binary")
    out, err, rc = run(["make", "test-cli-install"], cwd=repo, env=env, timeout=15)
    assert rc != 0, err_msg(out, err)
    assert "Missing executable test binary" in out + err
    assert not list((repo / "events").iterdir())


@pytest.mark.parametrize("failed_suite", ["release", "versioning"])
def test_all_stops_before_vm_suites_when_an_earlier_phase_fails(gate_repo, failed_suite):
    repo, env = gate_repo
    env["FAIL_SUITE"] = failed_suite
    out, err, rc = run(["make", "-j8", "test-all"], cwd=repo, env=env, timeout=15)
    assert rc != 0, err_msg(out, err)
    started = {path.stem for path in (repo / "events").glob("*.started")}
    assert started == ({"release"} if failed_suite == "release" else {"release", "versioning"})


def test_all_builds_once_then_uses_that_binary_for_vm_suites(gate_repo):
    repo, env = gate_repo
    env.pop("ZAIGR_TEST_BINARY")
    env["EXPECT_OVERLAP"] = "1"
    prep = repo / "vm_prep"
    prep.mkdir()
    for script in ("build-kernel.sh", "build-base-rootfs.sh"):
        path = prep / script
        path.write_text("#!/bin/sh\nexit 0\n")
        path.chmod(0o755)
    go = repo / "bin" / "go"
    go.write_text("""#!/bin/sh
set -eu
test -f events/versioning.finished
printf 'build\\n' >> events/builds
printf '#!/bin/sh\\nexit 0\\n' > zaigr
chmod +x zaigr
""")
    go.chmod(0o755)
    out, err, rc = run(["make", "-j8", "test-all"], cwd=repo, env=env, timeout=15)
    assert rc == 0, err_msg(out, err)
    assert (repo / "events" / "builds").read_text() == "build\n"
    for suite in ("cli", "install", "builtin"):
        record = json.loads((repo / "events" / f"{suite}.started").read_text())
        assert record["binary"] == str(repo / "zaigr")
