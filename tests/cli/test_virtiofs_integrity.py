"""Public CLI acceptance for guest writes and independent host reads on both shares."""
import json
from functools import partial
from pathlib import Path

import pytest

from ..conftest import err_msg
from ..conftest import run as _run
from ..fixtures.virtiofs.virtiofs_probe_host import (
    ALL_CASES,
    run_host_validations,
    write_host_to_guest_markers,
)

PROBE_SOURCE = Path(__file__).resolve().parents[1] / "fixtures" / "virtiofs" / "virtiofs_probe_guest.c"


def _checked_run(command, **kwargs):
    stdout, stderr, code = _run(command, **kwargs)
    assert code == 0, err_msg(stdout, stderr)
    return stdout


@pytest.mark.timeout(300)
def test_virtiofs_integrity_on_both_shares(project):
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    probe = project.cwd / "virtiofs-integrity-probe"
    # libsqlite3-dev supplies the header and static archive on the host.
    # The guest payload carries SQLite code and needs no SQLite package there.
    run(["gcc", "-O2", "-Wall", "-Wextra", "-Werror", "-pthread", "-o", probe,
         PROBE_SOURCE, "-Wl,-Bstatic", "-lsqlite3", "-Wl,-Bdynamic", "-lm", "-ldl", "-pthread"])
    run([zaigr, "project", "vm", "start"], input="y\n", timeout=180)

    shares = (
        ("workspace", project.cwd / "virtiofs-integrity-workspace", "/home/user/workspace/virtiofs-integrity-workspace"),
        ("agent-state", project.store_dir / "agent-state" / "virtiofs-integrity-agent-state", "/home/user/.zaigr-agent-state/virtiofs-integrity-agent-state"),
    )
    all_guest = []
    all_host = []
    for label, host_dir, guest_dir in shares:
        host_dir.mkdir(mode=0o700)
        write_host_to_guest_markers(host_dir)
        output = run([zaigr, "project", "vm", "exec", "--", "/home/user/workspace/virtiofs-integrity-probe", guest_dir], timeout=90)
        guest = [json.loads(line) for line in output.splitlines() if line.startswith('{"case":')]
        assert len(guest) == 14, (label, output)
        assert {item["case"] for item in guest} == set(ALL_CASES), (label, guest)
        assert all(item["passed"] is True for item in guest), (label, guest)
        assert next(item for item in guest if item["case"] == "sqlite-wal-two-process")["detail"] == "busy,commit,retry,rows=0..31"
        all_guest.extend((label, item) for item in guest)

        host = run_host_validations(host_dir, label)
        assert len(host) == 14, host
        assert {item.case for item in host} == set(ALL_CASES), host
        assert all(item.passed for item in host), host
        all_host.extend(host)
    assert len(all_guest) == len(all_host) == 28
