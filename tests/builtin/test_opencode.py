"""Acceptance coverage for the real OpenCode CLI and its private server."""

import json
import re
import time
from concurrent.futures import ThreadPoolExecutor
from functools import partial

import pexpect
import pytest

from ..conftest import err_msg, run, spawn_interactive


def _checked_run(cmd, **kwargs):
    stdout, stderr, rc = run(cmd, **kwargs)
    assert rc == 0, err_msg(stdout, stderr)
    return stdout


@pytest.mark.timeout(1800)
def test_opencode_installs_launches_and_preserves_sessions(project, setup_factory):
    checked = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    state = project.store_dir / "agent-state" / "opencode"
    guest_state = "/home/user/.zaigr-agent-state/opencode"
    opencode_env = (
        f"env XDG_CONFIG_HOME={guest_state}/config "
        f"XDG_DATA_HOME={guest_state}/data "
        f"XDG_STATE_HOME={guest_state}/state "
        f"XDG_CACHE_HOME={guest_state}/cache"
    )

    shell = spawn_interactive(
        f"{zaigr} shell --preset opencode --ram 2048 --cpu 2",
        cwd=project.cwd,
        env=project.env,
        timeout=1200,
    )
    second = None
    try:
        shell.expect(r"Initialize project and continue\? \[y/N\]")
        shell.sendline("y")
        shell.expect(r":: Setup applied to (?:stopped project image|running project VM):")
        shell.expect("Build")
        shell.expect("auto")

        second = spawn_interactive(
            f"{zaigr} shell --preset opencode",
            cwd=project.cwd,
            env=project.env,
            timeout=120,
        )
        second.expect("Build")
        second.expect("auto")
        listeners = checked(f"{zaigr} project vm exec -- ss -Hltnp")
        addresses = [
            line.split()[3] for line in listeners.splitlines() if '"opencode.exe"' in line
        ]
        assert len(addresses) == 2, listeners
        assert len(set(addresses)) == 2
        for index, address in enumerate(addresses):
            assert address.startswith("127.0.0.1:"), address
            setup_factory.preset(
                name=f"opencode-observer-{index}",
                run=(
                    "exec curl -sS --max-time 5 -o /dev/null -w '%{http_code}\\n' "
                    f"http://{address}/api/session "
                    f"-o /dev/null http://{address}/api/credential"
                ),
                setups=[],
            )
            response = checked(f"{zaigr} shell --preset opencode-observer-{index}")
            assert len(re.findall(r"\b401\b", response)) == 2, response

        # Concurrent API writers share the same database with the two TUIs.
        with ThreadPoolExecutor(max_workers=2) as workers:
            writes = [workers.submit(
                checked,
                f"{zaigr} project vm exec -- {opencode_env} opencode api --standalone "
                f"session.create --data '{{\"title\":\"Zaigr persistence test {index}\"}}'",
            ) for index in range(2)]
            session_ids = [json.loads(write.result())["data"]["id"] for write in writes]
        assert len(set(session_ids)) == 2
        shell.send("/exit")
        shell.expect("Exit the app")
        shell.send("\r")
        shell.expect(pexpect.EOF, timeout=30)
        # Closing the terminal exercises client disconnection and server cleanup.
        second.close(force=True)
    finally:
        shell.close(force=True)
        if second is not None:
            second.close(force=True)
    assert shell.exitstatus == 0, shell.transcript.tail(4000)

    deadline = time.monotonic() + 20
    while True:
        listeners = checked(f"{zaigr} project vm exec -- ss -Hltnp")
        if '"opencode.exe"' not in listeners:
            break
        assert time.monotonic() < deadline, listeners
        time.sleep(0.2)

    applied = checked(f"{zaigr} project setup list --applied")
    assert "opencode" in applied
    assert "opencode v2.0.26" in checked(
        f"{zaigr} project vm exec -- opencode --version"
    )
    assert (state / "data/opencode/opencode.db").is_file()
    assert not (project.cwd / ".opencode").exists()

    # A real exported credential structure with an intentionally unusable key.
    # No inference is sent. Import/export checks preserve the exact stored value.
    credentials = [{
        "id": "cred_12c1a2c69001eXVUgjklFfYvhr",
        "integrationID": "scaleway",
        "label": "Zaigr storage test",
        "active": True,
        "value": {"type": "key", "key": "zaigr-storage-test-not-a-real-key"},
    }]
    checked(
        f"{zaigr} project vm exec -- {opencode_env} opencode auth import --standalone",
        input=json.dumps(credentials),
    )
    checked(f"{zaigr} project vm stop", timeout=60)
    checked(f"{zaigr} project vm start", timeout=120)
    sessions = checked(
        f"{zaigr} project vm exec -- {opencode_env} "
        "opencode session list --standalone --format json"
    )
    assert all(session_id in sessions for session_id in session_ids)
    assert "Zaigr persistence test" in sessions
    saved = json.loads(checked(
        f"{zaigr} project vm exec -- {opencode_env} opencode auth export --standalone"
    ))
    assert saved == credentials

    stdout, stderr, rc = run(
        f"{zaigr} project vm exec -- curl -fsS --max-time 5 https://example.com",
        cwd=project.cwd,
        env=project.env,
        timeout=15,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert "Example Domain" not in stdout

    # Rebuild replays the setup; clean requires installation on the next launch.
    checked(f"{zaigr} project vm stop", timeout=60)
    checked(f"{zaigr} project rebuild", timeout=1200)
    checked(f"{zaigr} project vm start", timeout=120)
    sessions = checked(
        f"{zaigr} project vm exec -- {opencode_env} "
        "opencode session list --standalone --format json"
    )
    assert all(session_id in sessions for session_id in session_ids)
    assert json.loads(checked(
        f"{zaigr} project vm exec -- {opencode_env} opencode auth export --standalone"
    )) == credentials

    checked(f"{zaigr} project vm stop", timeout=60)
    checked(f"{zaigr} project clean", timeout=180)
    # A JSONC user config must survive without a newly seeded JSON shadowing it.
    config = state / "config/opencode/opencode.json"
    config.rename(config.with_suffix(".jsonc"))
    user_config = config.with_suffix(".jsonc").read_text() + "\n// user setting\n"
    config.with_suffix(".jsonc").write_text(user_config)
    reopened = spawn_interactive(
        f"{zaigr} shell --preset opencode",
        cwd=project.cwd,
        env=project.env,
        timeout=1200,
    )
    try:
        reopened.expect(r":: Setup applied to (?:stopped project image|running project VM):")
        reopened.expect("Build")
        reopened.expect("auto")
        reopened.send("/models")
        reopened.expect("Switch model")
        reopened.send("\r")
        reopened.send("scaleway")
        reopened.expect("Scaleway", timeout=30)
        reopened.send("\x1b")
        reopened.expect("Build")
        reopened.send("/exit")
        reopened.expect("Exit the app")
        reopened.send("\r")
        reopened.expect(pexpect.EOF, timeout=30)
    finally:
        reopened.close(force=True)
    assert reopened.exitstatus == 0, reopened.transcript.tail(4000)
    assert not config.exists()
    assert config.with_suffix(".jsonc").read_text() == user_config
    sessions = checked(
        f"{zaigr} project vm exec -- {opencode_env} "
        "opencode session list --standalone --format json"
    )
    assert all(session_id in sessions for session_id in session_ids)
    assert json.loads(checked(
        f"{zaigr} project vm exec -- {opencode_env} opencode auth export --standalone"
    )) == credentials
