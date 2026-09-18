"""Acceptance coverage for isolation between concurrent preset sessions."""

import shlex
import shutil
import socket
from functools import partial

import pexpect
import pytest

from ..conftest import SetupFactory, err_msg, spawn_interactive
from ..conftest import run as _run


def _checked_run(cmd, **kwargs):
    stdout, stderr, rc = _run(cmd, **kwargs)
    assert rc == 0, err_msg(stdout, stderr)
    return stdout


def _expect_denied(shell, denied_marker, allowed_marker):
    outcome = shell.expect_exact([denied_marker, allowed_marker], timeout=20)
    assert outcome == 0, shell.transcript.tail(4000)


@pytest.mark.timeout(300)
def test_internal_hard_links_are_allowed_but_cross_preset_links_are_rejected(
    project, setup_factory
):
    """Hard links are safe within one preset but cannot cross its boundary."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    marker = project.cwd / "hard-link-preset-ran"

    setup_factory.preset(
        name="hard-link-alpha",
        run="printf 'ran\\n' >> hard-link-preset-ran",
        setups=[],
    )

    run(f"{zaigr} project vm start", input="y\n", timeout=180)
    run(
        f"{zaigr} project vm exec -- mkdir -p "
        "/home/user/.zaigr-agent-state/hard-link-alpha/file-history/session-a "
        "/home/user/.zaigr-agent-state/hard-link-alpha/file-history/session-b "
        "/home/user/.zaigr-agent-state/hard-link-beta",
        timeout=20,
    )
    run(
        f"{zaigr} project vm exec -- tee "
        "/home/user/.zaigr-agent-state/hard-link-alpha/"
        "file-history/session-a/snapshot@v1",
        input="shared-inode-secret\n",
        timeout=20,
    )
    run(
        f"{zaigr} project vm exec -- ln "
        "/home/user/.zaigr-agent-state/hard-link-alpha/"
        "file-history/session-a/snapshot@v1 "
        "/home/user/.zaigr-agent-state/hard-link-alpha/"
        "file-history/session-b/snapshot@v1",
        timeout=20,
    )

    run(
        f"{zaigr} shell --preset hard-link-alpha",
        timeout=30,
    )
    assert marker.read_text(encoding="utf-8") == "ran\n"

    run(
        f"{zaigr} project vm exec -- ln "
        "/home/user/.zaigr-agent-state/hard-link-alpha/"
        "file-history/session-a/snapshot@v1 "
        "/home/user/.zaigr-agent-state/hard-link-beta/credential.txt",
        timeout=20,
    )

    stdout, stderr, rc = _run(
        f"{zaigr} shell --preset hard-link-alpha",
        cwd=project.cwd,
        env=project.env,
        timeout=30,
    )
    assert rc != 0, err_msg(stdout, stderr)
    message = stdout + stderr
    unsafe_path = (
        project.store_dir
        / "agent-state"
        / "hard-link-alpha"
        / "file-history"
        / "session-a"
        / "snapshot@v1"
    )
    assert str(unsafe_path) in message
    assert "unsafe preset state inode has 3 hard links" in message
    assert "only 2 inside preset hard-link-alpha" in message
    assert "copy the external link to a new inode" in message
    assert marker.read_text(encoding="utf-8") == "ran\n"

    run(
        f"{zaigr} project vm exec -- rm "
        "/home/user/.zaigr-agent-state/hard-link-beta/credential.txt",
        timeout=20,
    )
    run(
        f"{zaigr} project vm exec -- mkfifo "
        "/home/user/.zaigr-agent-state/hard-link-alpha/channel",
        timeout=20,
    )
    run(
        f"{zaigr} project vm exec -- ln "
        "/home/user/.zaigr-agent-state/hard-link-alpha/channel "
        "/home/user/.zaigr-agent-state/hard-link-beta/channel",
        timeout=20,
    )

    stdout, stderr, rc = _run(
        f"{zaigr} shell --preset hard-link-alpha",
        cwd=project.cwd,
        env=project.env,
        timeout=30,
    )
    assert rc != 0, err_msg(stdout, stderr)
    message = stdout + stderr
    assert "unsafe preset state inode has 2 hard links" in message
    assert "only 1 inside preset hard-link-alpha" in message
    assert marker.read_text(encoding="utf-8") == "ran\n"


@pytest.mark.timeout(360)
def test_preset_launch_cleans_environment_fds_and_ignores_host_ssh_config(
    project, setup_factory
):
    """Host SSH policy and launcher process state cannot enter the preset."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    setup_factory(
        setup_name="preset-launch-leaks",
        script_content=r"""
printf 'launcher-fd-secret\n' > /root/launcher-fd-secret
cat > /usr/local/lib/zaigr/test-root-shell <<'EOF'
#!/bin/bash
export ZAIGR_TEST_INHERITED_ENV=launcher-environment-secret
exec 9< /root/launcher-fd-secret
exec /bin/bash "$@"
EOF
chmod 0755 /usr/local/lib/zaigr/test-root-shell
usermod --shell /usr/local/lib/zaigr/test-root-shell root
""",
    )

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as port_socket:
        port_socket.bind(("127.0.0.1", 0))
        local_forward_port = port_socket.getsockname()[1]
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as port_socket:
        port_socket.bind(("127.0.0.1", 0))
        dynamic_forward_port = port_socket.getsockname()[1]
    remote_forward_port = 22999

    preset_script = r"""
unexpected="$(
    env | sed 's/=.*//' | grep -Ev \
        '^(HOME|LOGNAME|PATH|PWD|SHELL|SHLVL|TERM|USER|WORKSPACE|XDG_RUNTIME_DIR|_)$' || true
)"
if [[ -n "$unexpected" ]]; then
    printf 'UNEXPECTED_ENV=%s\n' "$unexpected"
else
    printf 'ENV_ALLOWLIST_OK\n'
fi
if [[ -e /proc/$$/fd/9 ]]; then
    printf 'LAUNCHER_FD_LEAK=%s\n' "$(readlink /proc/$$/fd/9)"
else
    printf 'LAUNCHER_FDS_CLEAN\n'
fi
if [[ -v ZAIGR_TEST_INHERITED_ENV || -v PRESET_HOST_SECRET || -v SSH_AUTH_SOCK ]]; then
    printf 'INHERITED_CREDENTIAL_ENV_PRESENT\n'
else
    printf 'INHERITED_CREDENTIAL_ENV_CLEAN\n'
fi
if (: <> /dev/tcp/127.0.0.1/__REMOTE_FORWARD_PORT__) 2>/dev/null; then
    printf 'REMOTE_FORWARD_PRESENT\n'
else
    printf 'REMOTE_FORWARD_ABSENT\n'
fi
printf 'CLEAN_PRESET_READY=%s|%s|%s|%s|%s|%s\n' \
    "$USER" "$LOGNAME" "$HOME" "$PWD" "$WORKSPACE" "$TERM"
stty -echo
read -r _
""".replace("__REMOTE_FORWARD_PORT__", str(remote_forward_port))
    setup_factory.preset(
        name="clean-launch",
        run=preset_script,
        setups=[],
    )

    run(
        f"{zaigr} project setup run preset-launch-leaks",
        input="y\n",
        timeout=180,
    )

    ssh_dir = project.home / ".ssh"
    ssh_dir.mkdir(mode=0o700)
    local_command_marker = project.cwd / "host-ssh-config-was-used"
    (ssh_dir / "config").write_text(
        "Host *\n"
        "    ForwardAgent yes\n"
        f"    LocalForward {local_forward_port} 127.0.0.1:22\n"
        f"    DynamicForward {dynamic_forward_port}\n"
        f"    RemoteForward {remote_forward_port} 127.0.0.1:22\n"
        "    Tunnel yes\n"
        "    PermitLocalCommand yes\n"
        f"    LocalCommand touch {local_command_marker}\n"
        "    SendEnv PRESET_HOST_SECRET\n",
        encoding="utf-8",
    )
    ssh_shim_dir = project.cwd / "ssh-shim"
    ssh_shim_dir.mkdir()
    real_ssh = shutil.which("ssh")
    assert real_ssh is not None
    ssh_shim = ssh_shim_dir / "ssh"
    ssh_shim.write_text(
        "#!/bin/sh\n"
        f"exec {shlex.quote(real_ssh)} -F {shlex.quote(str(ssh_dir / 'config'))} \"$@\"\n",
        encoding="utf-8",
    )
    ssh_shim.chmod(0o755)
    hostile_env = project.env
    hostile_env["PATH"] = f"{ssh_shim_dir}:{hostile_env['PATH']}"
    hostile_env["PRESET_HOST_SECRET"] = "host-environment-secret"
    agent_path = project.cwd / "host-agent.sock"
    hostile_env["SSH_AUTH_SOCK"] = str(agent_path)

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as agent_socket:
        agent_socket.bind(str(agent_path))
        agent_socket.listen()
        shell = spawn_interactive(
            f"{zaigr} shell --preset clean-launch",
            cwd=project.cwd,
            env=hostile_env,
            timeout=180,
        )
        try:
            shell.expect_exact("ENV_ALLOWLIST_OK", timeout=180)
            shell.expect_exact("LAUNCHER_FDS_CLEAN", timeout=20)
            shell.expect_exact("INHERITED_CREDENTIAL_ENV_CLEAN", timeout=20)
            shell.expect_exact("REMOTE_FORWARD_ABSENT", timeout=20)
            shell.expect(
                r"CLEAN_PRESET_READY=user\|user\|/home/user\|"
                r"/home/user/workspace\|/home/user/workspace\|[^\r\n]+",
                timeout=20,
            )

            for port in (local_forward_port, dynamic_forward_port):
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                    probe.settimeout(1)
                    with pytest.raises(OSError):
                        probe.connect(("127.0.0.1", port))

            assert not local_command_marker.exists()
            shell.sendline("done")
            shell.expect(pexpect.EOF, timeout=20)
            shell.close()
            assert shell.exitstatus == 0
        finally:
            if shell.isalive():
                shell.close(force=True)


@pytest.mark.timeout(300)
def test_concurrent_presets_isolate_state_processes_and_nested_ssh(
    project, setup_factory
):
    """Concurrent presets share one VM and workspace, but not credentials."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    setup_factory.preset(
        name="isolation-alpha",
        run=r"""
# Re-exec so the test credential is present in /proc's initial environment.
if [ "${PRESET_FIXTURE_REEXEC:-}" != isolation-alpha ]; then
    export PRESET_FIXTURE_REEXEC=isolation-alpha
    export PRESET_CREDENTIAL=alpha-environment-secret
    exec bash "$0"
fi
state=/home/user/.zaigr-agent-state/isolation-alpha
exec 9< "$state/open-credential.txt"
stty -echo
printf 'ALPHA_READY local_pid=%s\n' "$$"
while IFS= read -r command; do
    eval "$command"
done
""",
        setups=[],
    )
    setup_factory.preset(
        name="isolation-beta",
        run=r"""
# Re-exec so the test credential is present in /proc's initial environment.
if [ "${PRESET_FIXTURE_REEXEC:-}" != isolation-beta ]; then
    export PRESET_FIXTURE_REEXEC=isolation-beta
    export PRESET_CREDENTIAL=beta-environment-secret
    exec bash "$0"
fi
state=/home/user/.zaigr-agent-state/isolation-beta
exec 9< "$state/open-credential.txt"
stty -echo
printf 'BETA_READY local_pid=%s\n' "$$"
while IFS= read -r command; do
    eval "$command"
done
""",
        setups=[],
    )

    run(f"{zaigr} project vm start", input="y\n", timeout=180)
    initial_boot_id = run(
        f"{zaigr} project vm exec -- cat /proc/sys/kernel/random/boot_id",
        timeout=20,
    ).strip()
    run(
        f"{zaigr} project vm exec -- mkdir -p "
        "/home/user/.zaigr-agent-state/isolation-alpha",
        timeout=20,
    )
    run(
        f"{zaigr} project vm exec -- mkdir -p "
        "/home/user/.zaigr-agent-state/isolation-beta",
        timeout=20,
    )
    run(
        f"{zaigr} project vm exec -- tee "
        "/home/user/.zaigr-agent-state/isolation-alpha/state.txt",
        input="alpha-existing-state\n",
        timeout=20,
    )
    run(
        f"{zaigr} project vm exec -- tee "
        "/home/user/.zaigr-agent-state/isolation-beta/state.txt",
        input="beta-existing-state\n",
        timeout=20,
    )
    run(
        f"{zaigr} project vm exec -- tee "
        "/home/user/.zaigr-agent-state/isolation-alpha/open-credential.txt",
        input="alpha-open-fd-secret\n",
        timeout=20,
    )
    run(
        f"{zaigr} project vm exec -- tee "
        "/home/user/.zaigr-agent-state/isolation-beta/open-credential.txt",
        input="beta-open-fd-secret\n",
        timeout=20,
    )
    agent_state = project.store_dir / "agent-state"
    alpha_state = agent_state / "isolation-alpha"
    beta_state = agent_state / "isolation-beta"

    alpha = spawn_interactive(
        f"{zaigr} shell --preset isolation-alpha",
        cwd=project.cwd,
        env=project.env,
        timeout=180,
    )
    beta = None
    try:
        alpha.expect(r"ALPHA_READY local_pid=[0-9]+", timeout=180)

        beta = spawn_interactive(
            f"{zaigr} shell --preset isolation-beta",
            cwd=project.cwd,
            env=project.env,
            timeout=180,
        )
        beta.expect(r"BETA_READY local_pid=[0-9]+", timeout=120)

        # Resolve namespace-local fixture processes to the exact PIDs visible to
        # trusted VM commands. The direct reads below prove each target exists.
        alpha_pids = run(
            [
                zaigr,
                "project",
                "vm",
                "exec",
                "--",
                "bash",
                "-c",
                (
                    "for environ in /proc/[0-9]*/environ; do "
                    'if [[ -r "$environ" ]] && '
                    "tr '\\0' '\\n' < \"$environ\" 2>/dev/null | "
                    "grep -Fqx 'PRESET_CREDENTIAL=alpha-environment-secret'; then "
                    "pid=${environ#/proc/}; printf '%s\\n' \"${pid%/environ}\"; "
                    "fi; done"
                ),
            ],
            timeout=20,
        ).splitlines()
        assert len(alpha_pids) == 1, alpha_pids
        alpha_pid = alpha_pids[0]
        beta_pids = run(
            [
                zaigr,
                "project",
                "vm",
                "exec",
                "--",
                "bash",
                "-c",
                (
                    "for environ in /proc/[0-9]*/environ; do "
                    'if [[ -r "$environ" ]] && '
                    "tr '\\0' '\\n' < \"$environ\" 2>/dev/null | "
                    "grep -Fqx 'PRESET_CREDENTIAL=beta-environment-secret'; then "
                    "pid=${environ#/proc/}; printf '%s\\n' \"${pid%/environ}\"; "
                    "fi; done"
                ),
            ],
            timeout=20,
        ).splitlines()
        assert len(beta_pids) == 1, beta_pids
        beta_pid = beta_pids[0]
        assert alpha_pid != beta_pid

        alpha.sendline(
            "printf 'ALPHA_BOOT=%s\\n' \"$(cat /proc/sys/kernel/random/boot_id)\""
        )
        alpha.expect(r"ALPHA_BOOT=([0-9a-f-]{36})")
        alpha_boot_id = alpha.match.group(1)
        beta.sendline(
            "printf 'BETA_BOOT=%s\\n' \"$(cat /proc/sys/kernel/random/boot_id)\""
        )
        beta.expect(r"BETA_BOOT=([0-9a-f-]{36})")
        beta_boot_id = beta.match.group(1)
        assert alpha_boot_id == beta_boot_id == initial_boot_id

        alpha.sendline(
            "printf 'ALPHA_IDENTITY=%s|%s|%s|%s|%s\\n' "
            '"$USER" "$LOGNAME" "$HOME" "$PWD" "$WORKSPACE"'
        )
        alpha.expect_exact(
            "ALPHA_IDENTITY=user|user|/home/user|/home/user/workspace|"
            "/home/user/workspace"
        )
        beta.sendline(
            "printf 'BETA_IDENTITY=%s|%s|%s|%s|%s\\n' "
            '"$USER" "$LOGNAME" "$HOME" "$PWD" "$WORKSPACE"'
        )
        beta.expect_exact(
            "BETA_IDENTITY=user|user|/home/user|/home/user/workspace|"
            "/home/user/workspace"
        )

        alpha.sendline(
            "printf 'ALPHA_OWN_BEFORE=%s\\n' "
            '"$(cat /home/user/.zaigr-agent-state/isolation-alpha/state.txt)"'
        )
        alpha.expect_exact("ALPHA_OWN_BEFORE=alpha-existing-state")
        alpha.sendline(
            "printf 'alpha-updated-state\\n' > "
            "/home/user/.zaigr-agent-state/isolation-alpha/state.txt && "
            "printf 'ALPHA_OWN_AFTER=%s\\n' "
            '"$(cat /home/user/.zaigr-agent-state/isolation-alpha/state.txt)"'
        )
        alpha.expect_exact("ALPHA_OWN_AFTER=alpha-updated-state")

        beta.sendline(
            "printf 'BETA_OWN_BEFORE=%s\\n' "
            '"$(cat /home/user/.zaigr-agent-state/isolation-beta/state.txt)"'
        )
        beta.expect_exact("BETA_OWN_BEFORE=beta-existing-state")
        beta.sendline(
            "printf 'beta-updated-state\\n' > "
            "/home/user/.zaigr-agent-state/isolation-beta/state.txt && "
            "printf 'BETA_OWN_AFTER=%s\\n' "
            '"$(cat /home/user/.zaigr-agent-state/isolation-beta/state.txt)"'
        )
        beta.expect_exact("BETA_OWN_AFTER=beta-updated-state")

        trusted_identity = run(
            [
                zaigr,
                "project",
                "vm",
                "exec",
                "--",
                "bash",
                "-c",
                (
                    "printf '%s|%s|%s|%s|%s\\n' "
                    '"$USER" "$LOGNAME" "$HOME" "$PWD" "$WORKSPACE"'
                ),
            ],
            timeout=20,
        )
        assert trusted_identity.strip() == (
            "user|user|/home/user|/home/user/workspace|/home/user/workspace"
        )
        trusted_state_entries = run(
            f"{zaigr} project vm exec -- ls -1 /home/user/.zaigr-agent-state",
            timeout=20,
        )
        assert "isolation-alpha" in trusted_state_entries.splitlines()
        assert "isolation-beta" in trusted_state_entries.splitlines()
        assert (
            run(
                f"{zaigr} project vm exec -- cat "
                "/home/user/.zaigr-agent-state/isolation-alpha/state.txt",
                timeout=20,
            ).strip()
            == "alpha-updated-state"
        )
        assert (
            run(
                f"{zaigr} project vm exec -- cat "
                "/home/user/.zaigr-agent-state/isolation-beta/state.txt",
                timeout=20,
            ).strip()
            == "beta-updated-state"
        )
        run(
            [
                zaigr,
                "project",
                "vm",
                "exec",
                "--",
                "bash",
                "-c",
                "command -v ssh",
            ],
            timeout=20,
        )

        alpha_environment = run(
            [
                zaigr,
                "project",
                "vm",
                "exec",
                "--",
                "bash",
                "-c",
                f"tr '\\0' '\\n' < /proc/{alpha_pid}/environ",
            ],
            timeout=20,
        )
        assert "PRESET_CREDENTIAL=alpha-environment-secret" in (
            alpha_environment.splitlines()
        )
        beta_environment = run(
            [
                zaigr,
                "project",
                "vm",
                "exec",
                "--",
                "bash",
                "-c",
                f"tr '\\0' '\\n' < /proc/{beta_pid}/environ",
            ],
            timeout=20,
        )
        assert "PRESET_CREDENTIAL=beta-environment-secret" in (
            beta_environment.splitlines()
        )
        assert (
            run(
                f"{zaigr} project vm exec -- cat /proc/{alpha_pid}/fd/9",
                timeout=20,
            ).strip()
            == "alpha-open-fd-secret"
        )
        assert (
            run(
                f"{zaigr} project vm exec -- cat /proc/{beta_pid}/fd/9",
                timeout=20,
            ).strip()
            == "beta-open-fd-secret"
        )

        alpha.sendline(
            "if ls -A /home/user/.zaigr-agent-state >/dev/null 2>&1; then "
            "printf 'ALPHA_PARENT_ENUM_ALLOWED\\n'; else "
            "printf 'ALPHA_PARENT_ENUM_DENIED\\n'; fi"
        )
        _expect_denied(alpha, "ALPHA_PARENT_ENUM_DENIED", "ALPHA_PARENT_ENUM_ALLOWED")
        alpha.sendline(
            "if readlink -e /home/user/.zaigr-agent-state/isolation-beta "
            ">/dev/null 2>&1; then printf 'ALPHA_SIBLING_RESOLVE_ALLOWED\\n'; "
            "else printf 'ALPHA_SIBLING_RESOLVE_DENIED\\n'; fi"
        )
        _expect_denied(
            alpha, "ALPHA_SIBLING_RESOLVE_DENIED", "ALPHA_SIBLING_RESOLVE_ALLOWED"
        )
        alpha.sendline(
            "if stat /home/user/.zaigr-agent-state/isolation-beta "
            ">/dev/null 2>&1; then printf 'ALPHA_SIBLING_STAT_ALLOWED\\n'; "
            "else printf 'ALPHA_SIBLING_STAT_DENIED\\n'; fi"
        )
        _expect_denied(alpha, "ALPHA_SIBLING_STAT_DENIED", "ALPHA_SIBLING_STAT_ALLOWED")
        alpha.sendline(
            "if cat /home/user/.zaigr-agent-state/isolation-beta/state.txt "
            ">/dev/null 2>&1; then printf 'ALPHA_SIBLING_OPEN_ALLOWED\\n'; "
            "else printf 'ALPHA_SIBLING_OPEN_DENIED\\n'; fi"
        )
        _expect_denied(alpha, "ALPHA_SIBLING_OPEN_DENIED", "ALPHA_SIBLING_OPEN_ALLOWED")
        alpha.sendline(
            "if printf 'tampered\\n' >> "
            "/home/user/.zaigr-agent-state/isolation-beta/state.txt 2>/dev/null; "
            "then printf 'ALPHA_SIBLING_MODIFY_ALLOWED\\n'; else "
            "printf 'ALPHA_SIBLING_MODIFY_DENIED\\n'; fi"
        )
        _expect_denied(
            alpha, "ALPHA_SIBLING_MODIFY_DENIED", "ALPHA_SIBLING_MODIFY_ALLOWED"
        )
        alpha.sendline(
            "if mv /home/user/.zaigr-agent-state/isolation-beta/state.txt "
            "/home/user/.zaigr-agent-state/isolation-beta/state.moved "
            ">/dev/null 2>&1; then printf 'ALPHA_SIBLING_RENAME_ALLOWED\\n'; "
            "else printf 'ALPHA_SIBLING_RENAME_DENIED\\n'; fi"
        )
        _expect_denied(
            alpha, "ALPHA_SIBLING_RENAME_DENIED", "ALPHA_SIBLING_RENAME_ALLOWED"
        )
        alpha.sendline(
            "if rm /home/user/.zaigr-agent-state/isolation-beta/state.txt "
            ">/dev/null 2>&1; then printf 'ALPHA_SIBLING_DELETE_ALLOWED\\n'; "
            "else printf 'ALPHA_SIBLING_DELETE_DENIED\\n'; fi"
        )
        _expect_denied(
            alpha, "ALPHA_SIBLING_DELETE_DENIED", "ALPHA_SIBLING_DELETE_ALLOWED"
        )

        beta.sendline(
            "if ls -A /home/user/.zaigr-agent-state >/dev/null 2>&1; then "
            "printf 'BETA_PARENT_ENUM_ALLOWED\\n'; else "
            "printf 'BETA_PARENT_ENUM_DENIED\\n'; fi"
        )
        _expect_denied(beta, "BETA_PARENT_ENUM_DENIED", "BETA_PARENT_ENUM_ALLOWED")
        beta.sendline(
            "if readlink -e /home/user/.zaigr-agent-state/isolation-alpha "
            ">/dev/null 2>&1; then printf 'BETA_SIBLING_RESOLVE_ALLOWED\\n'; "
            "else printf 'BETA_SIBLING_RESOLVE_DENIED\\n'; fi"
        )
        _expect_denied(
            beta, "BETA_SIBLING_RESOLVE_DENIED", "BETA_SIBLING_RESOLVE_ALLOWED"
        )
        beta.sendline(
            "if stat /home/user/.zaigr-agent-state/isolation-alpha "
            ">/dev/null 2>&1; then printf 'BETA_SIBLING_STAT_ALLOWED\\n'; "
            "else printf 'BETA_SIBLING_STAT_DENIED\\n'; fi"
        )
        _expect_denied(beta, "BETA_SIBLING_STAT_DENIED", "BETA_SIBLING_STAT_ALLOWED")
        beta.sendline(
            "if cat /home/user/.zaigr-agent-state/isolation-alpha/state.txt "
            ">/dev/null 2>&1; then printf 'BETA_SIBLING_OPEN_ALLOWED\\n'; "
            "else printf 'BETA_SIBLING_OPEN_DENIED\\n'; fi"
        )
        _expect_denied(beta, "BETA_SIBLING_OPEN_DENIED", "BETA_SIBLING_OPEN_ALLOWED")
        beta.sendline(
            "if printf 'tampered\\n' >> "
            "/home/user/.zaigr-agent-state/isolation-alpha/state.txt 2>/dev/null; "
            "then printf 'BETA_SIBLING_MODIFY_ALLOWED\\n'; else "
            "printf 'BETA_SIBLING_MODIFY_DENIED\\n'; fi"
        )
        _expect_denied(
            beta, "BETA_SIBLING_MODIFY_DENIED", "BETA_SIBLING_MODIFY_ALLOWED"
        )
        beta.sendline(
            "if mv /home/user/.zaigr-agent-state/isolation-alpha/state.txt "
            "/home/user/.zaigr-agent-state/isolation-alpha/state.moved "
            ">/dev/null 2>&1; then printf 'BETA_SIBLING_RENAME_ALLOWED\\n'; "
            "else printf 'BETA_SIBLING_RENAME_DENIED\\n'; fi"
        )
        _expect_denied(
            beta, "BETA_SIBLING_RENAME_DENIED", "BETA_SIBLING_RENAME_ALLOWED"
        )
        beta.sendline(
            "if rm /home/user/.zaigr-agent-state/isolation-alpha/state.txt "
            ">/dev/null 2>&1; then printf 'BETA_SIBLING_DELETE_ALLOWED\\n'; "
            "else printf 'BETA_SIBLING_DELETE_DENIED\\n'; fi"
        )
        _expect_denied(
            beta, "BETA_SIBLING_DELETE_DENIED", "BETA_SIBLING_DELETE_ALLOWED"
        )

        alpha.sendline(
            f"if tr '\\0' '\\n' < /proc/{beta_pid}/environ 2>/dev/null | "
            "grep -Fqx 'PRESET_CREDENTIAL=beta-environment-secret'; then "
            "printf 'ALPHA_SIBLING_ENV_ALLOWED\\n'; else "
            "printf 'ALPHA_SIBLING_ENV_DENIED\\n'; fi"
        )
        _expect_denied(alpha, "ALPHA_SIBLING_ENV_DENIED", "ALPHA_SIBLING_ENV_ALLOWED")
        alpha.sendline(
            f"if grep -Fxq beta-open-fd-secret /proc/{beta_pid}/fd/9 "
            "2>/dev/null; then printf 'ALPHA_SIBLING_FD_ALLOWED\\n'; else "
            "printf 'ALPHA_SIBLING_FD_DENIED\\n'; fi"
        )
        _expect_denied(alpha, "ALPHA_SIBLING_FD_DENIED", "ALPHA_SIBLING_FD_ALLOWED")
        beta.sendline(
            f"if tr '\\0' '\\n' < /proc/{alpha_pid}/environ 2>/dev/null | "
            "grep -Fqx 'PRESET_CREDENTIAL=alpha-environment-secret'; then "
            "printf 'BETA_SIBLING_ENV_ALLOWED\\n'; else "
            "printf 'BETA_SIBLING_ENV_DENIED\\n'; fi"
        )
        _expect_denied(beta, "BETA_SIBLING_ENV_DENIED", "BETA_SIBLING_ENV_ALLOWED")
        beta.sendline(
            f"if grep -Fxq alpha-open-fd-secret /proc/{alpha_pid}/fd/9 "
            "2>/dev/null; then printf 'BETA_SIBLING_FD_ALLOWED\\n'; else "
            "printf 'BETA_SIBLING_FD_DENIED\\n'; fi"
        )
        _expect_denied(beta, "BETA_SIBLING_FD_DENIED", "BETA_SIBLING_FD_ALLOWED")

        alpha.sendline(
            "if ssh -o BatchMode=yes -o ConnectTimeout=5 "
            "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            "user@127.0.0.1 grep -Fxq beta-updated-state "
            "/home/user/.zaigr-agent-state/isolation-beta/state.txt "
            ">/dev/null 2>&1; then printf 'ALPHA_NESTED_SSH_ESCAPE_ALLOWED\\n'; "
            "else printf 'ALPHA_NESTED_SSH_ESCAPE_DENIED\\n'; fi"
        )
        _expect_denied(
            alpha, "ALPHA_NESTED_SSH_ESCAPE_DENIED", "ALPHA_NESTED_SSH_ESCAPE_ALLOWED"
        )
        beta.sendline(
            "if ssh -o BatchMode=yes -o ConnectTimeout=5 "
            "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            "user@127.0.0.1 grep -Fxq alpha-updated-state "
            "/home/user/.zaigr-agent-state/isolation-alpha/state.txt "
            ">/dev/null 2>&1; then printf 'BETA_NESTED_SSH_ESCAPE_ALLOWED\\n'; "
            "else printf 'BETA_NESTED_SSH_ESCAPE_DENIED\\n'; fi"
        )
        _expect_denied(
            beta, "BETA_NESTED_SSH_ESCAPE_DENIED", "BETA_NESTED_SSH_ESCAPE_ALLOWED"
        )

        alpha.sendline(
            "printf 'alpha-workspace-value\\n' > "
            "/home/user/workspace/alpha-shared.txt && "
            "printf 'ALPHA_WORKSPACE_WRITE_OK\\n'"
        )
        alpha.expect_exact("ALPHA_WORKSPACE_WRITE_OK")
        beta.sendline(
            "printf 'beta-workspace-value\\n' > "
            "/home/user/workspace/beta-shared.txt && "
            "printf 'BETA_WORKSPACE_WRITE_OK\\n'"
        )
        beta.expect_exact("BETA_WORKSPACE_WRITE_OK")
        alpha.sendline(
            "printf 'ALPHA_READS_BETA_WORKSPACE=%s\\n' "
            '"$(cat /home/user/workspace/beta-shared.txt)"'
        )
        alpha.expect_exact("ALPHA_READS_BETA_WORKSPACE=beta-workspace-value")
        beta.sendline(
            "printf 'BETA_READS_ALPHA_WORKSPACE=%s\\n' "
            '"$(cat /home/user/workspace/alpha-shared.txt)"'
        )
        beta.expect_exact("BETA_READS_ALPHA_WORKSPACE=alpha-workspace-value")
        assert (project.cwd / "alpha-shared.txt").read_text(
            encoding="utf-8"
        ) == "alpha-workspace-value\n"
        assert (project.cwd / "beta-shared.txt").read_text(
            encoding="utf-8"
        ) == "beta-workspace-value\n"

        alpha.sendline("exit")
        alpha.expect(pexpect.EOF)
        alpha.close()
        assert alpha.exitstatus == 0
        beta.sendline("exit")
        beta.expect(pexpect.EOF)
        beta.close()
        assert beta.exitstatus == 0
    finally:
        if beta is not None and beta.isalive():
            beta.close(force=True)
        if alpha.isalive():
            alpha.close(force=True)

    assert (alpha_state / "state.txt").read_text(
        encoding="utf-8"
    ) == "alpha-updated-state\n"
    assert (beta_state / "state.txt").read_text(
        encoding="utf-8"
    ) == "beta-updated-state\n"


@pytest.mark.timeout(300)
def test_preset_masks_state_and_ssh_keys_when_home_is_inside_workspace(
    project_factory,
):
    """The workspace mount must not provide an alias around preset isolation."""
    project = project_factory("home-inside-workspace")
    project.home = project.cwd
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    preset_name = "isolation edge"

    SetupFactory(project.home).preset(
        name=preset_name,
        run=r"""
stty -echo
printf 'EDGE_READY\n'
while IFS= read -r command; do
    eval "$command"
done
""",
        setups=[],
    )

    run(f"{zaigr} project vm start", input="y\n", timeout=180)
    run(
        f"{zaigr} project vm exec -- mkdir -p "
        "/home/user/.zaigr-agent-state/isolation-sibling",
        timeout=20,
    )
    run(
        f"{zaigr} project vm exec -- tee "
        "/home/user/.zaigr-agent-state/isolation-sibling/secret.txt",
        input="workspace-alias-secret\n",
        timeout=20,
    )

    shell = spawn_interactive(
        f"{zaigr} shell --preset {shlex.quote(preset_name)}",
        cwd=project.cwd,
        env=project.env,
        timeout=180,
    )
    try:
        shell.expect_exact("EDGE_READY", timeout=180)

        shell.sendline(
            "if test -r /home/user/workspace/.zaigr/root-ssh.key; then "
            "printf 'ROOT_KEY_ALLOWED\\n'; else printf 'ROOT_KEY_DENIED\\n'; fi"
        )
        _expect_denied(shell, "ROOT_KEY_DENIED", "ROOT_KEY_ALLOWED")
        shell.sendline(
            "if test -r /home/user/workspace/.zaigr/user-ssh.key; then "
            "printf 'USER_KEY_ALLOWED\\n'; else printf 'USER_KEY_DENIED\\n'; fi"
        )
        _expect_denied(shell, "USER_KEY_DENIED", "USER_KEY_ALLOWED")
        shell.sendline(
            "if cat /home/user/workspace/.zaigr/store/*/agent-state/"
            "isolation-sibling/secret.txt >/dev/null 2>&1; then "
            "printf 'STATE_ALIAS_ALLOWED\\n'; else printf 'STATE_ALIAS_DENIED\\n'; fi"
        )
        _expect_denied(shell, "STATE_ALIAS_DENIED", "STATE_ALIAS_ALLOWED")
        shell.sendline(
            "if cat '/home/user/workspace/.zaigr/presets/isolation edge/run' "
            ">/dev/null 2>&1; then printf 'CONTROL_STATE_ALLOWED\\n'; else "
            "printf 'CONTROL_STATE_DENIED\\n'; fi"
        )
        _expect_denied(shell, "CONTROL_STATE_DENIED", "CONTROL_STATE_ALLOWED")

        for user, marker in (("root", "ROOT"), ("user", "USER")):
            shell.sendline(
                "if ssh -o BatchMode=yes -o ConnectTimeout=5 "
                "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
                f"-i /home/user/workspace/.zaigr/{user}-ssh.key "
                f"{user}@127.0.0.1 true >/dev/null 2>&1; then "
                f"printf '{marker}_SSH_ALLOWED\\n'; else "
                f"printf '{marker}_SSH_DENIED\\n'; fi"
            )
            _expect_denied(shell, f"{marker}_SSH_DENIED", f"{marker}_SSH_ALLOWED")

        shell.sendline("exit")
        shell.expect(pexpect.EOF)
        shell.close()
        assert shell.exitstatus == 0
    finally:
        if shell.isalive():
            shell.close(force=True)


@pytest.mark.timeout(300)
def test_legacy_runtime_keeps_trusted_user_access_and_requires_rebuild_for_presets(
    project, setup_factory
):
    """Old empty-password images remain manageable but cannot run unisolated presets."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    full_version = run(f"{zaigr} misc full-version", timeout=10)
    required_base_runtime = next(
        line.removeprefix("base-image: ")
        for line in full_version.splitlines()
        if line.startswith("base-image: ")
    )

    setup_factory(
        setup_name="simulate-legacy-runtime",
        script_content=r"""
printf '%s\n' 'PermitRootLogin yes' 'PermitEmptyPasswords yes' \
    > /etc/ssh/sshd_config.d/10-zaigr.conf
install -d -m 0700 /root/.ssh
install -m 0600 /run/zaigr-ssh/root-authorized-keys /root/.ssh/authorized_keys
cp /root/.ssh/authorized_keys /root/authorized_keys.before-migration
printf 'base-image:legacy-preset-runtime\n' > /etc/base-image-version
install -d -o user -g user -m 0700 /home/user/.ssh
ln -s /root/.ssh/authorized_keys /home/user/.ssh/authorized_keys
chown -h user:user /home/user/.ssh/authorized_keys
rm -f /run/zaigr-ssh/user-authorized-keys
rm -f /usr/local/lib/zaigr/run-preset-isolated
sshd -t
systemctl reload ssh
""",
    )
    setup_factory.preset(
        name="legacy-preset",
        run="printf 'LEGACY_PRESET_RAN\\n' > legacy-preset-ran.txt",
        setups=[],
    )

    run(f"{zaigr} project vm start", input="y\n", timeout=180)
    run(
        f"{zaigr} project setup run simulate-legacy-runtime",
        timeout=120,
    )

    user = run(f"{zaigr} project vm exec -- id -un", timeout=20)
    assert user.strip() == "user"
    user_key_link = run(
        f"{zaigr} project vm exec -- readlink /home/user/.ssh/authorized_keys",
        timeout=20,
    )
    assert user_key_link.strip() == "/root/.ssh/authorized_keys"
    run(
        f"{zaigr} project vm exec --root -- cmp "
        "/root/authorized_keys.before-migration /root/.ssh/authorized_keys",
        input="y\n",
        timeout=30,
    )

    shell = spawn_interactive(
        f"{zaigr} shell",
        cwd=project.cwd,
        env=project.env,
        timeout=60,
    )
    try:
        shell.sendline("printf 'LEGACY_SHELL_USER=%s\\n' \"$(id -un)\"")
        shell.expect_exact("LEGACY_SHELL_USER=user", timeout=20)
        shell.sendline("exit")
        shell.expect(pexpect.EOF)
        shell.close()
        assert shell.exitstatus == 0
    finally:
        if shell.isalive():
            shell.close(force=True)

    stdout, stderr, rc = _run(
        f"{zaigr} shell --preset legacy-preset",
        cwd=project.cwd,
        env=project.env,
        timeout=30,
    )
    assert rc != 0
    combined = stdout + stderr
    assert "runtime is outdated" in combined
    assert "running VM base runtime: legacy-preset-runtime" in combined
    assert f"required base runtime: {required_base_runtime}" in combined
    assert "zaigr project vm stop" in combined
    assert "zaigr project rebuild" in combined
    assert "preset agent state is preserved" in combined
    assert not (project.cwd / "legacy-preset-ran.txt").exists()

    stdout, stderr, rc = _run(
        f"{zaigr} project rebuild",
        cwd=project.cwd,
        env=project.env,
        timeout=30,
    )
    assert rc != 0
    combined = stdout + stderr
    assert "cannot replace the project's outdated base runtime" in combined
    assert "running VM base runtime: legacy-preset-runtime" in combined
    assert f"required base runtime: {required_base_runtime}" in combined
    assert "zaigr project vm stop" in combined
    assert "project VM is running;" not in combined
