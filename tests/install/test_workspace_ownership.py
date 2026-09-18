"""Shared files have independent guest ownership and host-caller ownership.

Guest root, the normal user, and a service must retain their own file ownership
and private-file access. On the host, every shared object belongs to the actual
unprivileged caller. These are acceptance requirements, not a choice of sharing
backend or a claim that the current implementation satisfies them.
"""

import shlex
from functools import partial

import pytest

from tests.conftest import err_msg


def _checked_run(container, command, **kwargs):
    """Keep container commands in the shared test transcript."""
    stdout, stderr, rc = container.run(command, **kwargs)
    assert rc == 0, f"Command failed: {command}\n{err_msg(stdout, stderr)}"
    return stdout


@pytest.fixture
def ownership_host(container_factory, request):
    """Prepare an isolated host account, without starting or configuring a VM."""
    host_uid, host_gid = request.param
    container = container_factory("docker.io/library/debian:trixie", standalone=True)
    admin = partial(_checked_run, container)
    admin("apt-get update -o APT::Update::Error-Mode=any", timeout=180)
    admin(
        "DEBIAN_FRONTEND=noninteractive apt-get install -y "
        "coreutils e2fsprogs openssh-client qemu-system-x86 qemu-utils",
        timeout=300,
    )
    admin(
        f"groupadd --gid {host_gid} zaigr-ownership && "
        f"useradd --create-home --uid {host_uid} --gid {host_gid} "
        "--shell /bin/bash zaigr-ownership"
    )
    admin(
        "install -d -m 0755 -o zaigr-ownership -g zaigr-ownership "
        "/home/zaigr-ownership/workspace"
    )
    caller = partial(
        _checked_run,
        container,
        user="zaigr-ownership",
        cwd="/home/zaigr-ownership/workspace",
        env={
            "HOME": "/home/zaigr-ownership",
            "PATH": "/home/zaigr-ownership/.local/bin:/usr/local/bin:/usr/bin:/bin",
        },
    )
    caller(
        'install -d "$HOME/.local/bin" && '
        'install -m 0755 /dist/zaigr "$HOME/.local/bin/zaigr"'
    )
    return caller, host_uid, host_gid


@pytest.mark.timeout(900)
@pytest.mark.parametrize(
    "ownership_host",
    [
        pytest.param((1000, 1000), id="host-1000"),
        pytest.param((1001, 1001), id="host-1001"),
        pytest.param((2000, 2300), id="host-2000-distinct-gid"),
        pytest.param((23001, 23002), id="host-service-id-overlap"),
    ],
    indirect=True,
)
def test_shared_workspace_preserves_guest_owners_and_host_caller(ownership_host):
    caller, host_uid, host_gid = ownership_host
    host_owner = f"{host_uid}:{host_gid}"
    assert caller("id -u").strip() == str(host_uid)
    assert caller("id -g").strip() == str(host_gid)
    assert host_uid != 0
    assert caller("stat -c '%u:%g:%a' .").strip() == f"{host_owner}:755"

    caller("zaigr project vm start", input="y\n", timeout=180)
    running = True
    try:
        identity = caller(
            "zaigr project vm exec -- sh -c 'id -u; id -g'", timeout=30
        ).splitlines()
        normal_uid, normal_gid = map(int, identity)
        assert normal_uid != 0
        assert normal_gid != 0

        # This must work before root creates any test directories. In particular,
        # do not repair the original 0755 workspace with chmod or chown.
        caller(
            "zaigr project vm exec -- sh -c "
            + shlex.quote(
                "cd /home/user/workspace && umask 077 && "
                "printf 'normal guest write\n' > ownership-probe.txt"
            ),
            timeout=30,
        )
        assert caller("cat ownership-probe.txt") == "normal guest write\n"
        assert caller("stat -c '%u:%g' ownership-probe.txt").strip() == host_owner

        # Never renumber the normal guest account to make the test pass. The
        # service is separate even if an implementation aligns normal and host
        # IDs. The last host case deliberately exercises numeric ID overlap when
        # the normal guest account does not already use that ID.
        service_uid = 23001 if normal_uid != 23001 else 23003
        service_gid = 23002 if normal_gid != 23002 else 23004
        actors = [
            ("normal", normal_uid, normal_gid),
            ("root", 0, 0),
            ("service", service_uid, service_gid),
        ]
        caller(
            "zaigr project vm exec --root -- sh -c "
            + shlex.quote(
                f"groupadd --gid {service_gid} zaigr-ownership-service && "
                f"useradd --no-create-home --uid {service_uid} "
                f"--gid {service_gid} --shell /bin/sh zaigr-ownership-service"
            ),
            input="y\n",
            timeout=30,
        )

        # Ordinary guest ownership operations on new test data are part of the
        # contract. Searchable directories isolate the files' 0600 permissions:
        # a denial cannot be explained by an inaccessible private parent.
        directories = " && ".join(
            f"install -d -m 0755 -o {uid} -g {gid} ownership-{name}"
            for name, uid, gid in actors
        )
        caller(
            "zaigr project vm exec --root -- sh -c "
            + shlex.quote("cd /home/user/workspace && " + directories),
            input="y\n",
            timeout=30,
        )

        contents = {name: f"{name} created\n" for name, _, _ in actors}
        for phase in ("before-restart", "after-restart"):
            if phase == "after-restart":
                caller("zaigr project vm stop", timeout=60)
                running = False
                caller("zaigr project vm start", input="y\n", timeout=180)
                running = True

            assert caller(
                "zaigr project vm exec -- id -u zaigr-ownership-service", timeout=30
            ).strip() == str(service_uid)
            assert caller(
                "zaigr project vm exec -- id -g zaigr-ownership-service", timeout=30
            ).strip() == str(service_gid)
            append_text = phase + " append\n"
            owner_checks = []
            for name, uid, gid in actors:
                directory = f"ownership-{name}"
                path = f"{directory}/private.txt"
                statements = [
                    "set -eu",
                    f'test "$(id -u)" = {uid}',
                    f'test "$(id -g)" = {gid}',
                    f'test "$(stat -c %u:%g:%a {directory})" = {uid}:{gid}:755',
                ]
                if phase == "before-restart":
                    statements.extend(
                        ["umask 077", f"printf %s {shlex.quote(contents[name])} > {path}"]
                    )
                statements.extend(
                    [
                        f'test "$(stat -c %u:%g:%a {path})" = {uid}:{gid}:600',
                        f'test "$(cat {path}; printf sentinel)" = '
                        + shlex.quote(contents[name] + "sentinel"),
                        f"printf %s {shlex.quote(append_text)} >> {path}",
                        f"touch {path}",
                        f'test "$(stat -c %u:%g:%a {path})" = {uid}:{gid}:600',
                    ]
                )
                contents[name] += phase + " append\n"
                owner_checks.append((name, uid, gid, "; ".join(statements)))

            privacy_checks = []
            for name, uid, gid in actors:
                statements = ["set -eu"]
                for other, _, _ in actors:
                    path = f"ownership-{other}/private.txt"
                    if name == "root" or name == other:
                        statements.append(
                            f'test "$(cat {path}; printf sentinel)" = '
                            + shlex.quote(contents[other] + "sentinel")
                        )
                        continue
                    statements.extend(
                        [
                            f"if cat {path} >/dev/null 2>&1; then "
                            f"printf '%s\\n' '{name} read {other} private file' >&2; "
                            "exit 1; fi",
                            f"if printf forbidden 2>/dev/null >> {path}; then "
                            f"printf '%s\\n' '{name} wrote {other} private file' >&2; "
                            "exit 1; fi",
                        ]
                    )
                privacy_checks.append((name, uid, gid, "; ".join(statements)))

            # Each CLI invocation starts a new process: creation alone or an
            # already-open descriptor cannot conceal failed reopen operations.
            # Enter the workspace before dropping identity, so a private
            # /home/user ancestor does not confound shared-file permissions.
            for name, uid, gid, script in owner_checks + privacy_checks:
                guest_script = "cd /home/user/workspace && "
                if name == "service":
                    guest_script += (
                        f"exec setpriv --reuid={uid} --regid={gid} "
                        "--clear-groups -- "
                    )
                guest_script += "sh -c " + shlex.quote(script)
                if name == "normal":
                    caller(
                        "zaigr project vm exec -- sh -c " + shlex.quote(guest_script),
                        timeout=30,
                    )
                else:
                    caller(
                        "zaigr project vm exec --root -- sh -c "
                        + shlex.quote(guest_script),
                        input="y\n",
                        timeout=30,
                    )

            for name, _, _ in actors:
                directory = f"ownership-{name}"
                path = f"{directory}/private.txt"
                # Do not constrain host mode bits: a backend can store guest
                # modes separately. Actual host ownership and access must work.
                assert caller(f"stat -c '%u:%g' {directory}").strip() == host_owner
                assert caller(f"stat -c '%u:%g' {path}").strip() == host_owner
                assert caller(f"cat {path}") == contents[name], (
                    f"{phase}: {name} contents changed unexpectedly, including "
                    "possible writes by a denied guest identity"
                )
                if phase == "before-restart":
                    # In-place host edits must not erase the guest owner. The
                    # next phase checks exact contents, ownership, and access.
                    caller(f"printf 'host edit\\n' >> {path}")
                    contents[name] += "host edit\n"

            assert caller("stat -c '%u:%g:%a' .").strip() == f"{host_owner}:755"
    finally:
        if running:
            caller("zaigr project vm stop", timeout=60)
