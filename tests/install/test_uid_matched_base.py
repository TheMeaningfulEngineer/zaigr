"""UID-only usability parity through the installed public CLI, not ID mapping."""

import json
from functools import partial

import pytest

from tests.conftest import err_msg

HOME = "/home/uid-host"
PREPARATION_WARNING = "Preparing the base image for your account automatically"


def checked(container, command, **kwargs):
    """Run a visible command with transcript capture and require success."""
    stdout, stderr, rc = container.run(command, **kwargs)
    assert rc == 0, err_msg(stdout, stderr)
    return stdout


@pytest.fixture
def uid_caller(request, container_factory):
    """Install zaigr in an isolated container with a real numeric host caller."""
    uid, gid = request.param
    container = container_factory("debian:trixie", standalone=True)
    checked(container, "apt-get update", timeout=180)
    checked(
        container,
        "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "
        "coreutils e2fsprogs openssh-client qemu-system-x86 qemu-utils",
        timeout=240,
    )
    checked(container, "install -m 0755 /dist/zaigr /usr/local/bin/zaigr")
    checked(container, f"getent group {gid} >/dev/null || groupadd -g {gid} uid-host")
    # -o permits the UID-1 collision probe without changing the container's daemon account.
    checked(container, f"useradd -o -u {uid} -g {gid} -m -s /bin/bash uid-host")
    checked(container, f"install -d -m 0755 -o {uid} -g {gid} {HOME}/old {HOME}/new {HOME}/later {HOME}/reset")
    env = {"HOME": HOME, "ZAIGR_VM_RAM": "512", "ZAIGR_VM_CPU": "1", "ZAIGR_DISK_SIZE": "8G"}
    return container, uid, gid, env


@pytest.mark.parametrize("uid_caller", [(1000, 1001), (1001, 1001), (1001, 1000), (2000, 2300)], indirect=True)
@pytest.mark.timeout(900)
def test_uid_matched_base_workspace_state_restart_and_reset(uid_caller):
    """Non-1000 users get the control user's filesystem behavior without host chmod."""
    container, uid, gid, env = uid_caller
    run = partial(checked, container, user=f"{uid}:{gid}", env=env)
    assert run("id -u").strip() == str(uid)
    assert run("id -g").strip() == str(gid)
    run(f"tee {HOME}/new/host-private", input="host-private contents\n")
    run(f"chmod 0600 {HOME}/new/host-private")
    before = run(f"stat -c '%u:%g:%a:%s' {HOME}/new/host-private")

    stdout, stderr, rc = container.run(
        "zaigr project vm start --ram 512 --cpu 1", cwd=f"{HOME}/old", user=f"{uid}:{gid}",
        env={**env, "ZAIGR_VM_RAM": "invalid", "ZAIGR_VM_CPU": "invalid"},
        input="y\n", timeout=480,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert (PREPARATION_WARNING in stderr) == (uid != 1000)
    assert "match-user" not in stdout + stderr
    assert "Migrated guest user UID" not in stdout + stderr
    assert run("zaigr project vm exec -- id -u", cwd=f"{HOME}/old").strip() == str(uid)
    run(
        "zaigr project vm exec -- touch /home/user/workspace/before-match",
        cwd=f"{HOME}/old",
    )
    status = run("zaigr global base-image status")
    assert "mode: factory" in status
    assert "UID" not in status
    assert run(f"stat -c '%u:%g:%a:%s' {HOME}/new/host-private") == before
    assert run(f"stat -c '%u:%g:%a' {HOME}/new").strip() == f"{uid}:{gid}:755"

    run("zaigr project vm stop", cwd=f"{HOME}/old", timeout=60)
    stdout, stderr, rc = container.run(
        "zaigr project vm start", cwd=f"{HOME}/old", user=f"{uid}:{gid}", env=env, timeout=180,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert PREPARATION_WARNING not in stderr
    assert run("zaigr project vm exec -- id -u", cwd=f"{HOME}/old").strip() == str(uid)
    run("zaigr project vm stop", cwd=f"{HOME}/old", timeout=60)

    stdout, stderr, rc = container.run(
        "zaigr project vm start", cwd=f"{HOME}/new", user=f"{uid}:{gid}", env=env,
        input="y\n", timeout=180,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert PREPARATION_WARNING not in stderr
    assert run("zaigr global base-image status") == status
    assert run("zaigr project vm exec -- id -u", cwd=f"{HOME}/new").strip() == str(uid)
    assert run("zaigr project vm exec -- id -g", cwd=f"{HOME}/new").strip() == "1001"
    assert "kvm" in run("zaigr project vm exec -- id -nG", cwd=f"{HOME}/new").split()
    assert run("zaigr project vm exec -- cat /home/user/workspace/host-private", cwd=f"{HOME}/new").strip() == "host-private contents"
    run("zaigr project vm exec -- sh -c 'umask 077; printf private > /home/user/guest-private'", cwd=f"{HOME}/new")
    assert run("zaigr project vm exec -- stat -c '%u:%a' /home/user/guest-private", cwd=f"{HOME}/new").strip() == f"{uid}:600"
    run("zaigr project vm exec -- touch /home/user/workspace/ordinary-write", cwd=f"{HOME}/new")
    run("zaigr project vm exec --root -- touch /home/user/workspace/root-write", cwd=f"{HOME}/new", input="y\n")
    for name in ("ordinary-write", "root-write"):
        assert run(f"stat -c '%u:%g' {HOME}/new/{name}").strip() == f"{uid}:{gid}"
    run(f"tee -a {HOME}/new/ordinary-write", input="host edit\n")
    assert run("zaigr project vm exec -- cat /home/user/workspace/ordinary-write", cwd=f"{HOME}/new").strip() == "host edit"
    run("zaigr project vm exec -- tee /home/user/workspace/script", cwd=f"{HOME}/new", input="#!/bin/sh\nprintf 'executable-ok\\n'\n")
    script_mode = run(f"stat -c '%a' {HOME}/new/script")
    run("zaigr project vm exec -- chmod +x /home/user/workspace/script", cwd=f"{HOME}/new")
    assert run(f"{HOME}/new/script").strip() == "executable-ok"
    run("zaigr project vm exec -- chmod -x /home/user/workspace/script", cwd=f"{HOME}/new")
    assert run(f"stat -c '%a' {HOME}/new/script") == script_mode
    run(f"test ! -x {HOME}/new/script")
    run("zaigr project vm exec -- ln -s missing-target /home/user/workspace/native-link", cwd=f"{HOME}/new")
    assert run(f"readlink {HOME}/new/native-link").strip() == "missing-target"
    assert run(f"stat -c '%F' {HOME}/new/native-link").strip() == "symbolic link"
    run("zaigr project vm exec -- tee /home/user/.zaigr-agent-state/state-canary", cwd=f"{HOME}/new", input="persistent state\n")
    run("zaigr project vm exec -- chmod 0600 /home/user/.zaigr-agent-state/state-canary", cwd=f"{HOME}/new")
    run("zaigr project vm stop", cwd=f"{HOME}/new", timeout=60)
    run("zaigr project vm start", cwd=f"{HOME}/new", timeout=180)
    assert run("zaigr project vm exec -- id -u", cwd=f"{HOME}/new").strip() == str(uid)
    assert run("zaigr project vm exec -- cat /home/user/guest-private", cwd=f"{HOME}/new").strip() == "private"
    assert run("zaigr project vm exec -- cat /home/user/.zaigr-agent-state/state-canary", cwd=f"{HOME}/new").strip() == "persistent state"

    run(f"mkdir -p {HOME}/.zaigr/setups/uid-marker")
    run(f"tee {HOME}/.zaigr/setups/uid-marker/setup.script", input="#!/bin/bash\nset -eu\nprintf marker > /opt/uid-marker\n")
    run("zaigr global base-image setup run uid-marker --ram 512", timeout=300)
    assert "UID" not in run("zaigr global base-image status")
    run("zaigr project vm start", cwd=f"{HOME}/later", input="y\n", timeout=180)
    assert run("zaigr project vm exec -- id -u", cwd=f"{HOME}/later").strip() == str(uid)
    assert run("zaigr project vm exec -- cat /opt/uid-marker", cwd=f"{HOME}/later").strip() == "marker"
    run("zaigr project vm stop", cwd=f"{HOME}/later", timeout=60)

    run("zaigr global base-image reset")
    stdout, stderr, rc = container.run(
        "zaigr project vm start", cwd=f"{HOME}/reset", user=f"{uid}:{gid}", env=env,
        input="y\n", timeout=480,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert (PREPARATION_WARNING in stderr) == (uid != 1000)
    assert run("zaigr project vm exec -- id -u", cwd=f"{HOME}/reset").strip() == str(uid)
    run("zaigr project vm stop", cwd=f"{HOME}/reset", timeout=60)
    run("zaigr project vm stop", cwd=f"{HOME}/new", timeout=60)
    run("zaigr project vm start", cwd=f"{HOME}/new", timeout=180)
    assert run("zaigr project vm exec -- id -u", cwd=f"{HOME}/new").strip() == str(uid)
    assert run("zaigr project vm exec -- cat /home/user/.zaigr-agent-state/state-canary", cwd=f"{HOME}/new").strip() == "persistent state"
    assert run(f"stat -c '%u:%g:%a:%s' {HOME}/new/host-private") == before
    run("zaigr project vm stop", cwd=f"{HOME}/new", timeout=60)


@pytest.mark.parametrize("uid_caller", [(1001, 1001)], indirect=True)
def test_global_setup_automatically_prepares_account_first(uid_caller):
    """Global setups inherit the caller's identity without a preparatory command."""
    container, uid, gid, env = uid_caller
    run = partial(checked, container, user=f"{uid}:{gid}", env=env)
    run(f"mkdir -p {HOME}/.zaigr/setups/existing-base")
    run(
        f"tee {HOME}/.zaigr/setups/existing-base/setup.script",
        input="#!/bin/bash\nset -eu\nprintf existing > /opt/existing-base\nid -u user > /opt/base-user-uid\n",
    )
    stdout, stderr, rc = container.run(
        "zaigr global base-image setup run existing-base --ram 512",
        user=f"{uid}:{gid}", env=env, timeout=600,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert PREPARATION_WARNING in stderr
    assert "match-user" not in stdout + stderr
    before = run("zaigr global base-image status")
    stdout, stderr, rc = container.run(
        "zaigr global base-image setup run existing-base --ram 512",
        user=f"{uid}:{gid}", env=env, timeout=30,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert PREPARATION_WARNING not in stderr
    assert run("zaigr global base-image status") == before
    run("zaigr project vm start", cwd=f"{HOME}/new", input="y\n", timeout=180)
    assert run("zaigr project vm exec -- id -u", cwd=f"{HOME}/new").strip() == str(uid)
    assert run("zaigr project vm exec -- cat /opt/base-user-uid", cwd=f"{HOME}/new").strip() == str(uid)
    assert run("zaigr project vm exec -- cat /opt/existing-base", cwd=f"{HOME}/new").strip() == "existing"
    run("zaigr project vm stop", cwd=f"{HOME}/new", timeout=60)


@pytest.mark.parametrize("uid_caller", [(1, 1001)], indirect=True)
def test_automatic_preparation_collision_keeps_factory_selection(uid_caller):
    """Failed automatic preparation never publishes a partially migrated base."""
    container, uid, gid, env = uid_caller
    run = partial(checked, container, user=f"{uid}:{gid}", env=env)
    stdout, stderr, rc = container.run(
        "zaigr project vm start", cwd=f"{HOME}/new", user=f"{uid}:{gid}", env=env,
        input="y\n", timeout=480,
    )
    assert PREPARATION_WARNING in stderr
    assert rc != 0 and "Target UID is already assigned" in stdout + stderr, err_msg(stdout, stderr)
    assert "mode: factory" in run("zaigr global base-image status")


@pytest.mark.parametrize("uid_caller", [(1001, 1001)], indirect=True)
@pytest.mark.parametrize("customized", [False, True])
@pytest.mark.timeout(900)
def test_runtime_upgrade_reprepares_only_factory_base(uid_caller, customized):
    """Upgrade invalidates disposable preparation without discarding custom setups."""
    container, uid, gid, env = uid_caller
    run = partial(checked, container, user=f"{uid}:{gid}", env=env)
    if customized:
        run(f"mkdir -p {HOME}/.zaigr/setups/upgrade-marker")
        run(
            f"tee {HOME}/.zaigr/setups/upgrade-marker/setup.script",
            input="#!/bin/bash\nset -eu\nprintf preserved > /opt/upgrade-marker\n",
        )
        run("zaigr global base-image setup run upgrade-marker --ram 512 --cpu 1", timeout=600)
    run("zaigr project vm start --ram 512 --cpu 1", cwd=f"{HOME}/old", input="y\n", timeout=480)
    run("zaigr project vm exec -- tee /home/user/upgrade-canary", cwd=f"{HOME}/old", input="keep my project\n")
    run("zaigr project vm stop", cwd=f"{HOME}/old", timeout=60)

    manifest_path = f"{HOME}/.zaigr/base-images/custom/current.json"
    manifest = json.loads(run(f"cat {manifest_path}"))
    original_runtime = manifest["runtime_version"]
    original_revision = manifest["revision"]
    original_source = manifest["source_image"]
    # Represent a valid published image from the previously bundled runtime.
    # Only its version marker changes; the immutable image and pins stay intact.
    manifest["runtime_version"] = "previous-bundled-runtime"
    run(f"tee {manifest_path}", input=json.dumps(manifest) + "\n")

    if customized:
        stdout, stderr, rc = container.run(
            "zaigr project vm start --ram 512 --cpu 1", cwd=f"{HOME}/new",
            user=f"{uid}:{gid}", env=env, input="y\n", timeout=60,
        )
        assert rc != 0, err_msg(stdout, stderr)
        assert "incompatible with bundled runtime" in stdout + stderr
        assert PREPARATION_WARNING not in stderr
        assert json.loads(run(f"cat {manifest_path}")) == manifest
        run("zaigr global base-image reset")
    assert "mode: factory" in run("zaigr global base-image status")
    stdout, stderr, rc = container.run(
        "zaigr project vm start --ram 512 --cpu 1", cwd=f"{HOME}/new",
        user=f"{uid}:{gid}", env=env, input="y\n", timeout=480,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert PREPARATION_WARNING in stderr
    assert "global base-image reset" not in stdout + stderr
    assert run("zaigr project vm exec -- id -u", cwd=f"{HOME}/new").strip() == str(uid)
    if customized:
        run("zaigr project vm exec -- test ! -e /opt/upgrade-marker", cwd=f"{HOME}/new")
    replacement = json.loads(run(f"cat {manifest_path}"))
    assert replacement["runtime_version"] == original_runtime
    assert replacement["revision"] != original_revision
    run(f"test -f {original_source}")
    run("zaigr project vm stop", cwd=f"{HOME}/new", timeout=60)

    run("zaigr project vm start", cwd=f"{HOME}/old", timeout=180)
    assert run("zaigr project vm exec -- cat /home/user/upgrade-canary", cwd=f"{HOME}/old").strip() == "keep my project"
    if customized:
        assert run("zaigr project vm exec -- cat /opt/upgrade-marker", cwd=f"{HOME}/old").strip() == "preserved"
    run("zaigr project vm stop", cwd=f"{HOME}/old", timeout=60)
