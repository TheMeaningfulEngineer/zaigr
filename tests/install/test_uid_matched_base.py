"""UID-only usability parity through the installed public CLI, not ID mapping."""

import json
import shlex
import uuid
from functools import partial

import pexpect
import pytest

from tests.conftest import err_msg, run, spawn_interactive

HOME = "/home/uid-host"
PREPARATION_WARNING = "Preparing the base image for your account automatically"


def checked(container, command, **kwargs):
    """Run a visible command with transcript capture and require success."""
    stdout, stderr, rc = container.run(command, **kwargs)
    assert rc == 0, err_msg(stdout, stderr)
    return stdout


def checked_host(command, **kwargs):
    """Run visible container infrastructure commands with transcript capture."""
    stdout, stderr, rc = run(command, **kwargs)
    assert rc == 0, err_msg(stdout, stderr)
    return stdout


@pytest.fixture(scope="session")
def uid_dependencies_image():
    """Prepare host tools once per worker, retaining fresh users and VMs in every case."""
    token = uuid.uuid4().hex
    builder = f"zaigr-uid-dependencies-{token}"
    image = f"localhost/zaigr-uid-dependencies:{token}"
    try:
        try:
            checked_host(
                ["podman", "run", "-d", "--rm", "--network", "host", "--name", builder,
                 "docker.io/library/debian:trixie", "sleep", "infinity"],
                timeout=600,
            )
            checked_host(
                ["podman", "exec", builder, "bash", "-lc",
                 "printf 'Acquire::ForceIPv4 \"true\";\\n' > /etc/apt/apt.conf.d/99zaigr-install-test-ipv4"],
                timeout=30,
            )
            checked_host(["podman", "exec", builder, "apt-get", "update"], timeout=180)
            checked_host(
                ["podman", "exec", "--env", "DEBIAN_FRONTEND=noninteractive", builder,
                 "apt-get", "install", "-y", "--no-install-recommends",
                 "coreutils", "e2fsprogs", "openssh-client", "qemu-system-x86", "qemu-utils"],
                timeout=240,
            )
            checked_host(["podman", "commit", "--pause=false", builder, image], timeout=120)
        finally:
            checked_host(
                ["podman", "rm", "--ignore", "--force", "--time", "0", builder], timeout=30,
            )
        yield image
    finally:
        checked_host(["podman", "image", "rm", "--ignore", image], timeout=60)


@pytest.fixture
def uid_caller(request, container_factory, uid_dependencies_image):
    """Install zaigr in an isolated container with a real numeric host caller."""
    uid, gid = request.param
    container = container_factory(uid_dependencies_image, standalone=True)
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


@pytest.mark.timeout(300)
def test_root_caller_uses_factory_guest_identity_for_both_shares(container_factory, uid_dependencies_image):
    container = container_factory(uid_dependencies_image, standalone=True)
    checked(container, "install -m 0755 /dist/zaigr /usr/local/bin/zaigr")
    env = {"HOME": "/tmp/zaigr-home", "ZAIGR_VM_RAM": "512", "ZAIGR_VM_CPU": "1", "ZAIGR_DISK_SIZE": "8G"}
    run = partial(checked, container, env=env, cwd="/tmp/zaigr-project")
    run("zaigr project vm start --ram 512 --cpu 1", input="y\n", timeout=180)
    assert run("zaigr project vm exec -- id -u").strip() == "1000"
    assert run("zaigr project vm exec -- id -g").strip() == "1001"
    assert run("zaigr project vm exec -- findmnt -n -o FSTYPE /home/user/workspace").strip() == "virtiofs"
    assert run("zaigr project vm exec -- findmnt -n -o FSTYPE /home/user/.zaigr-agent-state").strip() == "virtiofs"
    run("zaigr project vm exec -- touch /home/user/workspace/root-caller-user")
    run("zaigr project vm exec -- chmod 600 /home/user/workspace/root-caller-user")
    run("zaigr project vm exec --root -- touch /home/user/.zaigr-agent-state/root-caller-root", input="y\n")
    run("zaigr project vm exec --root -- chmod 600 /home/user/.zaigr-agent-state/root-caller-root", input="y\n")
    assert run("stat -c '%u:%g:%a' /tmp/zaigr-project/root-caller-user").strip() == "0:0:600"
    assert run("find /tmp/zaigr-home/.zaigr -name root-caller-root -exec stat -c '%u:%g:%a' {} \\;").strip() == "0:0:600"
    run("zaigr project vm stop")


@pytest.mark.timeout(600)
def test_restricted_namespace_requires_consent_and_remembers_project_choice(container_factory, uid_dependencies_image):
    """A real namespace denial cancels by default; explicit consent survives starts and rebuilds."""
    container = container_factory(uid_dependencies_image, standalone=True, namespace_capable=False)
    checked(container, "install -m 0755 /dist/zaigr /usr/local/bin/zaigr")
    checked(container, "useradd --uid 2000 --create-home --user-group sandbox-user")
    checked(container, "chown 2000:2000 /tmp/zaigr-home /tmp/zaigr-project")
    env = {"HOME": "/tmp/zaigr-home", "ZAIGR_VM_RAM": "512", "ZAIGR_VM_CPU": "1", "ZAIGR_DISK_SIZE": "8G"}
    user = partial(checked, container, user="2000:2000", env=env, cwd="/tmp/zaigr-project")
    stdout, stderr, rc = container.run("zaigr misc check", env=env, user="2000:2000", timeout=30)
    assert rc == 1, err_msg(stdout, stderr)
    assert stdout.startswith("Host: Debian GNU/Linux ")
    assert "Diagnosis: likely container restrictions" in stdout
    assert "Kernel audit:" in stdout
    assert "Daemon output:" in stdout
    assert "Container setup" in stdout
    assert "apparmor-profile >" not in stdout
    assert checked(container, "find /tmp/zaigr-home/.zaigr -name '*.qcow2'").strip() == ""

    # Viewing info and then reaching EOF must never authorize unsafe mode.
    stdout, stderr, rc = container.run(
        "zaigr project vm start --ram 512 --cpu 1", user="2000:2000",
        cwd="/tmp/zaigr-project", env=env, input="y\ninfo\n", timeout=180,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert "[cancel/info/unsafe] (default: cancel)" in stderr
    assert "compromise your host user account" in stderr
    assert "no unsafe preference was saved" in stderr
    assert "Full diagnostics: zaigr misc check" in stderr
    assert "Diagnosis:" not in stderr
    assert "Daemon output:" not in stderr
    assert checked(container, "find /tmp/zaigr-home/.zaigr -name vm-supervisor.json").strip() == ""

    start = spawn_interactive(shlex.join([
        "podman", "exec", "-it", "--user", "2000:2000", "--workdir", "/tmp/zaigr-project",
        *[arg for key, value in env.items() for arg in ("--env", f"{key}={value}")],
        container.name, "zaigr", "project", "vm", "start", "--ram", "512", "--cpu", "1",
    ]), timeout=300)
    try:
        start.expect_exact("Initialize project and continue? [y/N]")
        start.sendline("y")
        start.expect_exact("[cancel/info/unsafe] (default: cancel):")
        assert "compromise your host user account" in start.before
        assert "Daemon output:" not in start.before
        assert "zaigr misc check" not in start.before
        assert "Continue without file-sharing isolation" not in start.before
        start.sendline("info")
        start.expect_exact("Container setup")
        assert "Diagnosis:" not in start.before
        assert "Daemon output:" not in start.before
        start.expect_exact("Full diagnostics: zaigr misc check")
        start.expect_exact("Your choice [cancel/info/unsafe] (default: cancel):")
        start.sendline("unsafe")
        start.expect_exact("Saved for this project: file-sharing sandbox disabled.")
        start.expect(pexpect.EOF)
        start.close()
        assert start.exitstatus == 0, start.transcript.tail(4000)
    finally:
        if start.isalive():
            start.terminate(force=True)
    assert "virtiofs-sandbox=none" in user("zaigr project vm show-config")
    assert user("zaigr project vm exec -- id -u").strip() == "2000"
    user("zaigr project vm exec -- tee /home/user/workspace/shared-canary", input="preserved\n")
    assert user("cat shared-canary") == "preserved\n"
    user("zaigr project vm stop")

    stdout, stderr, rc = container.run(
        "zaigr project vm start", user="2000:2000", cwd="/tmp/zaigr-project", env=env, timeout=180,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert "WARNING: Without the file-sharing sandbox" in stderr
    assert "[cancel/info/unsafe]" not in stderr
    user("zaigr project vm stop")
    user("mkdir -p /tmp/zaigr-home/.zaigr/setups/sandbox-marker")
    user("tee /tmp/zaigr-home/.zaigr/setups/sandbox-marker/setup.script",
         input="#!/bin/sh\nset -eu\nprintf rebuilt > /opt/sandbox-marker\n")
    # An unrelated global image operation must not inherit the cwd project's opt-out.
    stdout, stderr, rc = container.run(
        "zaigr global base-image setup run sandbox-marker --ram 512", user="2000:2000",
        cwd="/tmp/zaigr-project", env=env, input="cancel\n", timeout=60,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert "This is a global image operation. Your choice applies only to this" in stderr
    assert "[cancel/info/unsafe]" in stderr
    assert "virtiofs-sandbox=none" in user("zaigr project vm show-config")
    user("zaigr project setup run sandbox-marker", timeout=300)
    user("tee /tmp/zaigr-home/.zaigr/setups/sandbox-marker/setup.script",
         input="#!/bin/sh\nset -eu\nprintf rebuilt-again > /opt/sandbox-marker\n")
    user("zaigr project rebuild", timeout=300)
    assert "virtiofs-sandbox=none" in user("zaigr project vm show-config")
    user("zaigr project vm start", timeout=180)
    assert user("zaigr project vm exec -- cat /opt/sandbox-marker").strip() == "rebuilt-again"
    assert user("cat shared-canary") == "preserved\n"
    user("zaigr project vm stop")
    user("zaigr project vm set-config --virtiofs-sandbox namespace")
    stdout, stderr, rc = container.run(
        "zaigr project vm start", user="2000:2000", cwd="/tmp/zaigr-project", env=env,
        input="cancel\n", timeout=30,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert "[cancel/info/unsafe]" in stderr
    assert "virtiofs-sandbox=namespace" in user("zaigr project vm show-config")


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
