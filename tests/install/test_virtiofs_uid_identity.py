"""Shared-mount identity and sandbox behavior through the installed CLI."""

import json
import shlex
import uuid
from functools import partial

import pexpect
import pytest

from tests.conftest import err_msg, run, spawn_interactive

HOME = "/home/uid-host"


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
def test_namespace_consent_survives_restarts_and_rebuilds(container_factory, uid_dependencies_image):
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
    assert "Project initialized with image project.qcow2" in stdout
    assert "virtiofs-sandbox=namespace" in user("zaigr project vm show-config")

    start = spawn_interactive(shlex.join([
        "podman", "exec", "-it", "--user", "2000:2000", "--workdir", "/tmp/zaigr-project",
        *[arg for key, value in env.items() for arg in ("--env", f"{key}={value}")],
        container.name, "zaigr", "project", "vm", "start", "--ram", "512", "--cpu", "1",
    ]), timeout=300)
    try:
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
    assert user("zaigr project vm exec -- id -u").strip() == "1000"
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
@pytest.mark.timeout(900)
def test_runtime_upgrade_rejects_custom_base_and_preserves_pinned_project(uid_caller):
    """An incompatible custom base is rejected while pinned projects remain usable."""
    container, uid, gid, env = uid_caller
    run = partial(checked, container, user=f"{uid}:{gid}", env=env)
    run(f"mkdir -p {HOME}/.zaigr/setups/upgrade-marker")
    run(
        f"tee {HOME}/.zaigr/setups/upgrade-marker/setup.script",
        input="#!/bin/bash\nset -eu\nprintf preserved > /opt/upgrade-marker\n",
    )
    run("zaigr global base-image setup run upgrade-marker --ram 512 --cpu 1", timeout=600)
    run("zaigr project vm start --ram 512 --cpu 1", cwd=f"{HOME}/old", input="y\n", timeout=480)
    assert run("zaigr project vm exec -- id -u", cwd=f"{HOME}/old").strip() == "1000"
    run("zaigr project vm exec -- tee /home/user/upgrade-canary", cwd=f"{HOME}/old", input="keep my project\n")
    run("zaigr project vm stop", cwd=f"{HOME}/old", timeout=60)


    manifest_path = f"{HOME}/.zaigr/base-images/custom/current.json"
    manifest = json.loads(run(f"cat {manifest_path}"))
    original_source = manifest["source_image"]
    # Represent a valid published image from the previously bundled runtime.
    # Only its version marker changes; the immutable image and pins stay intact.
    manifest["runtime_version"] = "previous-bundled-runtime"
    run(f"tee {manifest_path}", input=json.dumps(manifest) + "\n")

    stdout, stderr, rc = container.run(
        "zaigr project vm start --ram 512 --cpu 1", cwd=f"{HOME}/new",
        user=f"{uid}:{gid}", env=env, input="y\n", timeout=60,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert "incompatible with bundled runtime" in stdout + stderr
    assert json.loads(run(f"cat {manifest_path}")) == manifest
    run("zaigr global base-image reset")
    assert "mode: factory" in run("zaigr global base-image status")

    stdout, stderr, rc = container.run(
        "zaigr project vm start --ram 512 --cpu 1", cwd=f"{HOME}/new",
        user=f"{uid}:{gid}", env=env, input="y\n", timeout=480,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert "Preparing the base image for your account automatically" not in stderr
    assert "global base-image reset" not in stdout + stderr
    assert run("zaigr project vm exec -- id -u", cwd=f"{HOME}/new").strip() == "1000"
    run("zaigr project vm exec -- test ! -e /opt/upgrade-marker", cwd=f"{HOME}/new")
    run(f"test -f {original_source}")
    run("zaigr project vm stop", cwd=f"{HOME}/new", timeout=60)

    run("zaigr project vm start", cwd=f"{HOME}/old", timeout=180)
    assert run("zaigr project vm exec -- id -u", cwd=f"{HOME}/old").strip() == "1000"
    assert run("zaigr project vm exec -- cat /home/user/upgrade-canary", cwd=f"{HOME}/old").strip() == "keep my project"
    assert run("zaigr project vm exec -- cat /opt/upgrade-marker", cwd=f"{HOME}/old").strip() == "preserved"
    run("zaigr project vm stop", cwd=f"{HOME}/old", timeout=60)


@pytest.mark.parametrize("legacy_user_uid", [None, 0, 1001])
@pytest.mark.timeout(480)
def test_old_runtime_with_empty_manifest_selects_factory(container_factory, uid_dependencies_image, legacy_user_uid):
    """Legacy empty manifests, with omitted, zero, and nonzero tombstone UIDs, fall back to factory."""
    container = container_factory(uid_dependencies_image, standalone=True)
    checked(container, "install -m 0755 /dist/zaigr /usr/local/bin/zaigr")
    host_home = "/tmp/zaigr-empty-manifest-home"
    project = "/tmp/zaigr-empty-manifest-project"
    env = {"HOME": host_home, "ZAIGR_VM_RAM": "512", "ZAIGR_VM_CPU": "1", "ZAIGR_DISK_SIZE": "8G"}
    run = partial(checked, container, env=env, cwd=project)
    checked(container, f"install -d -m 0755 {host_home} {project}")

    revision = "legacy-empty-manifest"
    revision_root = f"{host_home}/.zaigr/base-images/custom/revisions/{revision}"
    checked(container, f"mkdir -p {revision_root}")
    manifest_path = f"{host_home}/.zaigr/base-images/custom/current.json"
    manifest = {
        "schema": 1,
        "runtime_version": "previous-bundled-runtime",
        "revision": revision,
        "source_image": f"{revision_root}/source.qcow2",
        "created_at": "2026-10-15T00:00:00Z",
    }
    if legacy_user_uid is not None:
        manifest["user_uid"] = legacy_user_uid
    # This documented compatibility fixture represents an old runtime's
    # factory-derived UID preparation, which has no applied setup records.
    # Its source path is intentionally not materialized: runtime mismatch
    # selection must discard this empty manifest before statting that path.
    run(f"tee {manifest_path}", input=json.dumps(manifest) + "\n")

    status = run("zaigr global base-image status")
    assert "mode: factory" in status
    stdout, stderr, rc = container.run(
        "zaigr project vm start --ram 512 --cpu 1", cwd=project, env=env,
        input="y\n", timeout=300,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert "Preparing the base image for your account automatically" not in stdout + stderr
    assert run("zaigr project vm exec -- id -u").strip() == "1000"
    run("zaigr project vm stop", timeout=60)
