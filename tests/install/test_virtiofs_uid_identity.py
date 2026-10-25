"""Shared-mount ownership on real distro hosts with a standalone install."""

import json
from functools import partial

import pytest

from tests.conftest import err_msg
from tests.install.conftest import CLOUDVM_DISTROS

HOME = "/home/uid-host"


def checked(vm, command, **kwargs):
    """Run one visible guest command and require success."""
    stdout, stderr, rc = vm.run(command, **kwargs)
    assert rc == 0, f"{command!r} failed (exit {rc}):\n{stdout}{stderr}"
    return stdout


def _install_profile_when_restricted(vm):
    """Load the documented path-scoped profile if this real host requires it."""
    restricted = checked(
        vm,
        "sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null || true",
        user="user",
    ).strip() == "1"
    if restricted:
        checked(vm, "zaigr misc apparmor-profile > /tmp/zaigr.profile", user="user")
        checked(
            vm,
            "sudo install -m 0644 /tmp/zaigr.profile /etc/apparmor.d/zaigr-virtiofsd",
            user="user",
        )
        checked(vm, "sudo apparmor_parser -r /etc/apparmor.d/zaigr-virtiofsd", user="user")


@pytest.fixture
def uid_caller(request, cloudvm_factory):
    """Prepare an actual numeric guest account and isolated host workspace."""
    uid, gid = request.param
    vm = cloudvm_factory(CLOUDVM_DISTROS[0], standalone=True)
    checked(vm, "sudo install -m 0755 /dist/zaigr /usr/local/bin/zaigr", user="user")
    checked(vm, "sudo getent group kvm >/dev/null || sudo groupadd --system kvm")
    checked(vm, f"sudo getent group {gid} >/dev/null || sudo groupadd -g {gid} uid-host")
    checked(
        vm,
        f"sudo getent passwd {uid} >/dev/null || sudo useradd -o -u {uid} -g {gid} "
        f"-G kvm -M -s /bin/bash uid-host",
    )
    checked(
        vm,
        f"sudo usermod -aG kvm \"$(getent passwd {uid} | cut -d: -f1)\"",
    )
    groups = checked(
        vm,
        f"id -nG \"$(getent passwd {uid} | cut -d: -f1)\"",
    ).split()
    assert "kvm" in groups, f"numeric user {uid} is not a member of kvm: {groups}"
    checked(vm, f"sudo install -d -m 0755 -o {uid} -g {gid} {HOME}/old {HOME}/new {HOME}/later {HOME}/reset")
    checked(vm, "sudo chown -R " + f"{uid}:{gid} {HOME}")
    _install_profile_when_restricted(vm)
    env = {"HOME": HOME, "ZAIGR_VM_RAM": "512", "ZAIGR_VM_CPU": "1", "ZAIGR_DISK_SIZE": "8G"}
    return vm, uid, gid, env


@pytest.mark.timeout(300)
def test_root_caller_is_rejected_before_vm_launch(cloudvm_factory):
    """Host-enforced networking rejects root before launching a project VM."""
    vm = cloudvm_factory(CLOUDVM_DISTROS[0], standalone=True)
    checked(vm, "install -m 0755 /dist/zaigr /usr/local/bin/zaigr")
    env = {"HOME": "/tmp/zaigr-home", "ZAIGR_VM_RAM": "512", "ZAIGR_VM_CPU": "1", "ZAIGR_DISK_SIZE": "8G"}
    checked(vm, "install -d -m 0755 /tmp/zaigr-home /tmp/zaigr-project")
    start = vm.run(
        "zaigr project vm start --ram 512 --cpu 1",
        env=env,
        cwd="/tmp/zaigr-project",
        input="y\n",
        timeout=60,
    )
    assert start[2] != 0, start[0] + start[1]
    assert "must run as an unprivileged" in (start[0] + start[1]).lower()
    status = vm.run("zaigr project status", env=env, cwd="/tmp/zaigr-project")
    assert status[2] != 0, status[0] + status[1]
    assert "project status requires a project. run 'zaigr shell' to initialize it" in (
        status[0] + status[1]
    ).lower()
    supervisors = vm.run(
        "find /tmp/zaigr-home/.zaigr -name vm-supervisor.json -print 2>/dev/null",
        env=env,
    )
    assert supervisors[2] in (0, 1), supervisors[0] + supervisors[1]
    assert supervisors[0].strip() == "", supervisors[0]


@pytest.mark.parametrize("distro", [distro for distro in CLOUDVM_DISTROS if distro in {"ubuntu-24.04", "ubuntu-26.04"}])
@pytest.mark.timeout(360)
def test_restricted_userns_fails_closed_until_profile_is_loaded(cloudvm_factory, distro):
    """The real Ubuntu restriction blocks startup until the README profile is loaded."""
    vm = cloudvm_factory(distro, standalone=True)
    checked(vm, "sudo install -m 0755 /dist/zaigr /usr/local/bin/zaigr", user="user")
    env = {"HOME": "/home/user", "ZAIGR_VM_RAM": "512", "ZAIGR_VM_CPU": "1", "ZAIGR_DISK_SIZE": "8G"}
    restricted = checked(
        vm,
        "sysctl -n kernel.apparmor_restrict_unprivileged_userns",
        user="user",
    ).strip()
    assert restricted == "1"

    check = vm.run("zaigr misc check", user="user", env=env, timeout=90)
    assert check[2] != 0, check[0] + check[1]
    assert "apparmor" in (check[0] + check[1]).lower()
    checked(vm, "mkdir -p /home/user/project", user="user")
    start = vm.run(
        "zaigr project vm start --ram 512 --cpu 1", cwd="/home/user/project",
        user="user", env=env, input="y\n", timeout=60,
    )
    assert start[2] != 0, "project startup unexpectedly continued under restricted user namespaces"
    supervisors = vm.run(
        "find /home/user/.zaigr -name vm-supervisor.json -print 2>/dev/null",
        user="user",
    )
    assert supervisors[2] in (0, 1), supervisors[0] + supervisors[1]
    assert supervisors[0].strip() == "", supervisors[0]

    checked(vm, "zaigr misc apparmor-profile > /tmp/zaigr.profile", user="user")
    checked(
        vm,
        "sudo install -m 0644 /tmp/zaigr.profile /etc/apparmor.d/zaigr-virtiofsd",
        user="user",
    )
    checked(vm, "sudo apparmor_parser -r /etc/apparmor.d/zaigr-virtiofsd", user="user")
    assert "7/7 checks passed" in checked(vm, "zaigr misc check", user="user", env=env, timeout=90)
    started = vm.run(
        "zaigr project vm start --ram 512 --cpu 1", cwd="/home/user/project",
        user="user", env=env, input="y\n", timeout=240,
    )
    assert started[2] == 0, f"profile-loaded VM failed to start:\n{started[0]}{started[1]}"
    checked(vm, "zaigr project vm stop", cwd="/home/user/project", user="user", env=env, timeout=60)


@pytest.mark.timeout(480)
def test_none_virtiofs_sandbox_setting_is_rejected(cloudvm_factory):
    """The deprecated no-sandbox setting cannot be selected through the CLI."""
    vm = cloudvm_factory(CLOUDVM_DISTROS[0], standalone=True)
    checked(vm, "sudo install -m 0755 /dist/zaigr /usr/local/bin/zaigr", user="user")
    _install_profile_when_restricted(vm)
    env = {"HOME": "/home/user", "ZAIGR_VM_RAM": "512", "ZAIGR_VM_CPU": "1", "ZAIGR_DISK_SIZE": "8G"}
    checked(vm, "mkdir -p /home/user/zaigr-none-sandbox", user="user")
    checked(vm, "zaigr project vm start --ram 512 --cpu 1", cwd="/home/user/zaigr-none-sandbox", user="user", env=env, input="y\n", timeout=240)
    checked(vm, "zaigr project vm stop", cwd="/home/user/zaigr-none-sandbox", user="user", env=env, timeout=60)
    output = vm.run(
        "zaigr project vm set-config --virtiofs-sandbox none",
        cwd="/home/user/zaigr-none-sandbox",
        user="user",
        env=env,
        input="y\n",
        timeout=30,
    )
    assert output[2] != 0, output[0] + output[1]
    assert "none is unsupported" in output[0] + output[1]


@pytest.mark.parametrize("uid_caller", [(1001, 1001)], indirect=True)
@pytest.mark.timeout(900)
def test_runtime_upgrade_rejects_custom_base_and_preserves_pinned_project(uid_caller):
    """An incompatible custom base is rejected while an existing project remains usable."""
    vm, uid, gid, env = uid_caller
    run = partial(checked, vm, user=f"{uid}:{gid}", env=env)
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
    manifest["runtime_version"] = "previous-bundled-runtime"
    run(f"tee {manifest_path}", input=json.dumps(manifest) + "\n")

    rejected = vm.run(
        "zaigr project vm start --ram 512 --cpu 1", cwd=f"{HOME}/new",
        user=f"{uid}:{gid}", env=env, input="y\n", timeout=60,
    )
    assert rejected[2] != 0, rejected[0] + rejected[1]
    assert "incompatible with bundled runtime" in rejected[0] + rejected[1]
    assert json.loads(run(f"cat {manifest_path}")) == manifest
    run("zaigr global base-image reset")
    assert "mode: factory" in run("zaigr global base-image status")

    started = vm.run(
        "zaigr project vm start --ram 512 --cpu 1", cwd=f"{HOME}/new",
        user=f"{uid}:{gid}", env=env, input="y\n", timeout=480,
    )
    assert started[2] == 0, err_msg(started[0], started[1])
    assert "Preparing the base image for your account automatically" not in started[1]
    assert "global base-image reset" not in started[0] + started[1]
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
def test_old_runtime_with_empty_manifest_selects_factory(cloudvm_factory, legacy_user_uid):
    """Legacy empty manifests fall back to the current factory runtime."""
    vm = cloudvm_factory(CLOUDVM_DISTROS[0], standalone=True)
    checked(vm, "sudo install -m 0755 /dist/zaigr /usr/local/bin/zaigr", user="user")
    _install_profile_when_restricted(vm)
    host_home = "/home/user/zaigr-empty-manifest-home"
    project = "/home/user/zaigr-empty-manifest-project"
    env = {"HOME": host_home, "ZAIGR_VM_RAM": "512", "ZAIGR_VM_CPU": "1", "ZAIGR_DISK_SIZE": "8G"}
    run = partial(checked, vm, user="user", env=env, cwd=project)
    checked(vm, f"install -d -m 0755 {host_home} {project}", user="user")

    revision = "legacy-empty-manifest"
    revision_root = f"{host_home}/.zaigr/base-images/custom/revisions/{revision}"
    checked(vm, f"mkdir -p {revision_root}", user="user")
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
    run(f"tee {manifest_path}", input=json.dumps(manifest) + "\n")

    assert "mode: factory" in run("zaigr global base-image status")
    started = vm.run(
        "zaigr project vm start --ram 512 --cpu 1", cwd=project, user="user", env=env,
        input="y\n", timeout=300,
    )
    assert started[2] == 0, err_msg(started[0], started[1])
    assert "Preparing the base image for your account automatically" not in started[0] + started[1]
    assert run("zaigr project vm exec -- id -u").strip() == "1000"
    run("zaigr project vm stop", timeout=60)
