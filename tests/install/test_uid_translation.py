"""UID/GID translation through real host users and a cloud-image project VM."""

import json
from functools import partial

import pytest

from tests.conftest import err_msg
from tests.install.test_virtiofs_uid_identity import HOME, checked

pytest_plugins = ("tests.install.test_virtiofs_uid_identity",)


@pytest.mark.parametrize("uid_caller", [(2000, 2300)], indirect=True)
@pytest.mark.timeout(480)
def test_fresh_nonroot_project_uses_factory_identity_without_uid_preparation(uid_caller):
    """A fresh non-root first project shares files as its actual host UID/GID."""
    vm, uid, gid, env = uid_caller
    root = partial(checked, vm, env=env)
    user = partial(checked, vm, user=f"{uid}:{gid}", env=env, cwd=f"{HOME}/new")
    assert user("id -u").strip() == str(uid)
    assert user("id -g").strip() == str(gid)
    manifest_path = f"{HOME}/.zaigr/base-images/custom/current.json"
    root(f"test ! -e {manifest_path}")

    stdout, stderr, rc = vm.run(
        "zaigr project vm start --ram 512 --cpu 1", cwd=f"{HOME}/new",
        user=f"{uid}:{gid}", env=env, input="y\n", timeout=300,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert "Preparing the base image for your account automatically" not in stdout + stderr
    assert "Migrated guest user UID" not in stdout + stderr
    assert "mode: factory" in user("zaigr global base-image status")
    assert root(f"test ! -e {manifest_path}") == ""
    assert user("zaigr project vm exec -- id -u").strip() == "1000"
    assert user("zaigr project vm exec -- id -g").strip() == "1001"
    state_paths = user(f"find {HOME}/.zaigr/store -type d -name agent-state").splitlines()
    assert len(state_paths) == 1

    for host_share, guest_share in (
        (f"{HOME}/new", "/home/user/workspace"),
        (state_paths[0], "/home/user/.zaigr-agent-state"),
    ):
        user(f"tee {host_share}/host-private", input="host secret\n")
        user(f"chmod 0600 {host_share}/host-private")
        assert user(f"zaigr project vm exec -- cat {guest_share}/host-private") == "host secret\n"
        user(f"zaigr project vm exec -- tee {guest_share}/host-private", input="guest update\n")
        assert user(f"cat {host_share}/host-private") == "guest update\n"
        assert user(f"stat -c '%u:%g:%a' {host_share}/host-private").strip() == f"{uid}:{gid}:600"
        user(f"zaigr project vm exec -- tee {guest_share}/guest-reply", input="guest reply\n")
        user(f"zaigr project vm exec -- chmod 0600 {guest_share}/guest-reply")
        assert user(f"cat {host_share}/guest-reply") == "guest reply\n"
        assert user(f"stat -c '%u:%g:%a' {host_share}/guest-reply").strip() == f"{uid}:{gid}:600"
    user("zaigr project vm stop", timeout=60)


@pytest.mark.parametrize("uid_caller", [(1001, 1000), (2000, 2300)], indirect=True)
@pytest.mark.timeout(900)
def test_legacy_base_translates_mismatched_identity_on_both_shares(uid_caller):
    """An unknown-UID custom image translates private files in both directions."""
    vm, uid, gid, env = uid_caller
    host = partial(checked, vm, user=f"{uid}:{gid}", env=env)
    user = partial(checked, vm, user=f"{uid}:{gid}", env=env, cwd=f"{HOME}/new")

    host(f"mkdir -p {HOME}/.zaigr/setups/legacy-marker")
    host(
        f"tee {HOME}/.zaigr/setups/legacy-marker/setup.script",
        input="#!/bin/sh\nset -eu\nprintf legacy > /opt/legacy-marker\n",
    )
    host("zaigr global base-image setup run legacy-marker --ram 512 --cpu 1", timeout=600)
    manifest_path = f"{HOME}/.zaigr/base-images/custom/current.json"
    manifest = json.loads(host(f"cat {manifest_path}"))
    # Model a legacy manifest from a root-built custom base. Current callers
    # must be nonroot, so the custom image itself is created via the supported
    # numeric account and only this backward-compatibility field is synthesized.
    manifest["user_uid"] = 0
    host(f"tee {manifest_path}", input=json.dumps(manifest) + "\n")
    assert user("id -u").strip() == str(uid)
    assert user("id -g").strip() == str(gid)
    user("zaigr project vm start --ram 512 --cpu 1", input="y\n", timeout=300)
    user("zaigr project vm stop", timeout=60)
    user("zaigr project vm set-config --virtiofs-sandbox namespace", input="y\n")
    user("zaigr project vm start --ram 512 --cpu 1", input="y\n", timeout=300)
    assert "virtiofs-sandbox=namespace" in user("zaigr project vm show-config")
    guest_uid = user("zaigr project vm exec -- id -u").strip()
    guest_gid = user("zaigr project vm exec -- id -g").strip()
    assert guest_uid == "1000" and guest_uid != str(uid)
    assert guest_gid == "1001" and guest_gid != str(gid)
    assert user("zaigr project vm exec -- cat /opt/legacy-marker") == "legacy"
    state_paths = user(f"find {HOME}/.zaigr/store -type d -name agent-state").splitlines()
    assert len(state_paths) == 1

    for host_share, guest_share in (
        (f"{HOME}/new", "/home/user/workspace"),
        (state_paths[0], "/home/user/.zaigr-agent-state"),
    ):
        assert user(f"zaigr project vm exec -- findmnt -n -o FSTYPE {guest_share}").strip() == "virtiofs"
        user(f"tee {host_share}/host-private", input="host secret\n")
        user(f"chmod 0600 {host_share}/host-private")
        assert user(f"zaigr project vm exec -- cat {guest_share}/host-private") == "host secret\n"
        user(f"zaigr project vm exec -- tee {guest_share}/host-private", input="guest update\n")
        assert user(f"cat {host_share}/host-private") == "guest update\n"
        assert user(f"stat -c '%u:%g:%a' {host_share}/host-private").strip() == f"{uid}:{gid}:600"
        user(f"zaigr project vm exec -- tee {guest_share}/guest-reply", input="guest reply\n")
        user(f"zaigr project vm exec -- chmod 0600 {guest_share}/guest-reply")
        assert user(f"cat {host_share}/guest-reply") == "guest reply\n"
        assert user(f"stat -c '%u:%g:%a' {host_share}/guest-reply").strip() == f"{uid}:{gid}:600"
    assert json.loads(user(f"cat {manifest_path}")) == manifest
    user("zaigr project vm stop", timeout=60)
