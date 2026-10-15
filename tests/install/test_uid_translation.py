"""Ownership translation with a real non-root caller and a different guest UID."""

import json
from functools import partial

import pytest

from tests.conftest import err_msg
from tests.install.test_virtiofs_uid_identity import HOME, checked

pytest_plugins = ("tests.install.test_virtiofs_uid_identity",)


@pytest.mark.parametrize("uid_caller", [(2000, 2300)], indirect=True)
@pytest.mark.timeout(480)
def test_fresh_nonroot_project_uses_factory_identity_without_uid_preparation(uid_caller):
    """A fresh non-root first project uses virtiofs translation without rebuilding the base."""
    container, uid, gid, env = uid_caller
    root = partial(checked, container, env=env)
    user = partial(checked, container, user=f"{uid}:{gid}", env=env, cwd=f"{HOME}/new")
    assert user("id -u").strip() == str(uid)
    assert user("id -g").strip() == str(gid)
    manifest_path = f"{HOME}/.zaigr/base-images/custom/current.json"
    root(f"test ! -e {manifest_path}")

    stdout, stderr, rc = container.run(
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
@pytest.mark.parametrize("sandbox", ["namespace", "none"])
@pytest.mark.timeout(900)
def test_legacy_base_translates_mismatched_identity_on_both_shares(uid_caller, sandbox):
    """An unknown-UID custom image translates private files in both directions."""
    container, uid, gid, env = uid_caller
    root = partial(checked, container, env=env)
    user = partial(checked, container, user=f"{uid}:{gid}", env=env, cwd=f"{HOME}/new")

    # The unchanged CLI exempts legacy custom bases from automatic migration.
    # Build one through the public CLI as root, then transfer only host storage.
    root(f"mkdir -p {HOME}/.zaigr/setups/legacy-marker")
    root(f"tee {HOME}/.zaigr/setups/legacy-marker/setup.script",
         input="#!/bin/sh\nset -eu\nprintf legacy > /opt/legacy-marker\n")
    root("zaigr global base-image setup run legacy-marker --ram 512 --cpu 1", timeout=300)
    manifest_path = f"{HOME}/.zaigr/base-images/custom/current.json"
    manifest = json.loads(root(f"cat {manifest_path}"))
    assert manifest.get("user_uid", 0) == 0
    root(f"chown -R {uid}:{gid} {HOME}")
    assert user("id -u").strip() == str(uid)
    assert user("id -g").strip() == str(gid)
    # Project configuration commands require an initialized project. Initialize
    # it through the public start command, then stop before changing the sandbox.
    user("zaigr project vm start --ram 512 --cpu 1", input="y\n", timeout=180)
    user("zaigr project vm stop", timeout=60)
    user(f"zaigr project vm set-config --virtiofs-sandbox {sandbox}", input="y\n")
    user("zaigr project vm start --ram 512 --cpu 1", input="y\n", timeout=180)
    assert f"virtiofs-sandbox={sandbox}" in user("zaigr project vm show-config")
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
