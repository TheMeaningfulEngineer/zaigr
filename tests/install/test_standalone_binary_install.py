"""Install the standalone artifact as a regular user and exercise its VM workflow."""

import hashlib
from functools import partial

import pytest

from tests.install.conftest import CLOUDVM_DISTROS


def checked(vm, command, **kwargs):
    """Run one visible guest command and require success."""
    stdout, stderr, rc = vm.run(command, **kwargs)
    assert rc == 0, f"{command!r} failed (exit {rc}):\n{stdout}{stderr}"
    return stdout


@pytest.mark.parametrize("distro", CLOUDVM_DISTROS)
@pytest.mark.timeout(900)
def test_install_standalone_as_regular_user_and_run_vm(cloudvm_factory, distro):
    """Use only the downloaded binary, documented dependencies, and user KVM access."""
    vm = cloudvm_factory(distro, standalone=True)
    checked(vm, "sudo apt-get update -o APT::Update::Error-Mode=any", timeout=180, user="user")
    checked(
        vm,
        "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "
        "coreutils e2fsprogs openssh-client qemu-system-x86 qemu-utils "
        "slirp4netns util-linux",
        timeout=300,
        user="user",
    )

    checked(vm, "mkdir -p /home/user/project", user="user")
    checked(vm, "cp /dist/zaigr /home/user/zaigr", user="user")
    checked(vm, "chmod 0644 /home/user/zaigr", user="user")
    checked(vm, "mkdir -p /home/user/.local/bin", user="user")
    checked(vm, "install -m 0755 /home/user/zaigr /home/user/.local/bin/zaigr", user="user")
    host_uid = checked(vm, "id -u", user="user").strip()
    host_gid = checked(vm, "id -g", user="user").strip()
    assert host_uid.isdigit() and host_uid != "0"
    assert checked(vm, "command -v zaigr", user="user", env={
        "PATH": "/home/user/.local/bin:/usr/local/bin:/usr/bin:/bin",
    }).strip() == "/home/user/.local/bin/zaigr"
    assert checked(vm, "stat -c '%u %a' /home/user/.local/bin/zaigr", user="user").strip() == f"{host_uid} 755"
    expected_digest = hashlib.sha256(vm.dist_artifact.read_bytes()).hexdigest()
    assert checked(vm, "sha256sum /home/user/.local/bin/zaigr", user="user").split()[0] == expected_digest
    checked(vm, "test ! -e /usr/bin/zaigr", user="user")
    package_query = vm.run("dpkg-query -W zaigr", user="user")
    assert package_query[2] != 0, "standalone install must not install the Debian package"

    apparmor_restricted = checked(
        vm,
        "sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null || true",
        user="user",
    ).strip() == "1"
    initial_check = vm.run(
        "/home/user/.local/bin/zaigr misc check", user="user", timeout=90,
        env={"PATH": "/home/user/.local/bin:/usr/local/bin:/usr/bin:/bin"},
    )
    if apparmor_restricted:
        assert initial_check[2] != 0, initial_check[0] + initial_check[1]
        assert "apparmor" in (initial_check[0] + initial_check[1]).lower()
        checked(
            vm,
            "/home/user/.local/bin/zaigr misc apparmor-profile > /tmp/zaigr.profile",
            user="user",
        )
        checked(
            vm,
            "sudo install -m 0644 /tmp/zaigr.profile /etc/apparmor.d/zaigr-virtiofsd",
            user="user",
        )
        checked(
            vm,
            "sudo apparmor_parser -r /etc/apparmor.d/zaigr-virtiofsd",
            user="user",
            timeout=30,
        )
    else:
        assert initial_check[2] == 0, initial_check[0] + initial_check[1]
    check = checked(
        vm,
        "/home/user/.local/bin/zaigr misc check",
        user="user",
        timeout=90,
        env={"PATH": "/home/user/.local/bin:/usr/local/bin:/usr/bin:/bin"},
    )
    assert "6/6 checks passed" in check

    user = partial(
        checked,
        vm,
        user="user",
        cwd="/home/user/project",
        env={"PATH": "/home/user/.local/bin:/usr/local/bin:/usr/bin:/bin"},
    )
    host_project_owner, host_project_mode = user("stat -c '%u:%g %a' .").split()
    assert host_project_owner == f"{host_uid}:{host_gid}"
    user("printf 'standalone installation works\\n' > installation-input.txt")
    start = vm.run(
        "/home/user/.local/bin/zaigr project vm start",
        cwd="/home/user/project", user="user", input="y\n", timeout=240,
        env={"PATH": "/home/user/.local/bin:/usr/local/bin:/usr/bin:/bin"},
    )
    assert start[2] == 0, f"project VM failed to start:\n{start[0]}{start[1]}"
    guest_uid = user("/home/user/.local/bin/zaigr project vm exec -- id -u", timeout=30).strip()
    guest_gid = user("/home/user/.local/bin/zaigr project vm exec -- id -g", timeout=30).strip()
    assert guest_uid.isdigit() and guest_uid != "0"
    guest_project_owner, guest_project_mode = user(
        "/home/user/.local/bin/zaigr project vm exec -- stat -c '%u:%g %a' .", timeout=30
    ).split()
    assert guest_project_owner == f"{guest_uid}:{guest_gid}"
    assert guest_project_mode == host_project_mode
    assert user("/home/user/.local/bin/zaigr project vm exec -- cat installation-input.txt", timeout=30) == "standalone installation works\n"
    input_owner = user(
        "/home/user/.local/bin/zaigr project vm exec -- stat -c '%u:%g' installation-input.txt", timeout=30
    ).strip()
    assert input_owner == f"{guest_uid}:{guest_gid}"
    user(
        "/home/user/.local/bin/zaigr project vm exec -- sh -c "
        "'cat installation-input.txt > installation-output.txt'",
        timeout=30,
    )
    assert user("cat installation-output.txt") == "standalone installation works\n"
    output_owner = user("stat -c '%u:%g' installation-output.txt").strip()
    assert output_owner == f"{host_uid}:{host_gid}"
    stopped = user("/home/user/.local/bin/zaigr project vm stop", timeout=60)
    assert "Project VM stopped" in stopped
    qemu_processes = vm.run("ps -eo comm= | grep -E '^qemu-system' || true", user="user")
    assert qemu_processes[2] == 0, qemu_processes[0] + qemu_processes[1]
    assert qemu_processes[0].strip() == "", "QEMU remains active after project VM shutdown:\n" + qemu_processes[0]
