"""Install the real standalone binary and run a VM without root privileges."""

import hashlib
from functools import partial

import pytest

from tests.conftest import err_msg, run


def _checked_run(container, command, **kwargs):
    """Run a visible container command and return its successful output."""
    stdout, stderr, rc = container.run(command, **kwargs)
    assert rc == 0, err_msg(stdout, stderr)
    return stdout


@pytest.mark.timeout(900)
@pytest.mark.parametrize("image", [
    "docker.io/library/debian:bookworm",
    "docker.io/library/debian:trixie",
    "docker.io/library/ubuntu:22.04",
    "docker.io/library/ubuntu:24.04",
])
def test_install_standalone_as_regular_user_and_run_vm(container_factory, image):
    """Use only the downloaded binary, documented host dependencies, and user KVM access."""
    container = container_factory(image, standalone=True)
    admin = partial(_checked_run, container)
    user = partial(
        _checked_run,
        container,
        user="zaigr-install",
        cwd="/home/zaigr-install/project",
        env={
            "HOME": "/home/zaigr-install",
            "PATH": "/home/zaigr-install/.local/bin:/usr/local/bin:/usr/bin:/bin",
        },
    )

    admin("apt-get update -o APT::Update::Error-Mode=any", timeout=180)
    admin(
        "DEBIAN_FRONTEND=noninteractive apt-get install -y "
        "coreutils e2fsprogs openssh-client qemu-system-x86 qemu-utils",
        timeout=300,
    )
    admin("useradd --create-home --uid 2000 --user-group --shell /bin/bash zaigr-install")
    admin("install -d -o zaigr-install -g zaigr-install /home/zaigr-install/project")

    assert user("id -u").strip() == "2000"
    user("! command -v zaigr")
    stdout, stderr, rc = container.run("dpkg-query -W zaigr")
    assert rc != 0, "zaigr must not be installed as a package: " + err_msg(stdout, stderr)

    # A browser download has no executable bit; installation supplies it as the user.
    user('cp /dist/zaigr "$HOME/zaigr"')
    user('chmod 0644 "$HOME/zaigr"')
    user('mkdir -p "$HOME/.local/bin"')
    user('install -m 0755 "$HOME/zaigr" "$HOME/.local/bin/zaigr"')
    assert user("command -v zaigr").strip() == "/home/zaigr-install/.local/bin/zaigr"
    assert user('stat -c "%u %a" "$HOME/.local/bin/zaigr"').strip() == "2000 755"
    expected_digest = hashlib.sha256(container.dist_artifact.read_bytes()).hexdigest()
    assert user('sha256sum "$HOME/.local/bin/zaigr"').split()[0] == expected_digest
    user("test ! -e /usr/bin/zaigr")
    user("zaigr misc check", timeout=30)

    user("printf 'standalone installation works\\n' > installation-input.txt")
    user("zaigr project vm start", input="y\n", timeout=180)
    try:
        guest_uid = user("zaigr project vm exec -- id -u", timeout=30).strip()
        assert guest_uid.isdigit() and guest_uid != "0"
        user("zaigr project vm exec -- stat -c '%u:%g %a' .", timeout=30)
        assert user(
            "zaigr project vm exec -- cat installation-input.txt", timeout=30
        ) == "standalone installation works\n"
        user(
            "zaigr project vm exec -- sh -c "
            "'cat installation-input.txt > installation-output.txt'",
            timeout=30,
        )
        assert user("cat installation-output.txt") == "standalone installation works\n"
    finally:
        stopped = user("zaigr project vm stop", timeout=60)
        assert "Project VM stopped" in stopped
        stdout, stderr, rc = run(
            ["podman", "top", container.name, "hpid", "comm"], timeout=10
        )
        assert rc == 0, err_msg(stdout, stderr)
        for row in stdout.splitlines()[1:]:
            pid, command = row.split(maxsplit=1)
            if not command.startswith("qemu-system"):
                continue
            # The container's PID 1 may not reap detached children. A zombie
            # with no surviving worker threads has completed shutdown.
            state, error, status = run(
                ["ps", "-p", pid, "-o", "stat=,nlwp="], timeout=10
            )
            fields = state.split()
            assert status == 1 or (
                status == 0
                and len(fields) == 2
                and fields[0][0] in {"Z", "X"}
                and fields[1] in {"0", "1"}
            ), "QEMU remains active after VM shutdown:\n" + err_msg(state, error)
