"""Install the Debian package and follow the documented host workflow."""

import re

import pexpect
import pytest

from tests.install.conftest import CLOUDVM_DISTROS


def checked(vm, command, **kwargs):
    """Run one visible guest command and require success."""
    stdout, stderr, rc = vm.run(command, **kwargs)
    assert rc == 0, f"{command!r} failed (exit {rc}):\n{stdout}{stderr}"
    return stdout


@pytest.mark.timeout(900)
@pytest.mark.parametrize("distro", CLOUDVM_DISTROS)
def test_install_deb_and_run_documented_workflow(cloudvm_factory, distro):
    """Install prerequisites and zaigr, then exercise a real nested project VM."""
    vm = cloudvm_factory(distro)

    checked(vm, "sudo apt-get update -o APT::Update::Error-Mode=any", timeout=180, user="user")
    checked(
        vm,
        "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "
        "coreutils e2fsprogs qemu-system-x86 qemu-utils",
        timeout=300,
        user="user",
    )
    checked(vm, "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y curl", timeout=120, user="user")
    checked(vm, f"sudo DEBIAN_FRONTEND=noninteractive apt-get install -y /dist/{vm.package_name}", timeout=240, user="user")
    package_dependencies = checked(
        vm, f"dpkg-deb -f /dist/{vm.package_name} Depends", user="user"
    )
    assert "openssh-client" not in package_dependencies
    assert "util-linux" not in package_dependencies
    product_path = vm.zaigr_path_without_host_tools()
    assert vm.run("command -v ssh", user="user", env={"PATH": product_path})[2] != 0
    assert vm.run("command -v ssh-keygen", user="user", env={"PATH": product_path})[2] != 0
    assert vm.run("command -v truncate", user="user", env={"PATH": product_path})[2] != 0
    assert vm.run("command -v setpriv", user="user", env={"PATH": product_path})[2] != 0
    product_env = {"PATH": product_path}
    version = checked(vm, "zaigr --version", timeout=30, user="user", env=product_env)
    assert version.strip() == vm.package_version

    apparmor_restricted = checked(
        vm,
        "sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null || true",
        user="user",
    ).strip() == "1"
    kernel_release = checked(vm, "uname -r", user="user").strip()
    assert kernel_release, "cloud image did not report a running kernel release"
    if distro in {"ubuntu-24.04", "ubuntu-26.04"}:
        assert apparmor_restricted, f"{distro} did not boot with stock AppArmor restriction; kernel={kernel_release}"
    initial_check, initial_err, initial_rc = vm.run("zaigr misc check", timeout=90, user="user", env=product_env)
    if apparmor_restricted:
        assert initial_rc != 0, initial_check + initial_err
        assert "AppArmor" in initial_check + initial_err or "apparmor" in initial_check + initial_err.lower()
        # Follow README's path-scoped profile instructions on Ubuntu releases
        # whose stock AppArmor policy blocks user namespaces.
        checked(vm, "zaigr misc apparmor-profile > /tmp/zaigr.profile", user="user", env=product_env)
        checked(
            vm,
            "sudo install -m 0644 /tmp/zaigr.profile /etc/apparmor.d/zaigr-virtiofsd",
            user="user",
        )
        checked(vm, "sudo apparmor_parser -r /etc/apparmor.d/zaigr-virtiofsd", timeout=30, user="user")
    else:
        assert initial_rc == 0, initial_check + initial_err
        assert "7/7 checks passed" in initial_check, initial_check + initial_err
    check = checked(vm, "zaigr misc check", timeout=90, user="user", env=product_env)
    assert "7/7 checks passed" in check, initial_check + "\n" + check

    checked(vm, "mkdir -p /home/user/zaigr-install-project", user="user")
    started = vm.run(
        "zaigr project vm start", cwd="/home/user/zaigr-install-project",
        input="y\n", timeout=240, user="user", env=product_env,
    )
    assert started[2] == 0, f"project VM failed to start:\n{started[0]}{started[1]}"

    root_status = checked(
        vm,
        "zaigr project vm exec --root -- passwd -S root",
        cwd="/home/user/zaigr-install-project",
        input="y\n",
        timeout=30,
        user="user",
        env=product_env,
    )
    assert re.search(r"^root\s+L(?:\s|$)", root_status, re.MULTILINE), root_status

    su_stdout, su_stderr, su_rc = vm.run(
        "zaigr project vm exec -- su - -c 'id -u'",
        cwd="/home/user/zaigr-install-project",
        input="not-the-root-password\n",
        timeout=30,
        user="user",
        env=product_env,
    )
    assert su_rc != 0, f"unprivileged su unexpectedly opened a root login shell:\n{su_stdout}{su_stderr}"
    assert "Authentication failure" in su_stdout + su_stderr, su_stdout + su_stderr

    root_exec_uid = checked(
        vm,
        "zaigr project vm exec --root -- id -u",
        cwd="/home/user/zaigr-install-project",
        input="y\n",
        timeout=30,
        user="user",
        env=product_env,
    )
    assert root_exec_uid.strip() == "0", root_exec_uid

    root_shell = vm.ssh_command(
        "zaigr shell --root",
        timeout=180,
        user="user",
        cwd="/home/user/zaigr-install-project",
        env=product_env,
    )
    try:
        root_shell.expect(r"Continue with root shell\? \[y/N\]", timeout=30)
        root_shell.sendline("y")
        root_shell.expect(r"root@[^:]+:.*# ", timeout=60)
        root_shell.sendline("printf 'ROOT_SHELL_UID=%s\\n' \"$(id -u)\"")
        root_shell.expect("ROOT_SHELL_UID=0", timeout=20)
        root_shell.expect(r"root@[^:]+:.*# ", timeout=20)
        root_shell.sendline("exit")
        root_shell.expect(pexpect.EOF, timeout=20)
    finally:
        if root_shell.isalive():
            root_shell.close(force=True)
    root_shell_transcript = root_shell.transcript.getvalue()
    assert "ROOT_SHELL_UID=0" in root_shell_transcript, root_shell_transcript

    allowed = vm.run(
        "zaigr project firewall allow deb.debian.org", cwd="/home/user/zaigr-install-project",
        timeout=30, user="user", env=product_env,
    )
    assert allowed[2] == 0, f"allow command failed:\n{allowed[0]}{allowed[1]}"
    log = vm.ssh_command(
        "zaigr project firewall domain-log", cwd="/home/user/zaigr-install-project",
        timeout=20, user="user", env=product_env,
    )
    try:
        log.expect("Firewall packet events coalesce", timeout=10)
        allowed_curl = vm.run(
            "zaigr project vm exec -- curl --noproxy '*' -4fsS --connect-timeout 5 "
            "--max-time 15 https://deb.debian.org/", cwd="/home/user/zaigr-install-project",
            timeout=30, user="user", env=product_env,
        )
        assert allowed_curl[2] == 0, f"allowed domain failed:\n{allowed_curl[0]}{allowed_curl[1]}"
        log.expect(r"DNS allowed\s+deb\.debian\.org", timeout=15)
        blocked_curl = vm.run(
            "zaigr project vm exec -- curl --noproxy '*' -4fsS --connect-timeout 3 "
            "--max-time 8 https://example.com/", cwd="/home/user/zaigr-install-project",
            timeout=20, user="user", env=product_env,
        )
        assert blocked_curl[2] != 0, "example.com unexpectedly passed the default-deny project firewall"
        log.expect(r"DNS blocked\s+example\.com", timeout=15)
    finally:
        if log.isalive():
            log.sendintr()
            log.expect(pexpect.EOF, timeout=10)
            log.close()
    transcript = log.transcript.getvalue()
    assert re.search(r"DNS allowed\s+deb\.debian\.org", transcript), transcript
    assert re.search(r"DNS blocked\s+example\.com", transcript), transcript
    checked(
        vm,
        "zaigr project vm stop",
        cwd="/home/user/zaigr-install-project",
        timeout=60,
        user="user",
        env=product_env,
    )
