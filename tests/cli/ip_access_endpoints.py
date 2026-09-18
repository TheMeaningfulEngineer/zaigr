"""Owned network namespaces and real services for project IP acceptance tests."""

import json
import os
import shlex
import uuid
from pathlib import Path

import pexpect
import pytest

from ..conftest import err_msg, run, spawn_interactive


def checked(cmd, **kwargs):
    """Run fixture infrastructure with the standard command transcript."""
    stdout, stderr, rc = run(cmd, **kwargs)
    assert rc == 0, err_msg(stdout, stderr)
    return stdout


def udp_probe(address):
    """Return a real UDP request command usable on the host and in a guest."""
    return [
        "timeout", "4", "bash", "-c",
        f"exec 3<>/dev/udp/{address}/18082; printf 'probe\\n' >&3; head -n 1 <&3",
    ]


def ssh_options(key):
    """Use only disposable credentials for the isolated test SSH service."""
    return [
        "ssh", "-F", "/dev/null", "-i", str(key), "-p", "2222",
        "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=4",
    ]


def assert_host_services(endpoint, key):
    """Prove exact services are alive in the same host network as the test VM."""
    prefix = endpoint["host_command"]
    for port in (18080, 18081):
        output = checked(prefix + [
            "curl", "--noproxy", "*", "-4fsS", "--max-time", "4",
            f"http://{endpoint['ip']}:{port}/",
        ], timeout=10)
        assert output.strip() == endpoint["token"] + ":0"
    assert checked(prefix + udp_probe(endpoint["ip"]), timeout=10).strip() == (
        endpoint["token"] + ":probe"
    )
    output = checked(
        prefix + ssh_options(key)
        + [f"root@{endpoint['ip']}", "printf", endpoint["token"]], timeout=10,
    )
    assert output == endpoint["token"]


@pytest.fixture()
def ip_network(test_root):
    """Own an isolated network, SSH server, and TCP/UDP services until VM teardown."""
    directory = test_root / "ip-network"
    directory.mkdir()
    key = directory / "client-key"
    host_key = directory / "host-key"
    for path in (key, host_key):
        checked(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", path])
    endpoints = [
        {"ip": f"192.0.2.{index + 11}", "token": f"ip-endpoint-{uuid.uuid4().hex}"}
        for index in range(2)
    ]
    host = {"port": 18083, "token": f"host-endpoint-{uuid.uuid4().hex}"}
    (directory / "services.json").write_text(
        json.dumps({"endpoints": endpoints, "host": host}), encoding="utf-8",
    )
    (directory / "sshd-empty").mkdir()
    (directory / "ssh-client.conf").write_text("Host *\n", encoding="utf-8")
    (directory / "sshd.conf").write_text(
        "Port 2222\nListenAddress 192.0.2.11\nListenAddress 192.0.2.12\n"
        f"HostKey {host_key}\nPidFile {directory}/sshd.pid\n"
        f"AuthorizedKeysFile {key}.pub\nPasswordAuthentication no\n"
        "KbdInteractiveAuthentication no\nUsePAM no\nPermitRootLogin yes\n"
        "StrictModes no\nAllowTcpForwarding no\nX11Forwarding no\n",
        encoding="utf-8",
    )
    server = Path(__file__).with_name("ip_access_fixture") / "server.py"
    command = [
        "unshare", "--user", "--map-current-user", "--map-auto",
        "--setuid", "0", "--setgid", "0", "--net", "--mount",
        "--pid", "--fork", "--kill-child",
        "python3", "-u", str(server), str(directory),
    ]
    process = spawn_interactive(shlex.join(command), timeout=20)
    namespace_pid = None
    namespace_inode = None
    qemu_cleanup = server.with_name("qemu_cleanup.py")
    try:
        process.expect(r"IP_NETWORK_READY ([0-9]+)", timeout=20)
        namespace_pid = process.match.group(1)
        namespace_inode = Path(f"/proc/{namespace_pid}/ns/net").stat().st_ino
        prefix = [
            "nsenter", "--target", namespace_pid, "--user", "--net", "--mount",
            "--preserve-credentials", "--wd=.",
        ]
        for endpoint in endpoints:
            endpoint["host_command"] = prefix
        yield {
            "first": endpoints[0], "second": endpoints[1], "key": key,
            "host": host, "host_command": prefix, "directory": directory,
            "namespace_inode": namespace_inode, "host_uid": os.getuid(),
            "qemu_cleanup": qemu_cleanup,
        }
    finally:
        try:
            if namespace_inode is not None:
                checked([
                    "python3", qemu_cleanup, "--cleanup",
                    str(namespace_inode), str(os.getuid()),
                ], timeout=20)
        finally:
            try:
                if process.isalive():
                    if namespace_pid is None:
                        process.sendcontrol("c")
                    else:
                        checked([
                            "nsenter", "--target", namespace_pid, "--user",
                            "--setuid", "0", "--setgid", "0",
                            "kill", "-TERM", namespace_pid,
                        ], timeout=10)
                    process.expect(pexpect.EOF, timeout=15)
                process.close()
                assert process.exitstatus == 0, process.before
            finally:
                if process.isalive():
                    # The supervisor's death kills PID 1 and its endpoint services.
                    checked([
                        "nsenter", "--target", str(process.pid), "--user",
                        "--setuid", "0", "--setgid", "0",
                        "kill", "-KILL", str(process.pid),
                    ], timeout=10)
                    process.expect(pexpect.EOF, timeout=10)
                    process.close()


@pytest.fixture()
def zaigr_bin(zaigr_bin, request):
    """Enter the service network while retaining the caller's UID and project cwd."""
    if "ip_endpoints" not in request.fixturenames and "host_endpoint" not in request.fixturenames:
        return zaigr_bin
    network = request.getfixturevalue("ip_network")
    wrapper = network["directory"] / "zaigr"
    wrapper.write_text(
        "#!/bin/sh\nexec " + shlex.join(network["host_command"] + [str(zaigr_bin)])
        + ' "$@"\n', encoding="utf-8",
    )
    wrapper.chmod(0o700)
    return wrapper


@pytest.fixture()
def ip_endpoints(ip_network):
    """Check both real destinations before any guest denial is interpreted."""
    for endpoint in (ip_network["first"], ip_network["second"]):
        assert_host_services(endpoint, ip_network["key"])
    return ip_network


@pytest.fixture()
def host_endpoint(ip_network):
    """Expose the namespace's loopback server via QEMU's documented host alias."""
    host = ip_network["host"]
    output = checked(ip_network["host_command"] + [
        "curl", "--noproxy", "*", "-4fsS", "--max-time", "4",
        f"http://127.0.0.1:{host['port']}/sentinel",
    ])
    assert output == host["token"]
    return host
