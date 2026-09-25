"""Mechanical fixtures and independent endpoint observations."""

import os
import pty
import select
import socket
import time
import tty
from pathlib import Path

import pytest

from ..conftest import err_msg, run


@pytest.fixture
def endpoint_binary(project):
    """Build the independent guest endpoint without guest package installation."""
    output = project.cwd / "endpoint"
    stdout, stderr, code = run([
        "gcc", "-static", "-O2", "-Wall", "-Wextra", "-Werror",
        "-o", output, Path(__file__).with_name("host_access_fixture") / "endpoint.c",
    ])
    assert code == 0, err_msg(stdout, stderr)
    return output


@pytest.fixture
def host_devices(test_root):
    """Keep two verified PTY peers alive until dependent VMs have stopped."""
    endpoints = []
    try:
        for i in range(2):
            master, slave = pty.openpty()
            alias = test_root / f"serial-{i}"
            endpoints.append((master, slave, alias))
            tty.setraw(slave)
            alias.symlink_to(os.ttyname(slave))
            os.write(master, b"local-test")
            assert select.select([slave], [], [], 2)[0]
            assert os.read(slave, 10) == b"local-test"
        yield endpoints
    finally:
        for master, slave, _ in endpoints:
            os.close(master)
            os.close(slave)


def unused_port():
    """Choose an ephemeral candidate; the product must still handle bind races."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_text(path, expected, timeout=10):
    """Wait for an independent endpoint's readiness or activity marker."""
    deadline = time.monotonic() + timeout
    text = ""
    while time.monotonic() < deadline:
        if path.exists():
            text = path.read_text()
            if expected in text:
                return text
        time.sleep(0.02)
    pytest.fail(f"{path}: expected {expected!r}; got {text!r}")


def http_body(port):
    """Fetch one real response through the host endpoint with bounded waits."""
    with socket.create_connection(("127.0.0.1", port), timeout=2) as peer:
        peer.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        response = bytearray()
        deadline = time.monotonic() + 3
        while True:
            remaining = deadline - time.monotonic()
            assert remaining > 0, "HTTP response did not finish before the deadline"
            peer.settimeout(remaining)
            chunk = peer.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
    return bytes(response).split(b"\r\n\r\n", 1)[1].decode()


def receive_peer(fd, expected):
    """Assemble and verify a framed payload from the host serial peer."""
    result = bytearray()
    deadline = time.monotonic() + 5
    while len(result) < len(expected):
        remaining = deadline - time.monotonic()
        assert remaining > 0 and select.select([fd], [], [], remaining)[0], result
        result.extend(os.read(fd, 256))
    assert result == expected
