"""Small-window streaming client for observable TCP lease continuity."""

from pathlib import Path

import pytest

from ...conftest import err_msg, run


@pytest.fixture
def public_http_stream_client(project):
    """Build a static guest client with a bounded TCP receive window."""
    output = project.cwd / "public_http_stream_client"
    stdout, stderr, code = run([
        "gcc", "-static", "-O2", "-Wall", "-Wextra", "-Werror",
        "-o", output, Path(__file__).with_name("stream_client.c"),
    ])
    assert code == 0, err_msg(stdout, stderr)
    return output
