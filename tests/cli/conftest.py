"""Shared fixtures for public CLI integration tests."""

pytest_plugins = (
    "tests.cli.host_access_endpoints",
    "tests.cli.host_network_fixture.dns",
    "tests.cli.host_network_fixture.endpoints",
    "tests.cli.host_network_fixture.stream",
)
