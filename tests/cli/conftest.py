"""Shared fixtures for public CLI integration tests."""

import pytest
from _pytest.runner import runtestprotocol

from tests.cli.host_network_fixture import public_site

pytest_plugins = (
    "tests.cli.host_access_endpoints",
    "tests.cli.host_network_fixture.dns",
    "tests.cli.host_network_fixture.endpoints",
    "tests.cli.host_network_fixture.stream",
)

PUBLIC_SITE_CHECK = "public_site_check"


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_protocol(item, nextitem):
    """Run a public-site test again if it failed while its site was not answering."""
    if not public_site.sites_used_by(item):
        return None
    item.ihook.pytest_runtest_logstart(nodeid=item.nodeid, location=item.location)
    item.public_site_attempt = 1
    public_site.forget_addresses()
    reports = runtestprotocol(item, nextitem=nextitem, log=False)
    if getattr(item, "public_site_down", False):
        item.public_site_attempt = 2
        public_site.forget_addresses()
        reports = runtestprotocol(item, nextitem=nextitem, log=False)
    for report in reports:
        item.ihook.pytest_runtest_logreport(report=report)
    item.ihook.pytest_runtest_logfinish(nodeid=item.nodeid, location=item.location)
    return True


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """Repeat a failed test's public requests from the host while it still matters."""
    outcome = yield
    report = outcome.get_result()
    sites = public_site.sites_used_by(item)
    if report.when != "call" or not report.failed or not sites:
        return
    check = public_site.check_sites(sites)
    item.public_site_down = not check.answered
    if check.answered:
        verdict = f"FAILED on zaigr's side, the host reached the site ({check.details})"
    elif item.public_site_attempt == 1:
        verdict = f"the host could not reach the site either, retrying ({check.details})"
    else:
        verdict = f"INCONCLUSIVE, the host could not reach the site ({check.details})"
    item.user_properties.append((PUBLIC_SITE_CHECK, f"{item.nodeid}: {verdict}"))
    report.sections.append(("Public site check", verdict))


def pytest_terminal_summary(terminalreporter):
    """List what the host saw for every public-site test that failed."""
    lines = {
        value
        for reports in terminalreporter.stats.values()
        for report in reports
        for name, value in getattr(report, "user_properties", [])
        if name == PUBLIC_SITE_CHECK
    }
    if lines:
        terminalreporter.section("Public site check")
        for line in sorted(lines):
            terminalreporter.line(line)
