"""The check that separates a public site not answering from a zaigr failure."""

import http.server
import threading

import pytest

from tests.cli.host_network_fixture import public_site


class _Answer(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()

    def log_message(self, format, *args):
        pass


@pytest.fixture
def local_site(monkeypatch):
    """Stand in for a public site with a server on one loopback address."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Answer)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://site.test:{server.server_address[1]}/"
    monkeypatch.setitem(public_site.PUBLIC_SITES, "site.test", url)
    yield
    server.shutdown()
    server.server_close()
    thread.join()


def test_a_site_that_answers_leaves_the_failure_with_zaigr(local_site, monkeypatch):
    monkeypatch.setitem(public_site._addresses, "site.test", {"127.0.0.1"})
    check = public_site.check_sites(["site.test"])
    assert check.answered, check.details
    assert "HTTP 200" in check.details


def test_a_site_that_does_not_answer_makes_the_test_inconclusive(monkeypatch):
    monkeypatch.setitem(public_site.PUBLIC_SITES, "site.test", "http://127.0.0.1:9/")
    check = public_site.check_sites(["site.test"])
    assert not check.answered
    assert "site.test" in check.details


def test_the_address_the_test_used_is_the_one_checked(local_site, monkeypatch):
    monkeypatch.setitem(public_site._addresses, "site.test", {"127.0.0.1", "127.0.0.2"})
    check = public_site.check_sites(["site.test"])
    assert not check.answered
    assert "site.test at 127.0.0.2" in check.details
