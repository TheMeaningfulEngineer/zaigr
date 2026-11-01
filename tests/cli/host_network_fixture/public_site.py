"""Tell a public site that is not answering apart from a failure in zaigr.

Some tests reach real public sites on purpose, because only a real site shows how
zaigr copes with CDN addresses and DNS answers. When such a test fails, the request
is repeated from the host straight away. If the host reaches the site, the problem
is on zaigr's side. If it does not, the test cannot say anything about zaigr, so it
runs once more and, if it fails again, stays failed and is labelled inconclusive.
"""

import inspect
import socket
import subprocess
from dataclasses import dataclass
from urllib.parse import urlsplit

PUBLIC_SITES = {
    "deb.debian.org": "http://deb.debian.org/debian/dists/trixie/Release",
    "pypi.org": "https://pypi.org/",
}

_addresses: dict[str, set[str]] = {}


@dataclass
class SiteCheck:
    """The result of repeating a test's public requests from the host."""

    answered: bool
    details: str


def public_address(host):
    """Resolve a public site and remember the address the test will use."""
    address = socket.gethostbyname(host)
    _addresses.setdefault(host, set()).add(address)
    return address


def forget_addresses():
    """Start a test attempt without the addresses of the previous one."""
    _addresses.clear()


def sites_used_by(item):
    """Return the public sites named in a test's source."""
    source = inspect.getsource(item.function)
    return sorted(site for site in PUBLIC_SITES if site in source)


def _probe(site, address=None):
    """Repeat a request from the host and describe what came back."""
    url = PUBLIC_SITES[site]
    parts = urlsplit(url)
    command = ["curl", "--noproxy", "*", "-4", "-sS", "--connect-timeout", "4",
               "--max-time", "12", "--output", "/dev/null", "--write-out", "%{http_code}"]
    if address is not None:
        port = parts.port or (443 if parts.scheme == "https" else 80)
        command += ["--resolve", f"{parts.hostname}:{port}:{address}"]
    target = f"{site} at {address}" if address else site
    try:
        result = subprocess.run(
            [*command, url], capture_output=True, text=True, timeout=15, check=False,
        )
    except subprocess.TimeoutExpired:
        return False, f"{target}: no answer within 15 seconds"
    status = result.stdout.strip()
    if result.returncode == 0 and status[:1] in {"2", "3"}:
        return True, f"{target}: HTTP {status}"
    reason = result.stderr.strip() or f"HTTP {status}"
    return False, f"{target}: {reason}"


def check_sites(sites):
    """Repeat from the host the requests behind a failed test."""
    results = []
    for site in sites:
        for address in sorted(_addresses.get(site, {None}), key=str):
            results.append(_probe(site, address))
    return SiteCheck(
        answered=all(answered for answered, _ in results),
        details="; ".join(detail for _, detail in results),
    )
