"""Exercise the dependency checker CLI against local upstream-shaped responses."""

import json
import re
import shutil
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from tests.conftest import REPO_ROOT, err_msg, run


def _summary_rows(out):
    """Map each summary label, without its tree branches, to its table line."""
    lines = out.split("Release notes:", 1)[0].splitlines()[2:]
    return {re.split(r"\s{2,}", line.lstrip("│├└─ "))[0]: line for line in lines}


def _install_checker(repo):
    """Copy the checker and a stable fixture lock into an isolated repository."""
    release_dir = repo / "release"
    release_dir.mkdir(parents=True)
    shutil.copy2(Path(REPO_ROOT) / "release" / "deps-check", release_dir / "deps-check")
    (repo / "deps.lock").write_text(
        "KERNEL_VERSION=6.12.0\nVIRTIOFSD_VERSION=1.13.2\nLIBSECCOMP_VERSION=2.6.0\n"
        "LIBCAP_NG_VERSION=0.8.5\nSLIRP4NETNS_VERSION=1.3.4\nGO_VERSION=1.24.4\n"
        "DEBIAN_SUITE=trixie\n",
        encoding="utf-8",
    )
    (repo / "go.mod").write_text(
        "module deps-check-fixture\n\n"
        "go 1.24.0\n\n"
        "require (\n"
        "\tgithub.com/google/nftables v0.3.0\n"
        "\tgithub.com/mdlayher/netlink v1.7.3-0.20250113171957-fbb4dce95f42\n"
        "\tgithub.com/klauspost/compress v1.18.5\n"
        "\tgithub.com/miekg/dns v1.1.70\n"
        "\tgithub.com/spf13/cobra v1.10.1\n"
        "\tgithub.com/vishvananda/netlink v1.3.0\n"
        "\tgolang.org/x/sys v0.39.0\n"
        "\texample.com/acme/tool/v2 v2.1.0\n"
        "\texample.org/other/tool v1.0.0\n"
        "\texample.org/legacy v1.2.0\n"
        "\texample.org/incompatible v1.0.0\n"
        "\tgopkg.in/yaml.v3 v3.0.1\n"
        ")\n\n"
        "require github.com/ignored/transitive v2.0.0 // indirect\n",
        encoding="utf-8",
    )
    setup = repo / "cmd" / "zaigr" / "builtin" / "setups" / "zaigr-dev"
    setup.mkdir(parents=True)
    (setup / "setup.script").write_text('rust_version="${RUST_VERSION:-1.82.0}"\n', encoding="utf-8")
    return release_dir / "deps-check"


def _stable_sources():
    """Return local release data with later versions and intervening notes."""
    kernel = {
        "releases": [
            {"version": "6.12.9", "moniker": "stable"},
            {"version": "6.18.2", "moniker": "longterm"},
            {"version": "7.0.1", "moniker": "stable"},
        ]
    }
    seccomp_first_page = [
        {"tag_name": "v2.6.1", "body": "seccomp patch one"},
        {"tag_name": "v2.6.2", "body": "seccomp patch two"},
    ]
    seccomp_first_page.extend(
        {"tag_name": f"unreleased-{index}", "body": "ignored fixture row"}
        for index in range(98)
    )
    virtiofsd_first_page = [
        {
            "tag_name": "v1.13.3",
            "description": (
                "[![Github Releases](badge.svg)](release.svg)\n\n"
                "virtiofsd patch three\n[download](archive.zip)\n\n"
                "- outer  item\n  - nested  item\n\n```sh\n    printf  'a  b'\n```"
            ),
        },
        {"tag_name": "v1.13.4", "description": "virtiofsd patch four"},
    ]
    virtiofsd_first_page.extend(
        {"tag_name": f"unreleased-{index}", "description": "ignored fixture row"}
        for index in range(98)
    )
    github = {
        "/repos/seccomp/libseccomp/releases": {
            1: seccomp_first_page,
            2: [{"tag_name": "v2.6.10", "body": "seccomp patch ten"}],
        },
        "/repos/seccomp/libseccomp/tags": {
            1: [{"name": "v2.7.0"}, {"name": "v2.7.1-rc.1"}],
        },
        "/repos/stevegrubb/libcap-ng/releases": {
            1: [
                {"tag_name": "v0.8.6", "body": "libcap-ng patch six"},
                {"tag_name": "v0.9.0", "body": "libcap-ng feature release"},
            ],
        },
        "/repos/stevegrubb/libcap-ng/tags": {1: [{"name": "v0.9.1"}]},
        "/repos/rootless-containers/slirp4netns/releases": {
            1: [
                {"tag_name": "v1.3.5", "body": "slirp patch five"},
                {"tag_name": "v1.4.0", "body": "slirp feature release"},
                {"tag_name": "v1.5.0-rc.1", "prerelease": True, "body": "excluded prerelease"},
            ],
        },
        "/repos/rootless-containers/slirp4netns/tags": {1: [{"name": "v1.4.1"}]},
        "/repos/rust-lang/rust/releases": {
            1: [
                {"tag_name": "1.82.1", "body": "Rust patch one"},
                {"tag_name": "1.83.0", "body": "Rust feature release"},
            ],
        },
    }
    gitlab = {
        "/api/v4/projects/virtio-fs%2Fvirtiofsd/releases": {
            1: virtiofsd_first_page,
            2: [{"tag_name": "v1.13.10", "description": "virtiofsd patch ten"}],
        },
        "/api/v4/projects/virtio-fs%2Fvirtiofsd/repository/tags": {
            1: [{"name": "v1.14.0"}],
        },
    }
    go = [
        {"version": "go1.24.5", "stable": True},
        {"version": "go1.24.6", "stable": True},
        {"version": "go1.25.0", "stable": True},
        {"version": "go1.25.1", "stable": True},
        {"version": "go1.25.2", "stable": True},
        {"version": "go1.26rc1", "stable": False},
    ]
    go_history = "".join(
        f'<h2 id="{version}">Go {version.removeprefix("go")}</h2><p>{note}</p>'
        for version, note in (
            ("go1.24.5", "Go patch five details"),
            ("go1.24.6", "Go patch six details"),
            ("go1.25.1", "Go feature patch one details"),
            ("go1.25.2", "Go feature patch two details"),
        )
    )
    modules = {
        "github.com/google/nftables": {"versions": ["v0.3.0", "v0.3.1", "v0.4.0"], "latest": "v0.4.0"},
        "github.com/google/nftables/v2": {"versions": ["v2.0.0", "v2.1.0"], "latest": "v2.1.0"},
        "github.com/mdlayher/netlink": {
            "versions": ["v1.7.3-0.20250113171957-fbb4dce95f42", "v1.7.3", "v1.7.4", "v1.8.0"],
            "latest": "v1.8.0",
        },
        "github.com/klauspost/compress": {"versions": ["v1.18.5", "v1.18.6", "v1.19.0"], "latest": "v1.19.0"},
        "github.com/miekg/dns": {"versions": ["v1.1.70", "v1.1.71"], "latest": "v1.1.71"},
        "github.com/spf13/cobra": {"versions": ["v1.10.1", "v1.10.2", "v1.11.0"], "latest": "v1.11.0"},
        "github.com/vishvananda/netlink": {"versions": ["v1.3.0", "v1.3.1", "v1.4.0"], "latest": "v1.4.0"},
        "golang.org/x/sys": {"versions": ["v0.39.0", "v0.39.1", "v0.40.0"], "latest": "v0.40.0"},
        "example.com/acme/tool/v2": {"versions": ["v2.1.0", "v2.2.0"], "latest": "v2.2.0"},
        "example.com/acme/tool/v3": {"versions": ["v3.0.0"], "latest": "v3.0.0"},
        "example.org/other/tool": {"versions": ["v1.0.0", "v1.0.1"], "latest": "v1.0.1"},
        "example.org/legacy": {"versions": ["v1.2.0"], "latest": "v1.2.0"},
        "example.org/legacy/v2": {"versions": ["v2.0.0"], "latest": "v2.0.0"},
        "example.org/incompatible": {"versions": ["v1.0.0", "v2.0.0+incompatible"], "latest": "v2.0.0+incompatible"},
        "gopkg.in/yaml.v3": {"versions": ["v3.0.1", "v3.0.2"], "latest": "v3.0.2"},
        "gopkg.in/yaml.v4": {"versions": ["v4.0.0"], "latest": "v4.0.0"},
    }
    return {
        "kernel": kernel,
        "github": github,
        "gitlab": gitlab,
        "go": go,
        "go_history": go_history,
        "debian_index": '<p>The current "stable" distribution of Debian is version 13, codenamed trixie.</p>',
        "debian_suite": "<p>Debian 13.7 was released on September 12th, 2026.</p><p>Debian 13.0 was initially released on August 9th, 2025.</p>",
        "modules": modules,
    }


@pytest.fixture
def upstream_server():
    """Serve upstream endpoint fixtures and record their requested paths."""
    state = {
        "sources": _stable_sources(),
        "requests": [],
        "fail_kernel": False,
        "fail_next_major": False,
    }

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            """Serve an upstream-compatible local fixture response."""
            parsed = urlsplit(self.path)
            query = parse_qs(parsed.query)
            page = int(query.get("page", ["1"])[0])
            state["requests"].append(self.path)
            if state["fail_kernel"] and parsed.path == "/releases.json":
                self.send_error(503, "fixture source unavailable")
                return
            if state["fail_next_major"] and parsed.path == "/github.com/google/nftables/v2/@v/list":
                self.send_error(500, "fixture next-major source unavailable")
                return
            sources = state["sources"]
            if parsed.path == "/releases.json":
                payload = sources["kernel"]
            elif parsed.path == "/releases/":
                payload = sources["debian_index"]
            elif parsed.path == "/releases/trixie/":
                payload = sources["debian_suite"]
            elif parsed.path == "/dl/":
                payload = sources["go"]
            elif parsed.path == "/doc/devel/release":
                payload = sources["go_history"]
            elif parsed.path == "/doc/go1.25":
                payload = "<main>Go 1.25 release features</main>"
            elif parsed.path.endswith("/@v/list"):
                module = parsed.path.removesuffix("/@v/list").lstrip("/")
                module_data = sources["modules"].get(module)
                if module_data is None:
                    self.send_error(404, "module version is absent from fixture")
                    return
                payload = "\n".join(module_data.get("versions", []))
            elif parsed.path.endswith("/@latest"):
                module = parsed.path.removesuffix("/@latest").lstrip("/")
                latest = sources["modules"].get(module, {}).get("latest")
                if latest is None:
                    self.send_error(404, "module version is absent from fixture")
                    return
                payload = {"Version": latest, "Time": "2026-10-28T00:00:00Z"}
            elif parsed.path.startswith("/api/v4/"):
                payload = sources["gitlab"].get(parsed.path, {}).get(page, [])
            else:
                payload = sources["github"].get(parsed.path, {}).get(page, [])
            body = payload.encode("utf-8") if isinstance(payload, str) else json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html" if isinstance(payload, str) else "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            """Keep fixture server request logs out of test output."""
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    state["base_url"] = f"http://{host}:{port}"
    try:
        yield state
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_deps_check_reports_versions_notes_and_local_source_mapping(tmp_path, upstream_server):
    """Report every intervening stable release using all expected upstream APIs."""
    checker = _install_checker(tmp_path)
    out, err, rc = run(
        [sys.executable, str(checker), "--source-base-url", upstream_server["base_url"]],
        cwd=tmp_path,
        timeout=30,
    )

    assert rc == 0, err_msg(out, err)
    table = out.split("Release notes:", 1)[0].splitlines()
    assert table[0].split() == ["component", "shipped", "latest", "fix", "latest", "overall"]
    rows = _summary_rows(out)
    assert "6.12.0" in rows["Kernel"] and "6.12.9" in rows["Kernel"]
    assert "7.0.1 (next long-term: 6.18.2)" in rows["Kernel"]
    assert "1.13.2" in rows["virtiofsd"] and "1.13.10" in rows["virtiofsd"] and "1.14.0" in rows["virtiofsd"]
    seccomp, cap_ng = rows["libseccomp (linked in)"], rows["libcap-ng (linked in)"]
    assert "2.6.0" in seccomp and "2.6.10" in seccomp and "2.7.0" in seccomp
    assert "0.8.5" in cap_ng and "0.8.6" in cap_ng and "0.9.1" in cap_ng
    slirp, go = rows["slirp4netns (upstream binary)"], rows["Go (compiles it)"]
    assert "1.3.4" in slirp and "1.3.5" in slirp and "1.4.1" in slirp
    assert "1.24.4" in go and "1.24.6" in go and "1.25.2" in go
    rust = rows["Rust (compiles it)"]
    assert "1.82.0" in rust and "1.82.1" in rust and "1.83.0" in rust
    assert "Debian 13 (trixie)" in rows["Base rootfs"] and rows["Base rootfs"].count("13.7") == 2
    assert "nftables" in rows and "v0.3.0" in rows["nftables"]
    assert "v0.3.1" in rows["nftables"] and "v2.1.0" in rows["nftables"]
    assert "mdlayher/netlink" in rows and "v1.7.4" in rows["mdlayher/netlink"] and "v1.8.0" in rows["mdlayher/netlink"]
    assert "v1.7.3-0.2025…" in rows["mdlayher/netlink"] and "fbb4dce95f42" not in rows["mdlayher/netlink"]
    assert "v1.18.6" in rows["compress"] and "v1.19.0" in rows["compress"]
    assert rows["dns"].count("v1.1.71") == 2
    assert "v1.10.2" in rows["cobra"] and "v1.11.0" in rows["cobra"]
    assert "v1.3.1" in rows["vishvananda/netlink"] and "v1.4.0" in rows["vishvananda/netlink"]
    assert "v0.39.1" in rows["sys"] and "v0.40.0" in rows["sys"]
    assert rows["acme/tool"].count("v2.1.0") == 2 and "v3.0.0" in rows["acme/tool"]
    assert "v1.0.1" in rows["other/tool"]
    assert "v2.0.0" in rows["legacy"]
    assert "v2.0.0+incompatible" in rows["incompatible"]
    assert "v4.0.0" in rows["yaml"]
    for note in (
        "virtiofsd patch three", "virtiofsd patch four", "virtiofsd patch ten",
        "seccomp patch one", "seccomp patch two", "seccomp patch ten",
        "libcap-ng patch six", "libcap-ng feature release", "slirp patch five",
        "slirp feature release", "Go patch five details", "Go patch six details",
        "Go feature patch one details", "Go feature patch two details",
        "Go 1.25 release features",
        "Rust patch one", "Rust feature release",
        "1.14.0: tag-only; no release notes entry was published",
        "bugfix updates channel:", "feature updates channel:",
        "      virtiofsd patch three", "      [download](archive.zip)",
        "      - outer  item\n        - nested  item\n      \n      ```sh\n          printf  'a  b'\n      ```",
    ):
        assert note in out
    assert "excluded prerelease" not in out
    assert "up to date" not in out
    assert "badge.svg" not in out
    virtiofsd_feature = out.split("virtiofsd release notes:", 1)[1].split("libseccomp release notes:", 1)[0]
    assert "1.13.3" not in virtiofsd_feature.split("feature updates channel:", 1)[1]
    go_notes = out.split("Go release notes:", 1)[1]
    assert "1.24.5" in go_notes.split("bugfix updates channel:", 1)[1].split("feature updates channel:", 1)[0]
    assert "1.24.5" not in go_notes.split("feature updates channel:", 1)[1]
    assert "go1.24.6" in out
    assert "Go patch six details" in out
    assert out.index("Release notes:") > out.index(rows["Go (compiles it)"])
    requests = "\n".join(upstream_server["requests"])
    assert "/releases.json" in requests
    assert "/dl/?mode=json&include=all" in requests
    assert "/doc/devel/release" in requests
    assert "/doc/go1.25" in requests
    assert "/repos/seccomp/libseccomp/releases?per_page=100&page=2" in requests
    assert "/repos/seccomp/libseccomp/tags?per_page=100&page=1" in requests
    assert "/repos/rootless-containers/slirp4netns/releases?per_page=100&page=1" in requests
    assert "/api/v4/projects/virtio-fs%2Fvirtiofsd/releases?per_page=100&page=2" in requests
    assert "/releases/" in requests and "/releases/trixie/" in requests
    assert "/github.com/mdlayher/netlink/@v/list" in requests
    assert "/github.com/mdlayher/netlink/@latest" in requests
    assert "/github.com/google/nftables/v2/@v/list" in requests
    assert "/example.com/acme/tool/v3/@v/list" in requests
    assert "/example.org/legacy/v2/@v/list" in requests
    assert "/gopkg.in/yaml.v4/@v/list" in requests
    module_list_requests = [request for request in upstream_server["requests"] if request.endswith("/@v/list")]
    assert len(module_list_requests) == 24
    assert not any("/github.com/google/nftables/v3/" in request for request in upstream_server["requests"])
    assert not any("ignored/transitive" in request for request in upstream_server["requests"])


def test_deps_check_with_no_upstream_updates_exits_successfully(tmp_path, upstream_server):
    """A clean upstream with no newer versions is a successful report."""
    checker = _install_checker(tmp_path)
    upstream_server["sources"] = {
        "kernel": {"releases": [{"version": "6.12.0", "moniker": "longterm"}]},
        "github": {},
        "gitlab": {},
        "go": [],
        "go_history": "",
        "debian_index": '<p>The current "stable" distribution of Debian is version 13, codenamed trixie.</p>',
        "debian_suite": "<p>Debian 13.7 was released on September 12th, 2026.</p>",
        "modules": {
            "github.com/google/nftables": {"versions": ["v0.3.0"], "latest": "v0.3.0"},
            "github.com/mdlayher/netlink": {"versions": ["v1.7.3-0.20250113171957-fbb4dce95f42"], "latest": "v1.7.3-0.20250113171957-fbb4dce95f42"},
            "github.com/klauspost/compress": {"versions": ["v1.18.5"], "latest": "v1.18.5"},
            "github.com/miekg/dns": {"versions": ["v1.1.70"], "latest": "v1.1.70"},
            "github.com/spf13/cobra": {"versions": ["v1.10.1"], "latest": "v1.10.1"},
            "github.com/vishvananda/netlink": {"versions": ["v1.3.0"], "latest": "v1.3.0"},
            "golang.org/x/sys": {"versions": ["v0.39.0"], "latest": "v0.39.0"},
            "example.com/acme/tool/v2": {"versions": ["v2.1.0"], "latest": "v2.1.0"},
            "example.org/other/tool": {"versions": ["v1.0.0"], "latest": "v1.0.0"},
            "example.org/legacy": {"versions": ["v1.2.0"], "latest": "v1.2.0"},
            "example.org/incompatible": {"versions": ["v1.0.0"], "latest": "v1.0.0"},
            "gopkg.in/yaml.v3": {"versions": ["v3.0.1"], "latest": "v3.0.1"},
        },
    }
    out, err, rc = run(
        [sys.executable, str(checker), "--source-base-url", upstream_server["base_url"]],
        cwd=tmp_path,
        timeout=30,
    )

    assert rc == 0, err_msg(out, err)
    table = out.split("Release notes:", 1)[0]
    summary_rows = _summary_rows(out)
    assert summary_rows["Kernel"].count("6.12.0") == 3
    assert "next long-term" not in table
    assert summary_rows["virtiofsd"].count("1.13.2") == 3
    assert summary_rows["Go (compiles it)"].count("1.24.4") == 3
    assert summary_rows["Rust (compiles it)"].count("1.82.0") == 3
    assert "Debian 13 (trixie)" in summary_rows["Base rootfs"] and summary_rows["Base rootfs"].count("13.7") == 2
    assert summary_rows["nftables"].count("v0.3.0") == 3, table
    assert out.split("Release notes:", 1)[1].count("    none") == 12
    assert "up to date" not in out


def test_deps_check_reports_next_debian_stable_when_released(tmp_path, upstream_server):
    """Show the next stable Debian only after it is the published stable release."""
    checker = _install_checker(tmp_path)
    upstream_server["sources"]["debian_index"] = (
        '<p>The current "stable" distribution of Debian is version 14, codenamed forky.</p>'
    )
    out, err, rc = run(
        [sys.executable, str(checker), "--source-base-url", upstream_server["base_url"]],
        cwd=tmp_path,
        timeout=30,
    )

    assert rc == 0, err_msg(out, err)
    row = _summary_rows(out)["Base rootfs"]
    assert "Debian 13 (trixie)" in row and "13.7" in row and "Debian 14 (forky)" in row


def test_deps_check_normalizes_wrapped_debian_metadata(tmp_path, upstream_server):
    """Whitespace changes in Debian page markup do not break release parsing."""
    checker = _install_checker(tmp_path)
    upstream_server["sources"]["debian_index"] = (
        '<p>The current "stable" distribution of Debian is version</p>'
        '<p>13, codenamed</p><p>trixie.</p>'
    )
    upstream_server["sources"]["debian_suite"] = (
        "<p>Debian</p><p>13.7</p><p>was released on October 1st, 2026.</p>"
    )
    out, err, rc = run(
        [sys.executable, str(checker), "--source-base-url", upstream_server["base_url"]],
        cwd=tmp_path,
        timeout=30,
    )

    assert rc == 0, err_msg(out, err)
    row = _summary_rows(out)["Base rootfs"]
    assert "Debian 13 (trixie)" in row and "13.7" in row


def test_deps_check_shows_what_each_dependency_serves(tmp_path, upstream_server):
    """Nest each dependency under the component it is built into or used for."""
    checker = _install_checker(tmp_path)
    out, err, rc = run(
        [sys.executable, str(checker), "--source-base-url", upstream_server["base_url"]],
        cwd=tmp_path,
        timeout=30,
    )

    assert rc == 0, err_msg(out, err)
    table = out.split("Release notes:", 1)[0].splitlines()
    width = len(table[1].split("  ")[0])
    lines = [line[:width].rstrip() for line in table[2:]]
    assert lines[:12] == [
        "Guest VM (shipped inside zaigr)",
        "├─ Kernel",
        "└─ Base rootfs",
        "Host helpers (shipped inside zaigr)",
        "├─ virtiofsd",
        "│  ├─ libseccomp (linked in)",
        "│  ├─ libcap-ng (linked in)",
        "│  └─ Rust (compiles it)",
        "└─ slirp4netns (upstream binary)",
        "zaigr binary",
        "├─ Go (compiles it)",
        "└─ Go modules (linked in)",
    ]
    assert lines[12] == "   ├─ nftables"
    assert lines[23] == "   └─ yaml"
    assert len(lines) == 24


def test_deps_check_requires_the_rust_pin(tmp_path, upstream_server):
    """A moved Rust pin fails the report instead of dropping the compiler row."""
    checker = _install_checker(tmp_path)
    script = tmp_path / "cmd" / "zaigr" / "builtin" / "setups" / "zaigr-dev" / "setup.script"
    script.write_text("# the pin moved\n", encoding="utf-8")
    out, err, rc = run(
        [sys.executable, str(checker), "--source-base-url", upstream_server["base_url"]],
        cwd=tmp_path,
        timeout=30,
    )

    assert rc == 1
    assert "missing the Rust version pin" in out + err


def test_deps_check_reports_next_major_upstream_failure(tmp_path, upstream_server):
    """A failed adjacent-major lookup names proxy.golang.org and exits nonzero."""
    checker = _install_checker(tmp_path)
    upstream_server["fail_next_major"] = True
    out, err, rc = run(
        [sys.executable, str(checker), "--source-base-url", upstream_server["base_url"]],
        cwd=tmp_path,
        timeout=30,
    )

    assert rc == 1
    assert "fetch failed from host proxy.golang.org" in out + err
    assert "fixture next-major source unavailable" in out + err
    assert any(
        request.startswith("/github.com/google/nftables/v2/@v/list")
        for request in upstream_server["requests"]
    )


def test_deps_check_reports_original_host_for_upstream_failure(tmp_path, upstream_server):
    """A local fixture failure names the upstream source that could not be fetched."""
    checker = _install_checker(tmp_path)
    upstream_server["fail_kernel"] = True
    out, err, rc = run(
        [sys.executable, str(checker), "--source-base-url", upstream_server["base_url"]],
        cwd=tmp_path,
        timeout=30,
    )

    assert rc == 1
    assert "ERROR: fetch failed from host www.kernel.org" in out + err
    assert "fixture source unavailable" in out + err
