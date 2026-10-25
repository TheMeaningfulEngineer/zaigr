import hashlib
import os
import stat
from pathlib import Path

from tests.conftest import run

REPO_ROOT = Path(__file__).resolve().parents[2]


def _write_executable(path, content):
    """Write an executable test command."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def test_fetch_slirp4netns_verifies_and_copies_pinned_static_binary(tmp_path):
    """Publish only the matching static binary and record its version."""
    repo = tmp_path / "repo"
    (repo / "vm_prep").mkdir(parents=True)
    (repo / "cmd/zaigr/vm_data").mkdir(parents=True)
    script = repo / "vm_prep/fetch-slirp4netns.sh"
    script.write_bytes((REPO_ROOT / "vm_prep/fetch-slirp4netns.sh").read_bytes())
    script.chmod(0o755)
    binary = tmp_path / "upstream-slirp4netns"
    binary.write_text(
        "#!/bin/sh\n"
        "case \"${1-}\" in\n"
        "  --version) printf 'slirp4netns version 1.3.4\\n' ;;\n"
        "  --help) printf 'usage: slirp4netns --disable-dns\\n' ;;\n"
        "  *) exit 2 ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    binary.chmod(0o755)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    (repo / "deps.lock").write_text(
        f"SLIRP4NETNS_VERSION=1.3.4\nSLIRP4NETNS_SHA256={digest}\n",
        encoding="utf-8",
    )
    bin_dir = tmp_path / "bin"
    _write_executable(
        bin_dir / "curl",
        "#!/bin/sh\nset -eu\nwhile [ \"$1\" != --output ]; do shift; done\nshift\ncp "
        + str(binary)
        + " \"$1\"\n",
    )
    _write_executable(
        bin_dir / "readelf",
        "#!/bin/sh\ncase \"$1\" in\n"
        "  -h) printf 'Machine: Advanced Micro Devices X86-64\\n' ;;\n"
        "  -l) printf 'LOAD\\n' ;;\n"
        "  -d) printf 'There is no dynamic section in this file.\\n' ;;\n"
        "esac\n",
    )
    _write_executable(bin_dir / "ldd", "#!/bin/sh\nprintf 'not a dynamic executable\\n'\n")
    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}:{env['PATH']}"
    env["ZAIGR_EXTERNAL_SOURCES"] = str(tmp_path / "external-sources")

    out, err, rc = run([script], cwd=repo, env=env, timeout=10)

    assert rc == 0, out + err
    output = repo / "cmd/zaigr/vm_data/slirp4netns"
    assert output.read_bytes() == binary.read_bytes()
    assert output.stat().st_mode & stat.S_IXUSR
    assert (repo / "cmd/zaigr/vm_data/slirp4netns.version").read_text(encoding="utf-8") == "1.3.4\n"
    assert digest in out
    (bin_dir / "curl").write_text("#!/bin/sh\nexit 19\n", encoding="utf-8")
    (bin_dir / "curl").chmod(0o755)

    out, err, rc = run([script], cwd=repo, env=env, timeout=10)

    assert rc == 0, out + err
    assert "Downloading" not in out
    assert output.read_bytes() == binary.read_bytes()


def test_fetch_slirp4netns_rejects_checksum_mismatch_before_publishing(tmp_path):
    """Keep the embedded output untouched when an upstream checksum differs."""
    repo = tmp_path / "repo"
    (repo / "vm_prep").mkdir(parents=True)
    data_dir = repo / "cmd/zaigr/vm_data"
    data_dir.mkdir(parents=True)
    (data_dir / "slirp4netns").write_bytes(b"previous binary")
    (data_dir / "slirp4netns.version").write_text("old\n", encoding="utf-8")
    script = repo / "vm_prep/fetch-slirp4netns.sh"
    script.write_bytes((REPO_ROOT / "vm_prep/fetch-slirp4netns.sh").read_bytes())
    script.chmod(0o755)
    (repo / "deps.lock").write_text(
        "SLIRP4NETNS_VERSION=1.3.4\nSLIRP4NETNS_SHA256=" + "0" * 64 + "\n",
        encoding="utf-8",
    )
    binary = tmp_path / "upstream-slirp4netns"
    binary.write_bytes(b"wrong artifact")
    bin_dir = tmp_path / "bin"
    _write_executable(
        bin_dir / "curl",
        "#!/bin/sh\nset -eu\nwhile [ \"$1\" != --output ]; do shift; done\nshift\ncp "
        + str(binary)
        + " \"$1\"\n",
    )
    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}:{env['PATH']}"
    env["ZAIGR_EXTERNAL_SOURCES"] = str(tmp_path / "external-sources")

    out, err, rc = run([script], cwd=repo, env=env, timeout=10)

    assert rc != 0
    assert "did not match its pinned SHA-256" in out + err
    assert (data_dir / "slirp4netns").read_bytes() == b"previous binary"
    assert (data_dir / "slirp4netns.version").read_text(encoding="utf-8") == "old\n"
