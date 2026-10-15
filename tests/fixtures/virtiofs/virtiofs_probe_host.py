"""Independent host oracle for the disposable guest virtiofs probe."""
import sqlite3
import time
from collections import namedtuple
from pathlib import Path

HostResult = namedtuple("HostResult", "case share_label passed detail")
APPEND_CASES = (
    "append-wronly-fsync", "append-rdwr-fsync", "append-wronly-fdatasync",
    "append-wronly-existing", "append-rdwr-existing", "plain-write-fsync",
    "mixed-idle-append", "mixed-permission-fallback",
)
ALL_CASES = APPEND_CASES + (
    "mmap-msync", "sqlite-wal-two-process", "rename", "rename-over-existing",
    "host-to-guest-visibility", "guest-to-host-ready",
)


def record(index):
    return bytes((index * 37 + j * 13) & 255 for j in range(512))


def _bytes(path, expected):
    try:
        actual = path.read_bytes()
    except OSError as error:
        return f"could not read {path.name}: {error}"
    if actual != expected:
        return f"{path.name}: got {len(actual)} bytes, expected {len(expected)}; first mismatch {next((i for i, pair in enumerate(zip(actual, expected)) if pair[0] != pair[1]), 'length')}"
    return ""


def write_host_to_guest_markers(share_dir):
    share_dir = Path(share_dir)
    with (share_dir / "probe-h2g-data").open("xb") as data:
        data.write(record(42))
        data.flush()
    (share_dir / "probe-h2g-ready").touch(exist_ok=False)


def run_host_validations(share_dir, share_label):
    share_dir = Path(share_dir)
    results = []

    def add(name, detail):
        results.append(HostResult(name, share_label, not detail, detail))

    expected = b"".join(record(i) for i in range(32))
    for name in APPEND_CASES:
        add(name, _bytes(share_dir / f"probe-{name}", expected))
    add("mmap-msync", _bytes(share_dir / "probe-mmap-msync", bytes((i * 97 + 13) & 255 for i in range(16384))))

    db_path = share_dir / "probe-sqlite-wal.db"
    try:
        connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=0)
        try:
            mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
            rows = [row[0] for row in connection.execute("SELECT v FROM t ORDER BY v")]
            integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
            detail = "" if (mode, rows, integrity) == ("wal", list(range(32)), "ok") else f"mode={mode}, rows={rows}, integrity={integrity}"
        finally:
            connection.close()
    except (sqlite3.Error, OSError) as error:
        detail = f"SQLite read-only inspection failed: {error}"
    add("sqlite-wal-two-process", detail)

    detail = _bytes(share_dir / "probe-rename-dst-nonexistent", record(7))
    if (share_dir / "probe-rename-src").exists():
        detail += " source still exists"
    add("rename", detail)

    detail = _bytes(share_dir / "probe-rename-over-dst", record(11))
    if (share_dir / "probe-rename-over-src").exists():
        detail += " source still exists"
    add("rename-over-existing", detail)

    deadline = time.monotonic() + 10
    while not (share_dir / "probe-h2g-ack").exists() and time.monotonic() < deadline:
        time.sleep(0.1)
    detail = "" if (share_dir / "probe-h2g-ack").exists() else "guest acknowledgement did not appear"
    detail += _bytes(share_dir / "probe-h2g-data", record(42))
    add("host-to-guest-visibility", detail)

    detail = "" if (share_dir / "probe-g2h-ready").exists() else "guest ready marker absent"
    detail += _bytes(share_dir / "probe-g2h-data", record(77))
    add("guest-to-host-ready", detail)
    return results
