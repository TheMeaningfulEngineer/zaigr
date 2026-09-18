"""Reclaim only QEMU processes owned by one test's network namespace and UID."""

import os
import select
import signal
import sys
import time
from contextlib import ExitStack
from pathlib import Path


def wait_for_exit(handles, timeout):
    """Wait a bounded interval for stable process handles to report exit."""
    pending = dict(handles)
    deadline = time.monotonic() + timeout
    while pending and time.monotonic() < deadline:
        ready, _, _ = select.select(list(pending), [], [], max(0, deadline - time.monotonic()))
        for handle in ready:
            del pending[handle]
    return pending


def terminate_qemus(namespace_inode, host_uid, interrupt):
    """Identify exact owned QEMUs, terminate them, and report unexpected leftovers."""
    handles = {}
    with ExitStack() as closer:
        for process in Path("/proc").iterdir():
            if not process.name.isdecimal():
                continue
            handle = None
            try:
                if process.stat().st_uid != host_uid:
                    continue
                handle = os.pidfd_open(int(process.name))
                executable = (process / "exe").readlink().name
                if (
                    process.stat().st_uid == host_uid
                    and (process / "ns/net").stat().st_ino == namespace_inode
                    and executable.startswith("qemu-system-")
                    and (process / "comm").read_text().strip() == executable[:15]
                ):
                    handles[handle] = int(process.name)
                    closer.callback(os.close, handle)
                    handle = None
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue
            finally:
                if handle is not None:
                    os.close(handle)
        print(
            f":: scoped QEMU check: net inode={namespace_inode}, "
            f"host UID={host_uid}, PIDs={list(handles.values())}", flush=True,
        )
        if interrupt and len(handles) != 1:
            raise RuntimeError("Crash injection requires exactly one owned QEMU")
        for handle, pid in handles.items():
            print(f":: scoped QEMU cleanup: SIGTERM PID {pid} via pidfd", flush=True)
            try:
                signal.pidfd_send_signal(handle, signal.SIGTERM)
            except ProcessLookupError:
                pass
        remaining = wait_for_exit(handles, 5)
        for handle, pid in remaining.items():
            print(f":: scoped QEMU cleanup: SIGKILL PID {pid} via pidfd", flush=True)
            try:
                signal.pidfd_send_signal(handle, signal.SIGKILL)
            except ProcessLookupError:
                pass
        remaining = wait_for_exit(remaining, 5)
        if remaining:
            raise RuntimeError(f"Owned QEMUs did not exit: {list(remaining.values())}")
        if handles:
            print(f":: scoped QEMU processes exited: {list(handles.values())}", flush=True)
        if handles and not interrupt:
            print(":: cleanup failure: QEMU survived primary project teardown", flush=True)
            return 1
        return 0


if __name__ == "__main__":
    mode, inode, uid = sys.argv[1:]
    if mode not in ("--cleanup", "--interrupt"):
        raise SystemExit("Expected --cleanup or --interrupt")
    raise SystemExit(terminate_qemus(int(inode), int(uid), mode == "--interrupt"))
